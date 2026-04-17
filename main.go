// pot-node is the Proof-of-Turn consensus peer for a DiceWars game session.
//
// Full protocol specification: https://arxiv.org/pdf/2304.07384v1
//
// # Usage
//
// Every node needs a persistent keypair. The first run generates and saves one:
//
//	pot-node --keyfile node-a.key --listen :7000
//
// # Two-node example
//
//	# Terminal 1 — host (leads turn 0, waits for 1 peer)
//	pot-node --keyfile a.key --listen :7000
//
//	# Terminal 2 — joining node (leads turn 1)
//	pot-node --keyfile b.key --listen :7001 --join localhost:7000
//
// # N-node example  (3 nodes shown; extend the pattern for more)
//
// Each joiner must advertise a dialable address so other peers can reach it
// after bootstrap. On a single machine:
//
//	pot-node --keyfile a.key --listen :7000 --expect 2
//	pot-node --keyfile b.key --listen :7001 --advertise-addr localhost:7001 --join localhost:7000
//	pot-node --keyfile c.key --listen :7002 --advertise-addr localhost:7002 --join localhost:7000
//
// # HTTP API
//
// Each node exposes a small HTTP API for the game frontend (default :8080):
//
//	POST /move   — submit a game move as JSON: {"moveType","from","to","playerId"}
//	GET  /events — SSE stream; one JSON event per consensus state change
//	GET  /status — current state snapshot: {"state","slot","leaderId"}
//
// The --api-addr flag overrides the listen address for the HTTP API.
//
// # Bootstrap handshake and mesh formation
//
// Phase 1 — Bootstrap: each joining node creates its block-traffic listener
// first, then dials the host. The host collects a Hello (ID, public key, addr)
// from every expected peer, builds the ordered peer list and genesis block, and
// sends SessionInfo back to all of them simultaneously.
//
// Phase 2 — Mesh: each joiner at index i dials all peers at indices 1..i-1
// (index 0 is the host, already connected). Combined with the pool's accept loop,
// this produces a fully-connected graph in O(N²) connections. The connection
// topology is symmetric — every node can broadcast to and receive from every
// other node directly.
//
// See session.Info.Validate for the cryptographic checks applied on receipt.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"pot-node/api"
	"pot-node/block"
	"pot-node/blockchain"
	"pot-node/consensus"
	"pot-node/crypto"
	"pot-node/network"
	"pot-node/session"
)

func main() {
	listenAddr    := flag.String("listen", ":7000", "TCP address to accept block-traffic connections on")
	advertiseAddr := flag.String("advertise-addr", "", "address peers use to dial us; defaults to 127.0.0.1+listen port")
	joinAddr      := flag.String("join", "", "session host address to dial (omit to host the session)")
	expect        := flag.Int("expect", 1, "number of peers to wait for before starting (host only)")
	keyFile       := flag.String("keyfile", "node.key", "keypair file — created on first run if absent")
	turnDur       := flag.Duration("turn-duration", consensus.DefaultTurnDuration, "length of each Leading Node's active window")
	transitionDur := flag.Duration("transition-duration", consensus.DefaultTransitionDuration, "handover buffer between turns (thesis constant: 5s)")
	apiAddr       := flag.String("api-addr", ":8080", "HTTP API listen address (POST /move, GET /events, GET /status)")
	flag.Parse()

	kp := loadOrCreateKey(*keyFile)
	id := crypto.NodeID(kp.Public)
	log.Printf("node id: %s", id)

	myAddr := advertiseAddrFor(*listenAddr, *advertiseAddr)
	myAPIAddr := apiAdvertiseAddr(myAddr, *apiAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool := network.NewPool()

	var (
		info           session.Info
		bootstrapConns []net.Conn
		ln             net.Listener
	)

	if *joinAddr == "" {
		info, bootstrapConns, ln = hostBootstrap(kp, myAddr, myAPIAddr, *listenAddr, *expect)
	} else {
		// Joiner: start listening BEFORE bootstrap so our address is reachable
		// by the time the host distributes SessionInfo to the other peers.
		var err error
		ln, err = net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("listen %s: %v", *listenAddr, err)
		}
		var conn net.Conn
		info, conn = joinBootstrap(kp, myAddr, myAPIAddr, *joinAddr)
		bootstrapConns = []net.Conn{conn}
	}

	if err := info.Validate(); err != nil {
		log.Fatalf("invalid session info: %v", err)
	}
	log.Printf("session ready: %d peer(s), genesis %s", len(info.Peers), info.Genesis.Hash[:12])

	peers := make([]string, len(info.Peers))
	peerKeys := make(map[string]ed25519.PublicKey, len(info.Peers))
	for i, p := range info.Peers {
		peers[i] = p.ID
		peerKeys[p.ID] = p.PubKey
	}

	// Seed chain from genesis, then attempt to catch up from the host's API.
	// This allows a rejoining node to resume at the correct slot without
	// replaying block traffic from the beginning.
	chain := blockchain.New()
	if err := chain.Append(info.Genesis, nil); err != nil {
		log.Fatalf("seed chain: %v", err)
	}
	// TODO(sync-resilience): currently syncs only from Peers[0] (the bootstrap host).
	// A more robust implementation would try each peer in turn order and take the
	// first successful response, so a rejoining node isn't blocked by the host being offline.
	if *joinAddr != "" && info.Peers[0].APIAddr != "" {
		if synced, err := syncChain(info.Peers[0].APIAddr, info.Genesis, peerKeys); err != nil {
			log.Printf("chain sync failed, starting from genesis: %v", err)
		} else {
			chain = synced
			log.Printf("chain synced: %d block(s)", chain.Len())
		}
	}

	tm := consensus.New(consensus.Config{
		NodeID:             id,
		KeyPair:            kp,
		Peers:              peers,
		PeerKeys:           peerKeys,
		TurnDuration:       *turnDur,
		TransitionDuration: *transitionDur,
	}, chain)

	// Promote each bootstrapped connection to a live block-traffic peer.
	for _, conn := range bootstrapConns {
		pool.Register(ctx, conn, tm)
	}

	// Mesh phase: dial all peers that precede us in the turn order, skipping
	// index 0 (the host — already connected via bootstrap). Peers with higher
	// indices will dial us through the pool's accept loop.
	myIdx := 0
	for i, p := range info.Peers {
		if p.ID == id {
			myIdx = i
			break
		}
	}
	for i := 1; i < myIdx; i++ {
		p := info.Peers[i]
		log.Printf("connecting to peer %d at %s", i, p.Addr)
		if err := pool.Connect(ctx, p.Addr, tm); err != nil {
			log.Printf("warn: peer %d (%s): %v", i, p.Addr, err)
		}
	}

	apiSrv := api.New(tm, id, chain)
	go apiSrv.Run(ctx)

	httpSrv := &http.Server{Addr: *apiAddr, Handler: apiSrv.Handler()}
	go func() {
		log.Printf("API listening on %s", *apiAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		httpSrv.Shutdown(context.Background()) //nolint:errcheck
	}()

	go tm.Run(ctx)
	pool.Run(ctx, ln, tm)
}

// hostBootstrap listens on listenAddr, waits for expect peers to connect and
// send their Hello, then broadcasts SessionInfo over each connection.
// myAddr is the host's block-traffic address; myAPIAddr is its HTTP API address.
// Both are included in PeerMeta so joiners can reach the host after bootstrap.
func hostBootstrap(kp crypto.KeyPair, myAddr, myAPIAddr, listenAddr string, expect int) (session.Info, []net.Conn, net.Listener) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	log.Printf("hosting session on %s, waiting for %d peer(s)", listenAddr, expect)

	hellos := make([]session.Hello, 0, expect)
	conns := make([]net.Conn, 0, expect)
	for range expect {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		h, err := session.ReceiveHello(conn)
		if err != nil {
			log.Fatalf("receive hello from %s: %v", conn.RemoteAddr(), err)
		}
		log.Printf("peer hello: %s at %s", h.ID[:12], h.Addr)
		hellos = append(hellos, h)
		conns = append(conns, conn)
	}

	id := crypto.NodeID(kp.Public)
	peers := make([]session.PeerMeta, 0, expect+1)
	peers = append(peers, session.PeerMeta{ID: id, PubKey: kp.Public, Addr: myAddr, APIAddr: myAPIAddr})
	for _, h := range hellos {
		peers = append(peers, session.PeerMeta{ID: h.ID, PubKey: h.PubKey, Addr: h.Addr, APIAddr: h.APIAddr})
	}

	genesis, err := block.NewGenesisBlock(id, kp.Private)
	if err != nil {
		log.Fatalf("create genesis: %v", err)
	}

	info := session.Info{Peers: peers, Genesis: genesis}
	for _, conn := range conns {
		if err := session.Send(conn, info); err != nil {
			log.Fatalf("send session info to %s: %v", conn.RemoteAddr(), err)
		}
	}
	return info, conns, ln
}

// joinBootstrap dials hostAddr, sends a Hello carrying myAddr and myAPIAddr,
// and receives the SessionInfo. Returns the Info and the connection (which
// becomes a block-traffic channel for the host).
func joinBootstrap(kp crypto.KeyPair, myAddr, myAPIAddr, hostAddr string) (session.Info, net.Conn) {
	conn, err := net.Dial("tcp", hostAddr)
	if err != nil {
		log.Fatalf("dial %s: %v", hostAddr, err)
	}
	hello := session.Hello{
		ID:      crypto.NodeID(kp.Public),
		PubKey:  kp.Public,
		Addr:    myAddr,
		APIAddr: myAPIAddr,
	}
	if err := session.SendHello(conn, hello); err != nil {
		log.Fatalf("send hello: %v", err)
	}
	info, err := session.Receive(conn)
	if err != nil {
		log.Fatalf("receive session info: %v", err)
	}
	return info, conn
}

// apiAdvertiseAddr derives the dialable HTTP API address by combining the host
// from the block-traffic advertise address with the port from the API listen address.
// For example: blockAddr="nodeA:7000", apiListen=":8080" → "nodeA:8080".
func apiAdvertiseAddr(blockAddr, apiListen string) string {
	host, _, _ := net.SplitHostPort(blockAddr)
	_, port, _ := net.SplitHostPort(apiListen)
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// syncChain fetches the block chain from peerAPIAddr, validates every block
// (structural integrity + Ed25519 signatures), and verifies the genesis hash
// matches the one agreed during bootstrap. Falls back gracefully — the caller
// should log the error and continue from genesis if sync fails.
func syncChain(peerAPIAddr string, genesis *block.Block, peerKeys map[string]ed25519.PublicKey) (*blockchain.Chain, error) {
	resp, err := http.Get("http://" + peerAPIAddr + "/chain")
	if err != nil {
		return nil, fmt.Errorf("fetch /chain from %s: %w", peerAPIAddr, err)
	}
	defer resp.Body.Close()

	var blocks []*block.Block
	if err := json.NewDecoder(resp.Body).Decode(&blocks); err != nil {
		return nil, fmt.Errorf("decode chain: %w", err)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("empty chain from %s", peerAPIAddr)
	}
	if blocks[0].Hash != genesis.Hash {
		return nil, fmt.Errorf("genesis mismatch: expected %.12s, got %.12s", genesis.Hash, blocks[0].Hash)
	}

	chain := blockchain.New()
	for _, b := range blocks {
		if err := chain.Append(b, peerKeys); err != nil {
			return nil, fmt.Errorf("invalid block %d: %w", b.Index, err)
		}
	}
	return chain, nil
}

// advertiseAddrFor returns the address peers should dial to reach this node.
// If advertise is non-empty it is used directly. Otherwise, if listen starts
// with ":" (port-only), "127.0.0.1" is prepended so the result is dialable on
// the same machine. Pass --advertise-addr for cross-machine or Docker deployments.
func advertiseAddrFor(listen, advertise string) string {
	if advertise != "" {
		return advertise
	}
	if strings.HasPrefix(listen, ":") {
		return "127.0.0.1" + listen
	}
	return listen
}

// ---- key persistence --------------------------------------------------------

type savedKey struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// loadOrCreateKey reads the keypair from path, or generates a new one and
// writes it there if the file does not exist.
func loadOrCreateKey(path string) crypto.KeyPair {
	if data, err := os.ReadFile(path); err == nil {
		var sk savedKey
		if json.Unmarshal(data, &sk) == nil {
			priv, e1 := hex.DecodeString(sk.Private)
			pub, e2 := hex.DecodeString(sk.Public)
			if e1 == nil && e2 == nil && len(priv) == 64 && len(pub) == 32 {
				return crypto.KeyPair{
					Private: ed25519.PrivateKey(priv),
					Public:  ed25519.PublicKey(pub),
				}
			}
		}
		log.Printf("key file %s is malformed — generating a fresh keypair", path)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate keypair: %v", err)
	}
	sk := savedKey{
		Private: hex.EncodeToString(kp.Private),
		Public:  hex.EncodeToString(kp.Public),
	}
	data, _ := json.MarshalIndent(sk, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("warning: could not save key to %s: %v", path, err)
	} else {
		log.Printf("new keypair saved to %s", path)
	}
	return kp
}
