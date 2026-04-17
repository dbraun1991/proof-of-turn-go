package network_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/block"
	"pot-node/crypto"
	"pot-node/network"
)

// ---- helpers ----------------------------------------------------------------

func mustKeyPair(t *testing.T) crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

func mustGenesisBlock(t *testing.T) *block.Block {
	t.Helper()
	kp := mustKeyPair(t)
	b, err := block.NewGenesisBlock(crypto.NodeID(kp.Public), kp.Private)
	require.NoError(t, err)
	return b
}

// mustMoveBlock creates a signed GameMove block chained to prev.
func mustMoveBlock(t *testing.T, prev *block.Block) *block.Block {
	t.Helper()
	kp := mustKeyPair(t)
	id := crypto.NodeID(kp.Public)
	b, err := block.NewGameMoveBlock(prev, id, block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: id}, kp.Private)
	require.NoError(t, err)
	return b
}

// tcpPair starts a listener on a random port and dials it. Returns the accepted
// server-side conn and the client-side conn, plus a cleanup function.
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- nil
		} else {
			done <- c
		}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Wait for Accept to complete before closing the listener.
	// Closing ln first can race with the Accept call and cause it to fail.
	server = <-done
	ln.Close()

	require.NotNil(t, server)
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}

// stubRouter is a minimal BlockRouter used in place of consensus.TurnManager.
type stubRouter struct {
	mu       sync.Mutex
	received []*block.Block
	out      chan *block.Block
}

func newStubRouter() *stubRouter {
	return &stubRouter{out: make(chan *block.Block, 64)}
}

func (r *stubRouter) ReceiveBlock(b *block.Block) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, b)
}

func (r *stubRouter) OutBlocks() <-chan *block.Block { return r.out }

func (r *stubRouter) Received() []*block.Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*block.Block, len(r.received))
	copy(out, r.received)
	return out
}

// ---- Peer tests -------------------------------------------------------------

func TestPeer_WriteRead(t *testing.T) {
	server, client := tcpPair(t)
	writer := network.NewPeer(client)
	reader := network.NewPeer(server)

	genesis := mustGenesisBlock(t)
	require.NoError(t, writer.Write(genesis))

	got, err := reader.Read()
	require.NoError(t, err)
	assert.Equal(t, genesis.Hash, got.Hash)
	assert.Equal(t, genesis.Type, got.Type)
}

func TestPeer_MultipleBlocksInOrder(t *testing.T) {
	server, client := tcpPair(t)
	writer := network.NewPeer(client)
	reader := network.NewPeer(server)

	genesis := mustGenesisBlock(t)
	move := mustMoveBlock(t, genesis)

	require.NoError(t, writer.Write(genesis))
	require.NoError(t, writer.Write(move))

	b0, err := reader.Read()
	require.NoError(t, err)
	assert.Equal(t, genesis.Hash, b0.Hash)

	b1, err := reader.Read()
	require.NoError(t, err)
	assert.Equal(t, move.Hash, b1.Hash)
}

func TestPeer_ReadOnClosedConnection(t *testing.T) {
	server, client := tcpPair(t)
	peer := network.NewPeer(client)

	// Closing the remote end causes the next Read to return an error.
	server.Close()
	client.Close()

	_, err := peer.Read()
	assert.Error(t, err)
}

func TestPeer_ConcurrentWrites(t *testing.T) {
	// N goroutines write to the same Peer concurrently. The reader must receive
	// N well-formed blocks without any framing corruption.
	const N = 20
	server, client := tcpPair(t)
	writer := network.NewPeer(client)
	reader := network.NewPeer(server)

	genesis := mustGenesisBlock(t)

	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			assert.NoError(t, writer.Write(genesis))
		}()
	}

	received := make([]*block.Block, 0, N)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range N {
			b, err := reader.Read()
			if err != nil {
				return
			}
			received = append(received, b)
		}
	}()

	wg.Wait()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for concurrent writes to be received")
	}

	assert.Len(t, received, N)
	for _, b := range received {
		assert.Equal(t, genesis.Hash, b.Hash, "each received block must be uncorrupted")
	}
}

// ---- Pool tests -------------------------------------------------------------

func TestPool_EmptyOnCreate(t *testing.T) {
	p := network.NewPool()
	assert.Equal(t, 0, p.Len())
}

func TestPool_AddLen(t *testing.T) {
	// Use real TCP so each peer has a distinct remote address.
	s1, c1 := tcpPair(t)
	s2, c2 := tcpPair(t)
	_ = s1
	_ = s2

	p := network.NewPool()
	p.Add(network.NewPeer(c1))
	p.Add(network.NewPeer(c2))
	assert.Equal(t, 2, p.Len())
}

func TestPool_RemoveDecrementsLen(t *testing.T) {
	s, c := tcpPair(t)
	_ = s

	peer := network.NewPeer(c)
	p := network.NewPool()
	p.Add(peer)
	require.Equal(t, 1, p.Len())

	p.Remove(peer.Addr())
	assert.Equal(t, 0, p.Len())
}

func TestPool_AddReplacesExistingAddr(t *testing.T) {
	// Adding a peer whose address is already registered closes the old connection
	// and replaces it. Len stays 1.
	s, c := tcpPair(t)
	_ = s

	p := network.NewPool()
	p.Add(network.NewPeer(c))
	require.Equal(t, 1, p.Len())

	// Adding the same connection address a second time closes the old entry
	// and replaces it — Len stays at 1.
	p.Add(network.NewPeer(c)) // old entry closed; new entry registered
	assert.Equal(t, 1, p.Len())
}

func TestPool_BroadcastReachesAllPeers(t *testing.T) {
	// Three TCP pairs; the client side is registered in the pool.
	// Each server reads the broadcast block.
	const N = 3
	servers := make([]net.Conn, N)
	clients := make([]net.Conn, N)
	for i := range N {
		servers[i], clients[i] = tcpPair(t)
	}

	p := network.NewPool()
	readers := make([]*network.Peer, N)
	for i := range N {
		p.Add(network.NewPeer(clients[i]))
		readers[i] = network.NewPeer(servers[i])
	}

	genesis := mustGenesisBlock(t)
	p.Broadcast(genesis)

	for i, r := range readers {
		servers[i].SetDeadline(time.Now().Add(time.Second))
		b, err := r.Read()
		require.NoError(t, err, "peer %d did not receive broadcast", i)
		assert.Equal(t, genesis.Hash, b.Hash)
	}
}

func TestPool_BroadcastRemovesBrokenPeer(t *testing.T) {
	// net.Pipe is used here instead of TCP because TCP write errors are
	// asynchronous — the first write may succeed (kernel buffers it) even
	// when the remote is gone. net.Pipe is synchronous: Write returns
	// io.ErrClosedPipe immediately when the other end is closed.
	c1, c2 := net.Pipe()
	c2.Close() // remote gone — next Write on c1 fails immediately
	defer c1.Close()

	p := network.NewPool()
	p.Add(network.NewPeer(c1))
	require.Equal(t, 1, p.Len())

	p.Broadcast(mustGenesisBlock(t))

	assert.Equal(t, 0, p.Len(), "broken peer must be removed after failed write")
}

// TestPool_ConnectAndReadLoop verifies that Pool.Connect dials a listener,
// registers the peer, and the readLoop delivers blocks to the router.
func TestPool_ConnectAndReadLoop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	router := newStubRouter()
	p := network.NewPool()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Accept one connection and write a block to it (simulates a peer sending).
	genesis := mustGenesisBlock(t)
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		peer := network.NewPeer(conn)
		peer.Write(genesis) //nolint:errcheck
	}()

	require.NoError(t, p.Connect(ctx, ln.Addr().String(), router))
	<-accepted

	require.Eventually(t, func() bool {
		return len(router.Received()) == 1
	}, time.Second, 5*time.Millisecond)

	assert.Equal(t, genesis.Hash, router.Received()[0].Hash)
}

// TestPool_RunBroadcastsOutBlocks verifies that Pool.Run forwards blocks from
// router.OutBlocks() to all connected peers via broadcastLoop.
func TestPool_RunBroadcastsOutBlocks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	router := newStubRouter()
	p := network.NewPool()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.Run(ctx, ln, router)

	// Dial the listener from the test so p accepts us as an inbound peer.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Wait for the acceptLoop to register the peer.
	require.Eventually(t, func() bool { return p.Len() == 1 }, time.Second, 5*time.Millisecond)

	// Push a block through the router's OutBlocks channel.
	genesis := mustGenesisBlock(t)
	router.out <- genesis

	// Read it from the connection that was accepted.
	conn.SetDeadline(time.Now().Add(time.Second))
	got, err := network.NewPeer(conn).Read()
	require.NoError(t, err)
	assert.Equal(t, genesis.Hash, got.Hash)
}

// TestPool_BidirectionalExchange verifies full duplex: blocks flow A→B and B→A
// through two pools connected to each other.
func TestPool_BidirectionalExchange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerA := newStubRouter()
	routerB := newStubRouter()
	poolA := network.NewPool()
	poolB := network.NewPool()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pool B listens; pool A connects.
	go poolB.Run(ctx, ln, routerB)

	require.NoError(t, poolA.Connect(ctx, ln.Addr().String(), routerA))

	// Wait for both sides to register the peer.
	require.Eventually(t, func() bool { return poolA.Len() == 1 && poolB.Len() == 1 }, time.Second, 5*time.Millisecond)

	genesis := mustGenesisBlock(t)
	move := mustMoveBlock(t, genesis)

	// A broadcasts genesis to B.
	poolA.Broadcast(genesis)
	// B broadcasts move to A.
	poolB.Broadcast(move)

	require.Eventually(t, func() bool { return len(routerB.Received()) >= 1 }, time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return len(routerA.Received()) >= 1 }, time.Second, 5*time.Millisecond)

	assert.Equal(t, genesis.Hash, routerB.Received()[0].Hash, "B must receive A's block")
	assert.Equal(t, move.Hash, routerA.Received()[0].Hash, "A must receive B's block")
}
