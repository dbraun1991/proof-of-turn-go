package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"pot-node/block"
)

// BlockRouter is the interface through which Pool exchanges blocks with the
// consensus layer. consensus.TurnManager satisfies this interface; in tests
// a lightweight stub is used instead.
type BlockRouter interface {
	// ReceiveBlock delivers a block received from a peer to the consensus layer.
	ReceiveBlock(b *block.Block)
	// OutBlocks returns the channel on which the consensus layer emits blocks
	// that should be broadcast to all connected peers.
	OutBlocks() <-chan *block.Block
}

// Pool manages the set of connected peers and routes blocks between the
// consensus layer and the network.
//
// # Thread safety
//
// The peer map is protected by a sync.RWMutex. Broadcast takes a snapshot of
// the peer list under a read lock, releases the lock, then writes to each peer
// individually. This means a Broadcast call never blocks new connections from
// being added concurrently.
//
// # Peer lifecycle
//
// Peers are added via Add (called by Connect and acceptLoop). They are removed
// automatically when a Write or the readLoop encounters an error, or explicitly
// via Remove. Removing a peer closes its TCP connection.
type Pool struct {
	mu    sync.RWMutex
	peers map[string]*Peer // remote address → peer
}

// NewPool creates an empty pool.
func NewPool() *Pool {
	return &Pool{peers: make(map[string]*Peer)}
}

// Add registers peer with the pool. If a peer with the same remote address is
// already registered the old connection is closed and replaced. This handles
// reconnection from the same remote host without leaking connections.
func (p *Pool) Add(peer *Peer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.peers[peer.Addr()]; ok {
		old.Close()
	}
	p.peers[peer.Addr()] = peer
}

// Remove closes and deregisters the peer at addr. No-op if addr is unknown.
func (p *Pool) Remove(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if peer, ok := p.peers[addr]; ok {
		peer.Close()
		delete(p.peers, addr)
	}
}

// Len returns the number of currently registered peers.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.peers)
}

// Broadcast writes b to every registered peer. Peers whose Write call fails
// are removed from the pool — a broken connection is treated as a permanent
// departure since PoT uses a fixed, session-scoped peer set.
func (p *Pool) Broadcast(b *block.Block) {
	// Snapshot under read lock so we do not hold the lock during I/O.
	p.mu.RLock()
	peers := make([]*Peer, 0, len(p.peers))
	for _, peer := range p.peers {
		peers = append(peers, peer)
	}
	p.mu.RUnlock()

	for _, peer := range peers {
		if err := peer.Write(b); err != nil {
			// Write lock safe here: read lock was released above.
			p.Remove(peer.Addr())
		}
	}
}

// Register wraps conn in a Peer, adds it to the pool, and starts its read loop.
// Use this when a connection is established outside the pool — for example
// after a session bootstrap handshake — and the caller wants it to participate
// in normal block traffic without an additional Accept/Dial cycle.
func (p *Pool) Register(ctx context.Context, conn net.Conn, router BlockRouter) {
	peer := NewPeer(conn)
	p.Add(peer)
	go p.readLoop(ctx, peer, router)
}

// Connect dials addr, registers the peer, and starts a read loop that
// delivers inbound blocks to router. The loop exits when ctx is cancelled
// or the connection is closed.
//
// A 5-second dial timeout is applied. The caller is responsible for retrying
// if the remote node is not yet ready.
func (p *Pool) Connect(ctx context.Context, addr string, router BlockRouter) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	peer := NewPeer(conn)
	p.Add(peer)
	go p.readLoop(ctx, peer, router)
	return nil
}

// Run accepts incoming connections and routes blocks until ctx is cancelled.
//
// Two loops run concurrently inside Run:
//   - acceptLoop: registers each incoming connection and starts its readLoop.
//   - broadcastLoop: forwards every block from router.OutBlocks to all peers.
//
// Run closes ln when ctx is cancelled so that any pending Accept call unblocks
// immediately. Run itself blocks until broadcastLoop exits.
func (p *Pool) Run(ctx context.Context, ln net.Listener, router BlockRouter) {
	// Close the listener on cancellation to unblock ln.Accept.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go p.acceptLoop(ctx, ln, router)
	p.broadcastLoop(ctx, router)
}

// acceptLoop accepts incoming TCP connections, registers each as a Peer, and
// starts a readLoop goroutine to deliver its blocks to router. Returns when
// ln.Accept returns an error (typically because Run closed ln on ctx cancel).
func (p *Pool) acceptLoop(ctx context.Context, ln net.Listener, router BlockRouter) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		peer := NewPeer(conn)
		p.Add(peer)
		go p.readLoop(ctx, peer, router)
	}
}

// readLoop reads blocks from peer and delivers them to router until the
// connection closes or ctx is cancelled. Removes peer from the pool on exit,
// closing its connection if it is still open.
func (p *Pool) readLoop(ctx context.Context, peer *Peer, router BlockRouter) {
	defer p.Remove(peer.Addr())
	for {
		b, err := peer.Read()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
			router.ReceiveBlock(b)
		}
	}
}

// broadcastLoop forwards every block emitted by router.OutBlocks to all
// connected peers. Blocks until ctx is cancelled.
func (p *Pool) broadcastLoop(ctx context.Context, router BlockRouter) {
	out := router.OutBlocks() // evaluated once; same channel for the session lifetime
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-out:
			p.Broadcast(b)
		}
	}
}
