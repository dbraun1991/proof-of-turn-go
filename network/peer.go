// Package network provides TCP-based peer-to-peer transport for the PoT node.
//
// Full protocol specification: https://arxiv.org/pdf/2304.07384v1
//
// # Layers
//
// Peer handles a single TCP connection: it encodes and decodes blocks as
// newline-delimited JSON. One JSON object per line, written atomically.
//
// Pool manages the full set of connected peers and routes blocks between the
// consensus layer and the wire:
//
//	consensus.TurnManager.OutBlocks  →  Pool.broadcastLoop  →  Peer.Write  →  TCP
//	TCP  →  Peer.Read  →  Pool.readLoop  →  consensus.TurnManager.ReceiveBlock
//
// # Design notes
//
// The network package defines the BlockRouter interface rather than importing
// consensus directly. This keeps the dependency graph acyclic and allows the
// pool to be tested with a lightweight stub instead of a full TurnManager.
//
// All state in Pool is protected by a sync.RWMutex. Peer.Write is protected
// by its own mutex so multiple goroutines (e.g. broadcastLoop + a concurrent
// Broadcast call) cannot interleave JSON writes on the same connection.
package network

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"pot-node/block"
)

// Peer wraps a single TCP connection to a remote PoT node.
//
// Blocks are serialised as newline-delimited JSON — one complete JSON object
// per Write call. json.Encoder appends the newline automatically, and
// json.Decoder consumes exactly one object per Decode call, so framing is
// handled without a separate length prefix.
//
// Write is safe for concurrent use; Read is intended for a single goroutine.
type Peer struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	mu   sync.Mutex // serialises concurrent Write calls
}

// NewPeer wraps conn in a Peer. Does not take ownership of closing;
// call Close when the connection should be torn down.
func NewPeer(conn net.Conn) *Peer {
	return &Peer{
		conn: conn,
		enc:  json.NewEncoder(conn),
		dec:  json.NewDecoder(conn),
	}
}

// Write encodes b as a single JSON line and sends it to the peer.
// Safe for concurrent use from multiple goroutines — writes are serialised
// internally to prevent interleaved JSON on the connection.
func (p *Peer) Write(b *block.Block) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.enc.Encode(b); err != nil {
		return fmt.Errorf("write to %s: %w", p.Addr(), err)
	}
	return nil
}

// Read decodes and returns the next block from the peer.
// Blocks the calling goroutine until a complete JSON object is received or
// the connection is closed. Only one goroutine should call Read on a Peer —
// concurrent reads are not safe because json.Decoder maintains internal state.
func (p *Peer) Read() (*block.Block, error) {
	var b block.Block
	if err := p.dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("read from %s: %w", p.Addr(), err)
	}
	return &b, nil
}

// Addr returns the remote address of the connection. Used as the pool's
// de-duplication key.
func (p *Peer) Addr() string {
	return p.conn.RemoteAddr().String()
}

// Close closes the underlying TCP connection, unblocking any pending Read call.
func (p *Peer) Close() error {
	return p.conn.Close()
}
