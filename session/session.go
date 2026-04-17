// Package session handles the bootstrap handshake that runs once, before any
// consensus activity begins.
//
// Full protocol specification: https://arxiv.org/pdf/2304.07384v1
//
// # Bootstrap handshake
//
// Before the TurnManager starts, all peers must agree on two things: the
// ordered peer list (which determines turn order for the entire session) and
// the genesis block (the chain anchor). The session host — the node that
// creates the session — is the authoritative source of both.
//
// The handshake is a single JSON object written by the host and read by each
// joining peer immediately after the TCP connection is established, before any
// block traffic flows:
//
//	host ──── Info (JSON) ───► joiner
//
// Once a joiner has called Receive and Validate, it holds everything needed to
// construct a blockchain.Chain and a consensus.Config and call TurnManager.Run.
//
// # Wire format
//
// Info is encoded as a single newline-delimited JSON object — the same framing
// used by the network layer for blocks. ed25519.PublicKey ([]byte) is base64 by
// the standard encoding/json rules.
package session

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"pot-node/block"
	"pot-node/crypto"
)

// PeerMeta is the static identity of one session participant.
// ID must equal crypto.NodeID(PubKey); Validate enforces this invariant so
// callers cannot construct an inconsistent peer list.
//
// Addr is the block-traffic TCP address for this peer. Nodes use it to build
// the full-mesh connections required after bootstrap (each node dials all peers
// with a lower index). Empty for a single-node session.
//
// APIAddr is the HTTP API address (host:port) for this peer. Joining nodes use
// it to fetch the current chain from the host on startup.
type PeerMeta struct {
	ID      string            `json:"id"`
	PubKey  ed25519.PublicKey `json:"pub_key"`
	Addr    string            `json:"addr,omitempty"`
	APIAddr string            `json:"api_addr,omitempty"`
}

// Info is the payload exchanged during the bootstrap handshake.
// It carries everything a joining peer needs before the consensus loop starts.
//
// Peers is the canonical turn order for the entire session — index 0 leads
// first. The list must be identical on every node; any divergence would cause
// nodes to disagree on whose turn it is.
type Info struct {
	Peers   []PeerMeta   `json:"peers"`
	Genesis *block.Block `json:"genesis"`
}

// Send encodes info as a single JSON line and writes it to conn.
// Called by the session host immediately after accepting each connection.
func Send(conn net.Conn, info Info) error {
	if err := json.NewEncoder(conn).Encode(info); err != nil {
		return fmt.Errorf("send session info: %w", err)
	}
	return nil
}

// Receive decodes and returns the Info written by the session host.
// Called by each joining peer immediately after dialing.
func Receive(conn net.Conn) (Info, error) {
	var info Info
	if err := json.NewDecoder(conn).Decode(&info); err != nil {
		return Info{}, fmt.Errorf("receive session info: %w", err)
	}
	return info, nil
}

// Hello is the first message a joining peer sends to the session host.
// The host collects one Hello per expected peer, then builds the peer list and
// sends Info back. This two-message exchange lets the host assign IDs without
// any out-of-band key distribution.
//
// Addr is the TCP address other peers should dial to reach this node for block
// traffic. It must be a full host:port (e.g. "127.0.0.1:7001" or "nodeB:7001")
// so that nodes on different machines or Docker containers can connect.
//
// APIAddr is the HTTP API address (host:port) for this node. It is used by
// joining peers to fetch the current chain state on startup.
type Hello struct {
	ID      string            `json:"id"`
	PubKey  ed25519.PublicKey `json:"pub_key"`
	Addr    string            `json:"addr"`
	APIAddr string            `json:"api_addr,omitempty"`
}

// SendHello encodes h as a single JSON line and writes it to conn.
// Called by joining peers immediately after dialing the host.
func SendHello(conn net.Conn, h Hello) error {
	if err := json.NewEncoder(conn).Encode(h); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	return nil
}

// ReceiveHello decodes and returns the Hello sent by a joining peer.
// Called by the session host after accepting each connection.
func ReceiveHello(conn net.Conn) (Hello, error) {
	var h Hello
	if err := json.NewDecoder(conn).Decode(&h); err != nil {
		return Hello{}, fmt.Errorf("receive hello: %w", err)
	}
	return h, nil
}

// Validate checks that info is self-consistent and cryptographically sound:
//   - at least one peer is listed
//   - every peer's ID matches crypto.NodeID(PubKey) — prevents a peer from
//     claiming an identity whose key they do not hold
//   - the genesis block is structurally valid (index 0, correct hash)
//   - the genesis block's author signature verifies against the listed key —
//     prevents a rogue host from substituting a forged genesis
func (info Info) Validate() error {
	if len(info.Peers) == 0 {
		return errors.New("peer list is empty")
	}

	keys := make(map[string]ed25519.PublicKey, len(info.Peers))
	for _, p := range info.Peers {
		if got := crypto.NodeID(p.PubKey); got != p.ID {
			return fmt.Errorf("peer ID mismatch: claimed %s, key hashes to %s", p.ID, got)
		}
		keys[p.ID] = p.PubKey
	}

	if info.Genesis == nil {
		return errors.New("genesis block is nil")
	}
	if info.Genesis.Type != block.BlockTypeGenesis {
		return fmt.Errorf("expected genesis block, got %s", info.Genesis.Type)
	}
	if err := info.Genesis.Valid(nil); err != nil {
		return fmt.Errorf("genesis block structurally invalid: %w", err)
	}
	// Signature check catches a rogue host replacing the genesis with one
	// signed by a key not in the agreed peer list.
	if err := info.Genesis.VerifySignatures(keys); err != nil {
		return fmt.Errorf("genesis signature invalid: %w", err)
	}
	return nil
}
