// Package blockchain manages the Proof-of-Turn chain: a thread-safe, append-only
// sequence of validated blocks.
//
// For the protocol context behind these design decisions, see the thesis:
// https://arxiv.org/pdf/2304.07384v1
//
// # Validation policy
//
// Append validates structural integrity (index sequence, prevHash linkage, hash
// correctness) on every call. Signature verification is optional: pass a non-nil
// publicKeys map to enable it, or nil to skip. Skipping is appropriate when
// replaying a chain received from a peer whose blocks were already verified
// individually at the network layer — re-verifying signatures on every replay
// would be redundant and expensive.
//
// # Longest-chain rule
//
// In a PoT session the peer set is small and known in advance, so chain forks are
// rare. When they do occur — typically from a network partition — the protocol
// resolves them by keeping the longest structurally valid chain. This mirrors
// Nakamoto consensus but without the proof-of-work cost: in PoT, length reflects
// the number of completed turn slots, not accumulated computation.
// ReplaceIfLonger performs structural validation only; the caller must verify
// signatures on each block before offering a candidate chain.
package blockchain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"pot-node/block"
)

// Chain is a thread-safe, append-only sequence of PoT blocks.
type Chain struct {
	mu     sync.RWMutex
	blocks []*block.Block
}

// New returns an empty chain. Append a genesis block before using the chain.
func New() *Chain {
	return &Chain{}
}

// NewWithGenesis creates a chain and appends a genesis block signed by the given key.
func NewWithGenesis(authorID string, key ed25519.PrivateKey) (*Chain, error) {
	genesis, err := block.NewGenesisBlock(authorID, key)
	if err != nil {
		return nil, fmt.Errorf("create genesis block: %w", err)
	}
	c := New()
	if err := c.Append(genesis, nil); err != nil {
		return nil, fmt.Errorf("append genesis block: %w", err)
	}
	return c, nil
}

// Append validates b against the current chain head and appends it on success.
//
// Pass a non-nil publicKeys map to also verify Ed25519 signatures.
// Pass nil to skip signature verification (structural checks always run).
func (c *Chain) Append(b *block.Block, publicKeys map[string]ed25519.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.latest()
	if err := b.Valid(prev); err != nil {
		return fmt.Errorf("structural validation failed: %w", err)
	}
	if publicKeys != nil {
		if err := b.VerifySignatures(publicKeys); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	c.blocks = append(c.blocks, b)
	return nil
}

// Latest returns the most recently appended block, or nil if the chain is empty.
func (c *Chain) Latest() *block.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest()
}

// latest is the unlocked inner accessor, called from within locked methods.
func (c *Chain) latest() *block.Block {
	if len(c.blocks) == 0 {
		return nil
	}
	return c.blocks[len(c.blocks)-1]
}

// Len returns the number of blocks in the chain.
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blocks)
}

// Blocks returns a copy of all blocks in chronological order (oldest first).
func (c *Chain) Blocks() []*block.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*block.Block, len(c.blocks))
	copy(out, c.blocks)
	return out
}

// IsValid verifies the entire chain's structural integrity.
// Signatures are not checked; use block.VerifySignatures per block for that.
func (c *Chain) IsValid() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.blocks) == 0 {
		return errors.New("chain is empty")
	}
	for i, b := range c.blocks {
		var prev *block.Block
		if i > 0 {
			prev = c.blocks[i-1]
		}
		if err := b.Valid(prev); err != nil {
			return fmt.Errorf("block %d: %w", i, err)
		}
	}
	return nil
}

// ReplaceIfLonger replaces the local chain with candidate if candidate is strictly
// longer and structurally valid. Returns true if replacement occurred.
//
// Length is the sole tiebreaker because in a PoT session there is no mining
// difficulty to compare — every block costs only one Ed25519 signature. A longer
// chain means more completed turn slots, which is the closest analogue to
// accumulated work. See the package doc for context on when forks arise.
//
// Signature verification is the caller's responsibility; verify each block before
// passing the candidate here.
func (c *Chain) ReplaceIfLonger(candidate []*block.Block) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(candidate) <= len(c.blocks) {
		return false, nil
	}

	for i, b := range candidate {
		var prev *block.Block
		if i > 0 {
			prev = candidate[i-1]
		}
		if err := b.Valid(prev); err != nil {
			return false, fmt.Errorf("candidate block %d invalid: %w", i, err)
		}
	}

	c.blocks = make([]*block.Block, len(candidate))
	copy(c.blocks, candidate)
	return true, nil
}
