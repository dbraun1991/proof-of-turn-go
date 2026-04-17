// Package block defines the Block type and constructors for each of the five
// Proof-of-Turn block kinds: Genesis, GameMove, Transition, Vote, and Finalizing.
//
// For a full description of the PoT protocol and the role of each block type,
// see the thesis: https://arxiv.org/pdf/2304.07384v1
//
// # Block lifecycle
//
// Every block is created via a typed constructor (NewGenesisBlock, NewGameMoveBlock,
// etc.), which computes the canonical hash and signs it with the author's private key.
//
// Transition (handover) blocks are the exception: they require two signatures.
// The outgoing Leading Node calls NewTransitionBlock; the incoming Leading Node
// then calls AddCoSignature before the block can pass VerifySignatures.
//
// # Validation separation
//
// Valid checks structural integrity only (index sequence, hash chain, hash correctness).
// VerifySignatures checks Ed25519 signatures independently. Keeping these separate
// allows the blockchain layer to enforce structure without requiring access to the
// peer public-key registry. A node replaying a chain from a trusted peer can verify
// structure first and signatures second, or skip signature re-verification entirely.
package block

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	potcrypto "pot-node/crypto"
)

// BlockType identifies the role a block plays in the PoT protocol.
type BlockType string

const (
	// BlockTypeGenesis is the first block on every chain. Index 0, empty PrevHash.
	BlockTypeGenesis BlockType = "genesis"

	// BlockTypeGameMove carries a single player action submitted during
	// the Leading Node's turn slot.
	BlockTypeGameMove BlockType = "game_move"

	// BlockTypeTransition marks the handover between outgoing and incoming
	// Leading Node. Must be co-signed by both parties — a hard thesis requirement.
	BlockTypeTransition BlockType = "transition"

	// BlockTypeVote is broadcast by any node when a Leading Node misses its
	// turn slot. Reaching ≥50% active nodes triggers a forced handover.
	BlockTypeVote BlockType = "vote"

	// BlockTypeFinalizing is emitted by the Leading Node to end its turn early,
	// before the full turn duration expires.
	BlockTypeFinalizing BlockType = "finalizing"
)

// GenesisData is the payload of a genesis block.
type GenesisData struct {
	Note string `json:"note"`
}

// GameMoveData carries a single attack action submitted during the Leading
// Node's turn slot. The Seed field provides deterministic randomness for the
// dice roll — see MoveSeed for the derivation and its known limitation.
type GameMoveData struct {
	MoveType string `json:"moveType"` // currently always "attack"
	From     int    `json:"from"`     // attacking territory ID
	To       int    `json:"to"`       // defending territory ID
	PlayerID string `json:"playerId"`
	// Seed is derived from the previous block's hash (see MoveSeed).
	//
	// TODO(commit-reveal): The seed is computable before the move is submitted —
	// a player can preview the dice outcome and decide against unfavourable moves.
	// Proper fix: commit-reveal scheme where the incoming LN contributes entropy
	// after the move intent is committed to the chain, so neither party can
	// unilaterally control the result.
	Seed uint64 `json:"seed"`
}

// MoveSeed derives a deterministic seed from prev's hash.
// The first 8 bytes of SHA-256(prevHash) are interpreted as a big-endian uint64.
//
// See the TODO on GameMoveData.Seed — this seed is predictable before submission.
func MoveSeed(prev *Block) uint64 {
	h := sha256.Sum256([]byte(prev.Hash))
	return binary.BigEndian.Uint64(h[:8])
}

// TransitionData identifies the outgoing and incoming Leading Node.
type TransitionData struct {
	From string `json:"from"` // outgoing Leading Node ID
	To   string `json:"to"`   // incoming Leading Node ID
}

// VoteData records which node missed its turn and who is casting the vote.
type VoteData struct {
	MissedNode string `json:"missedNode"`
	VoterID    string `json:"voterId"`
}

// FinalizingData is the payload of a finalizing block.
type FinalizingData struct {
	Note string `json:"note"`
}

// Block is a single entry in the Proof-of-Turn chain.
//
// The Hash field covers all content fields (excluding Hash and Signature).
// Signature is the Ed25519 signature of the hash bytes by the AuthorID node.
// Transition blocks additionally carry CoSignerID and CoSignature from the
// incoming Leading Node, signing the same hash bytes.
type Block struct {
	Index     int             `json:"index"`
	Timestamp int64           `json:"timestamp"` // Unix milliseconds
	Type      BlockType       `json:"type"`
	Data      json.RawMessage `json:"data"`
	PrevHash  string          `json:"prevHash"`
	Hash      string          `json:"hash"`
	AuthorID  string          `json:"authorId"`
	Signature []byte          `json:"signature"`

	// CoSignerID and CoSignature are only populated on BlockTypeTransition.
	CoSignerID  string `json:"coSignerId,omitempty"`
	CoSignature []byte `json:"coSignature,omitempty"`
}

// nowMs returns the current Unix timestamp in milliseconds.
// Declared as a variable so tests can substitute a fixed value
// without needing to inject a clock through every constructor.
var nowMs = func() int64 { return time.Now().UnixMilli() }

// newBlock is the shared constructor used by all typed constructors.
func newBlock(prev *Block, bType BlockType, authorID string, data any) (*Block, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal block data: %w", err)
	}

	prevHash := ""
	index := 0
	if prev != nil {
		prevHash = prev.Hash
		index = prev.Index + 1
	}

	b := &Block{
		Index:     index,
		Timestamp: nowMs(),
		Type:      bType,
		Data:      raw,
		PrevHash:  prevHash,
		AuthorID:  authorID,
	}
	b.Hash = b.computeHash()
	return b, nil
}

// computeHash returns the SHA-256 hex digest of the block's canonical fields.
//
// Excluded from the hash input: Hash, Signature, CoSignerID, CoSignature.
// Hash and Signature are excluded because they depend on this value.
// CoSignerID and CoSignature are excluded deliberately: the co-signature on a
// Transition block signs the same hash bytes as the primary signature, so both
// parties commit to identical content. Adding co-signer identity to the hash
// would make it impossible to pre-compute the hash before the co-signer is known.
func (b *Block) computeHash() string {
	input := struct {
		Index     int             `json:"index"`
		Timestamp int64           `json:"timestamp"`
		Type      BlockType       `json:"type"`
		Data      json.RawMessage `json:"data"`
		PrevHash  string          `json:"prevHash"`
		AuthorID  string          `json:"authorId"`
	}{
		Index:     b.Index,
		Timestamp: b.Timestamp,
		Type:      b.Type,
		Data:      b.Data,
		PrevHash:  b.PrevHash,
		AuthorID:  b.AuthorID,
	}
	raw, _ := json.Marshal(input)
	return potcrypto.Hash(string(raw))
}

// applySignature hex-decodes the block's hash and signs the resulting bytes.
// Signing the hash rather than the raw payload means the signature commits to
// the fully assembled, canonical block — including its position in the chain
// (via Index and PrevHash) and its authorship (via AuthorID).
func applySignature(b *Block, key ed25519.PrivateKey) {
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.Signature = potcrypto.Sign(key, hashBytes)
}

// NewGenesisBlock creates the first block on a chain (index 0, empty PrevHash).
func NewGenesisBlock(authorID string, key ed25519.PrivateKey) (*Block, error) {
	b, err := newBlock(nil, BlockTypeGenesis, authorID, GenesisData{Note: "Genesis block"})
	if err != nil {
		return nil, err
	}
	applySignature(b, key)
	return b, nil
}

// NewGameMoveBlock creates a block carrying a single player action.
func NewGameMoveBlock(prev *Block, authorID string, move GameMoveData, key ed25519.PrivateKey) (*Block, error) {
	b, err := newBlock(prev, BlockTypeGameMove, authorID, move)
	if err != nil {
		return nil, err
	}
	applySignature(b, key)
	return b, nil
}

// NewTransitionBlock creates a handover block signed by the outgoing Leading Node.
// The incoming Leading Node must call AddCoSignature before the block is valid.
func NewTransitionBlock(prev *Block, fromID, toID string, fromKey ed25519.PrivateKey) (*Block, error) {
	b, err := newBlock(prev, BlockTypeTransition, fromID, TransitionData{From: fromID, To: toID})
	if err != nil {
		return nil, err
	}
	applySignature(b, fromKey)
	return b, nil
}

// AddCoSignature adds the incoming Leading Node's counter-signature to a Transition block.
// Both signatures cover the same hash bytes. The block should not be appended to the
// chain until this has been called.
func AddCoSignature(b *Block, coSignerID string, coKey ed25519.PrivateKey) error {
	if b.Type != BlockTypeTransition {
		return errors.New("co-signature only applies to transition blocks")
	}
	hashBytes, err := hex.DecodeString(b.Hash)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}
	b.CoSignerID = coSignerID
	b.CoSignature = potcrypto.Sign(coKey, hashBytes)
	return nil
}

// NewVoteBlock creates a block casting a vote for a missed-turn event.
func NewVoteBlock(prev *Block, authorID string, vote VoteData, key ed25519.PrivateKey) (*Block, error) {
	b, err := newBlock(prev, BlockTypeVote, authorID, vote)
	if err != nil {
		return nil, err
	}
	applySignature(b, key)
	return b, nil
}

// NewFinalizingBlock creates a block that ends the Leading Node's turn early.
func NewFinalizingBlock(prev *Block, authorID string, key ed25519.PrivateKey) (*Block, error) {
	b, err := newBlock(prev, BlockTypeFinalizing, authorID, FinalizingData{Note: "Turn finalized early"})
	if err != nil {
		return nil, err
	}
	applySignature(b, key)
	return b, nil
}

// Valid checks the block's structural integrity against its predecessor.
// It verifies index sequence, prevHash linkage, and hash correctness.
//
// Pass nil as prev only for a genesis block. Signature verification is separate;
// use VerifySignatures for that.
func (b *Block) Valid(prev *Block) error {
	if prev == nil {
		if b.Type != BlockTypeGenesis {
			return errors.New("only the genesis block may have no predecessor")
		}
		if b.Index != 0 {
			return errors.New("genesis block must have index 0")
		}
		if b.PrevHash != "" {
			return errors.New("genesis block must have empty prevHash")
		}
	} else {
		if b.Index != prev.Index+1 {
			return fmt.Errorf("expected index %d, got %d", prev.Index+1, b.Index)
		}
		if b.PrevHash != prev.Hash {
			return fmt.Errorf("prevHash mismatch: expected %s, got %s", prev.Hash, b.PrevHash)
		}
	}

	if got := b.computeHash(); got != b.Hash {
		return fmt.Errorf("hash mismatch: stored %s, computed %s", b.Hash, got)
	}

	return nil
}

// VerifySignatures checks Ed25519 signatures on the block.
// publicKeys maps node IDs to their public keys.
// Transition blocks must carry a valid co-signature from the incoming Leading Node.
func (b *Block) VerifySignatures(publicKeys map[string]ed25519.PublicKey) error {
	authorKey, ok := publicKeys[b.AuthorID]
	if !ok {
		return fmt.Errorf("unknown author: %s", b.AuthorID)
	}
	hashBytes, err := hex.DecodeString(b.Hash)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}
	if !potcrypto.Verify(authorKey, hashBytes, b.Signature) {
		return errors.New("invalid author signature")
	}

	if b.Type == BlockTypeTransition {
		if b.CoSignerID == "" {
			return errors.New("transition block missing co-signer")
		}
		coKey, ok := publicKeys[b.CoSignerID]
		if !ok {
			return fmt.Errorf("unknown co-signer: %s", b.CoSignerID)
		}
		if !potcrypto.Verify(coKey, hashBytes, b.CoSignature) {
			return errors.New("invalid co-signature")
		}
	}

	return nil
}

// DecodeData unmarshals the block's Data field into dst.
// dst must be a pointer to the struct type that corresponds to the block's Type:
//
//	BlockTypeGenesis     → *GenesisData
//	BlockTypeGameMove    → *GameMoveData
//	BlockTypeTransition  → *TransitionData
//	BlockTypeVote        → *VoteData
//	BlockTypeFinalizing  → *FinalizingData
func (b *Block) DecodeData(dst any) error {
	return json.Unmarshal(b.Data, dst)
}
