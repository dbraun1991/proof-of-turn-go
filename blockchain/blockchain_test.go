package blockchain_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/block"
	"pot-node/blockchain"
	"pot-node/crypto"
)

// helpers

func mustKeyPair(t *testing.T) crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

func nodeID(kp crypto.KeyPair) string { return crypto.NodeID(kp.Public) }

func keyMap(pairs ...crypto.KeyPair) map[string]ed25519.PublicKey {
	m := make(map[string]ed25519.PublicKey, len(pairs))
	for _, kp := range pairs {
		m[crypto.NodeID(kp.Public)] = kp.Public
	}
	return m
}

func mustChain(t *testing.T) (*blockchain.Chain, crypto.KeyPair) {
	t.Helper()
	kp := mustKeyPair(t)
	c, err := blockchain.NewWithGenesis(nodeID(kp), kp.Private)
	require.NoError(t, err)
	return c, kp
}

// creation

func TestNewWithGenesisHasOneBlock(t *testing.T) {
	c, _ := mustChain(t)
	assert.Equal(t, 1, c.Len())
}

func TestNewWithGenesisLatestIsGenesis(t *testing.T) {
	c, _ := mustChain(t)
	assert.Equal(t, block.BlockTypeGenesis, c.Latest().Type)
}

func TestNewChainIsEmpty(t *testing.T) {
	c := blockchain.New()
	assert.Equal(t, 0, c.Len())
	assert.Nil(t, c.Latest())
}

// append

func TestAppendValidBlock(t *testing.T) {
	c, kp := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, err := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)
	require.NoError(t, err)

	require.NoError(t, c.Append(b, keyMap(kp)))
	assert.Equal(t, 2, c.Len())
}

func TestAppendWithSignatureVerification(t *testing.T) {
	c, kp := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)
	assert.NoError(t, c.Append(b, keyMap(kp)))
}

func TestAppendRejectsWrongPrevHash(t *testing.T) {
	c, kp := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)
	b.PrevHash = "badhash"

	assert.Error(t, c.Append(b, nil))
	assert.Equal(t, 1, c.Len(), "chain must not grow on rejected block")
}

func TestAppendRejectsWrongIndex(t *testing.T) {
	c, kp := mustChain(t)
	// create a second chain to get a block with a different index
	c2, kp2 := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp2)}
	b, _ := block.NewGameMoveBlock(c2.Latest(), nodeID(kp2), move, kp2.Private)

	// b has index 1 and valid structure for c2, but prevHash will mismatch c
	assert.Error(t, c.Append(b, nil))
	_ = kp
}

func TestAppendRejectsInvalidSignature(t *testing.T) {
	c, kp := mustChain(t)
	kpWrong := mustKeyPair(t)

	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)

	// present wrong public key for the author
	badKeys := map[string]ed25519.PublicKey{nodeID(kp): kpWrong.Public}
	assert.Error(t, c.Append(b, badKeys))
}

// IsValid

func TestIsValidOnFreshChain(t *testing.T) {
	c, _ := mustChain(t)
	assert.NoError(t, c.IsValid())
}

func TestIsValidFailsOnEmptyChain(t *testing.T) {
	c := blockchain.New()
	assert.Error(t, c.IsValid())
}

func TestIsValidAfterMultipleBlocks(t *testing.T) {
	c, kp := mustChain(t)
	for i := 0; i < 5; i++ {
		move := block.GameMoveData{MoveType: "attack", From: i, To: i + 1, PlayerID: nodeID(kp)}
		b, _ := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)
		require.NoError(t, c.Append(b, nil))
	}
	assert.NoError(t, c.IsValid())
}

// Blocks

func TestBlocksReturnsCopy(t *testing.T) {
	c, _ := mustChain(t)
	blocks := c.Blocks()
	assert.Equal(t, 1, len(blocks))
	// mutating the returned slice must not affect the chain
	blocks[0] = nil
	assert.NotNil(t, c.Latest())
}

// ReplaceIfLonger

func TestReplaceIfLongerAcceptsLongerChain(t *testing.T) {
	c, kp := mustChain(t)

	// build a longer valid chain
	c2, kp2 := mustChain(t)
	for i := 0; i < 3; i++ {
		move := block.GameMoveData{MoveType: "attack", From: i, To: i + 1, PlayerID: nodeID(kp2)}
		b, _ := block.NewGameMoveBlock(c2.Latest(), nodeID(kp2), move, kp2.Private)
		require.NoError(t, c2.Append(b, nil))
	}

	replaced, err := c.ReplaceIfLonger(c2.Blocks())
	require.NoError(t, err)
	assert.True(t, replaced)
	assert.Equal(t, c2.Len(), c.Len())
	_ = kp
}

func TestReplaceIfLongerRejectsShorterChain(t *testing.T) {
	c, kp := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(c.Latest(), nodeID(kp), move, kp.Private)
	require.NoError(t, c.Append(b, nil))

	// candidate has only genesis
	c2, _ := mustChain(t)
	replaced, err := c.ReplaceIfLonger(c2.Blocks())
	require.NoError(t, err)
	assert.False(t, replaced)
	assert.Equal(t, 2, c.Len(), "longer chain must be retained")
}

func TestReplaceIfLongerRejectsInvalidCandidate(t *testing.T) {
	c, _ := mustChain(t)

	c2, kp2 := mustChain(t)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp2)}
	b, _ := block.NewGameMoveBlock(c2.Latest(), nodeID(kp2), move, kp2.Private)
	require.NoError(t, c2.Append(b, nil))

	// corrupt the candidate
	candidate := c2.Blocks()
	candidate[1].PrevHash = "corrupted"

	replaced, err := c.ReplaceIfLonger(candidate)
	assert.Error(t, err)
	assert.False(t, replaced)
}
