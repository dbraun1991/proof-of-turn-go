package block_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/block"
	"pot-node/crypto"
)

// helpers

func mustKeyPair(t *testing.T) crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

func keyMap(pairs ...crypto.KeyPair) map[string]ed25519.PublicKey {
	m := make(map[string]ed25519.PublicKey, len(pairs))
	for _, kp := range pairs {
		m[crypto.NodeID(kp.Public)] = kp.Public
	}
	return m
}

func nodeID(kp crypto.KeyPair) string { return crypto.NodeID(kp.Public) }

// genesis block

func TestNewGenesisBlock(t *testing.T) {
	kp := mustKeyPair(t)
	b, err := block.NewGenesisBlock(nodeID(kp), kp.Private)
	require.NoError(t, err)

	assert.Equal(t, 0, b.Index)
	assert.Equal(t, block.BlockTypeGenesis, b.Type)
	assert.Equal(t, nodeID(kp), b.AuthorID)
	assert.Empty(t, b.PrevHash)
	assert.NotEmpty(t, b.Hash)
	assert.NotEmpty(t, b.Signature)
}

func TestGenesisBlockStructuralValidity(t *testing.T) {
	kp := mustKeyPair(t)
	b, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	assert.NoError(t, b.Valid(nil))
}

func TestGenesisBlockSignatureValid(t *testing.T) {
	kp := mustKeyPair(t)
	b, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	assert.NoError(t, b.VerifySignatures(keyMap(kp)))
}

func TestGenesisBlockSignatureFailsWrongKey(t *testing.T) {
	kp1 := mustKeyPair(t)
	kp2 := mustKeyPair(t)
	b, _ := block.NewGenesisBlock(nodeID(kp1), kp1.Private)
	// present kp2 as the author's key
	keys := map[string]ed25519.PublicKey{nodeID(kp1): kp2.Public}
	assert.Error(t, b.VerifySignatures(keys))
}

// game move block

func TestNewGameMoveBlock(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)

	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, err := block.NewGameMoveBlock(genesis, nodeID(kp), move, kp.Private)
	require.NoError(t, err)

	assert.Equal(t, 1, b.Index)
	assert.Equal(t, block.BlockTypeGameMove, b.Type)
	assert.Equal(t, genesis.Hash, b.PrevHash)
}

func TestGameMoveBlockValid(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(genesis, nodeID(kp), move, kp.Private)
	assert.NoError(t, b.Valid(genesis))
}

func TestGameMoveBlockDecodeData(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	want := block.GameMoveData{MoveType: "attack", From: 3, To: 7, PlayerID: "p1"}
	b, _ := block.NewGameMoveBlock(genesis, nodeID(kp), want, kp.Private)

	var got block.GameMoveData
	require.NoError(t, b.DecodeData(&got))
	assert.Equal(t, want, got)
}

// transition block (handover)

func TestTransitionBlockRequiresCoSignature(t *testing.T) {
	kpFrom := mustKeyPair(t)
	kpTo := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kpFrom), kpFrom.Private)

	b, err := block.NewTransitionBlock(genesis, nodeID(kpFrom), nodeID(kpTo), kpFrom.Private)
	require.NoError(t, err)

	// without co-signature, VerifySignatures must fail
	keys := keyMap(kpFrom, kpTo)
	assert.Error(t, b.VerifySignatures(keys), "transition block without co-signature must fail verification")
}

func TestTransitionBlockValidAfterCoSign(t *testing.T) {
	kpFrom := mustKeyPair(t)
	kpTo := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kpFrom), kpFrom.Private)

	b, _ := block.NewTransitionBlock(genesis, nodeID(kpFrom), nodeID(kpTo), kpFrom.Private)
	require.NoError(t, block.AddCoSignature(b, nodeID(kpTo), kpTo.Private))

	assert.NoError(t, b.Valid(genesis))
	assert.NoError(t, b.VerifySignatures(keyMap(kpFrom, kpTo)))
}

func TestAddCoSignatureRejectsNonTransitionBlock(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	err := block.AddCoSignature(genesis, nodeID(kp), kp.Private)
	assert.Error(t, err)
}

// vote block

func TestNewVoteBlock(t *testing.T) {
	kp := mustKeyPair(t)
	kpMissed := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)

	vote := block.VoteData{MissedNode: nodeID(kpMissed), VoterID: nodeID(kp)}
	b, err := block.NewVoteBlock(genesis, nodeID(kp), vote, kp.Private)
	require.NoError(t, err)

	assert.Equal(t, block.BlockTypeVote, b.Type)
	assert.NoError(t, b.Valid(genesis))
	assert.NoError(t, b.VerifySignatures(keyMap(kp)))
}

// finalizing block

func TestNewFinalizingBlock(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)

	b, err := block.NewFinalizingBlock(genesis, nodeID(kp), kp.Private)
	require.NoError(t, err)

	assert.Equal(t, block.BlockTypeFinalizing, b.Type)
	assert.NoError(t, b.Valid(genesis))
	assert.NoError(t, b.VerifySignatures(keyMap(kp)))
}

// structural validation edge cases

func TestValidFailsWrongIndex(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(genesis, nodeID(kp), move, kp.Private)

	// pass a different block as prev — index will be wrong
	b2, _ := block.NewGameMoveBlock(genesis, nodeID(kp), move, kp.Private)
	assert.Error(t, b.Valid(b2))
}

func TestValidFailsTamperedHash(t *testing.T) {
	kp := mustKeyPair(t)
	b, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	b.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	assert.Error(t, b.Valid(nil))
}

func TestValidFailsWrongPrevHash(t *testing.T) {
	kp := mustKeyPair(t)
	genesis, _ := block.NewGenesisBlock(nodeID(kp), kp.Private)
	move := block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: nodeID(kp)}
	b, _ := block.NewGameMoveBlock(genesis, nodeID(kp), move, kp.Private)
	b.PrevHash = "badhash"
	assert.Error(t, b.Valid(genesis))
}
