package session_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/block"
	"pot-node/crypto"
	"pot-node/session"
)

// ---- helpers ----------------------------------------------------------------

func mustKeyPair(t *testing.T) crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

// mustInfo builds a valid Info with n peers. Peer 0 authors the genesis block.
func mustInfo(t *testing.T, n int) session.Info {
	t.Helper()
	require.Greater(t, n, 0)
	kps := make([]crypto.KeyPair, n)
	peers := make([]session.PeerMeta, n)
	for i := range n {
		kps[i] = mustKeyPair(t)
		peers[i] = session.PeerMeta{
			ID:     crypto.NodeID(kps[i].Public),
			PubKey: kps[i].Public,
		}
	}
	genesis, err := block.NewGenesisBlock(peers[0].ID, kps[0].Private)
	require.NoError(t, err)
	return session.Info{Peers: peers, Genesis: genesis}
}

// ---- Hello ------------------------------------------------------------------

func TestSendHello_ReceiveHello_RoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	kp := mustKeyPair(t)
	h := session.Hello{ID: crypto.NodeID(kp.Public), PubKey: kp.Public, Addr: "127.0.0.1:7001", APIAddr: "127.0.0.1:8081"}

	go func() { session.SendHello(c1, h) }() //nolint:errcheck

	got, err := session.ReceiveHello(c2)
	require.NoError(t, err)
	assert.Equal(t, h.ID, got.ID)
	assert.Equal(t, []byte(h.PubKey), []byte(got.PubKey))
	assert.Equal(t, h.Addr, got.Addr)
	assert.Equal(t, h.APIAddr, got.APIAddr)
}

func TestReceiveHello_InvalidJSON(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		c1.Write([]byte("not json\n")) //nolint:errcheck
		c1.Close()
	}()
	_, err := session.ReceiveHello(c2)
	assert.Error(t, err)
}

// ---- Send / Receive ---------------------------------------------------------

func TestSendReceive_RoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	info := mustInfo(t, 2)
	go func() { session.Send(c1, info) }() //nolint:errcheck

	got, err := session.Receive(c2)
	require.NoError(t, err)
	assert.Equal(t, info.Genesis.Hash, got.Genesis.Hash)
	assert.Len(t, got.Peers, 2)
	assert.Equal(t, info.Peers[0].ID, got.Peers[0].ID)
	assert.Equal(t, info.Peers[1].ID, got.Peers[1].ID)
}

func TestReceive_ClosedConn(t *testing.T) {
	c1, c2 := net.Pipe()
	c1.Close()
	c2.Close()
	_, err := session.Receive(c2)
	assert.Error(t, err)
}

func TestReceive_InvalidJSON(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		c1.Write([]byte("not json\n")) //nolint:errcheck
		c1.Close()
	}()
	_, err := session.Receive(c2)
	assert.Error(t, err)
}

// ---- Validate ---------------------------------------------------------------

func TestValidate_Valid(t *testing.T) {
	assert.NoError(t, mustInfo(t, 3).Validate())
}

func TestValidate_SinglePeer(t *testing.T) {
	// A single-peer session is degenerate but valid — the node leads every turn.
	assert.NoError(t, mustInfo(t, 1).Validate())
}

func TestValidate_EmptyPeers(t *testing.T) {
	info := mustInfo(t, 1)
	info.Peers = nil
	assert.Error(t, info.Validate())
}

func TestValidate_NilGenesis(t *testing.T) {
	info := mustInfo(t, 1)
	info.Genesis = nil
	assert.Error(t, info.Validate())
}

func TestValidate_WrongBlockType(t *testing.T) {
	info := mustInfo(t, 2)
	kp := mustKeyPair(t)
	id := crypto.NodeID(kp.Public)
	move, err := block.NewGameMoveBlock(
		info.Genesis, id,
		block.GameMoveData{MoveType: "attack", From: 1, To: 2, PlayerID: id},
		kp.Private,
	)
	require.NoError(t, err)
	info.Genesis = move
	assert.Error(t, info.Validate())
}

func TestValidate_IDMismatch(t *testing.T) {
	info := mustInfo(t, 2)
	// Swap IDs — each peer's ID no longer matches their public key.
	info.Peers[0].ID, info.Peers[1].ID = info.Peers[1].ID, info.Peers[0].ID
	assert.Error(t, info.Validate())
}

func TestValidate_TamperedGenesisHash(t *testing.T) {
	info := mustInfo(t, 1)
	info.Genesis.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	assert.Error(t, info.Validate())
}

func TestValidate_GenesisSignedByStranger(t *testing.T) {
	// Genesis signed by a key not present in the peer list must be rejected.
	info := mustInfo(t, 2)
	stranger := mustKeyPair(t)
	bad, err := block.NewGenesisBlock("stranger", stranger.Private)
	require.NoError(t, err)
	info.Genesis = bad
	assert.Error(t, info.Validate())
}

func TestValidate_PubKeyPreservedThroughJSON(t *testing.T) {
	// ed25519.PublicKey survives JSON (base64) round-trip and Validate still passes.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	original := mustInfo(t, 2)
	go func() { session.Send(c1, original) }() //nolint:errcheck

	received, err := session.Receive(c2)
	require.NoError(t, err)
	assert.NoError(t, received.Validate())
}
