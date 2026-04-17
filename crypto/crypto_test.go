package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pot-node/crypto"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	assert.Len(t, kp.Public, 32, "Ed25519 public key is 32 bytes")
	assert.Len(t, kp.Private, 64, "Ed25519 private key is 64 bytes")
}

func TestGenerateKeyPairIsRandom(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	assert.NotEqual(t, kp1.Public, kp2.Public, "two key pairs must differ")
}

func TestSignVerify(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	data := []byte("test payload")
	sig := crypto.Sign(kp.Private, data)
	assert.True(t, crypto.Verify(kp.Public, data, sig))
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	sig := crypto.Sign(kp1.Private, []byte("data"))
	assert.False(t, crypto.Verify(kp2.Public, []byte("data"), sig), "wrong key must not verify")
}

func TestVerifyFailsWithTamperedData(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	sig := crypto.Sign(kp.Private, []byte("original"))
	assert.False(t, crypto.Verify(kp.Public, []byte("tampered"), sig), "tampered data must not verify")
}

func TestHashIsDeterministic(t *testing.T) {
	assert.Equal(t, crypto.Hash("hello"), crypto.Hash("hello"))
}

func TestHashOutputFormat(t *testing.T) {
	h := crypto.Hash("hello")
	assert.Len(t, h, 64, "SHA-256 hex string is 64 characters")
}

func TestHashDistinct(t *testing.T) {
	assert.NotEqual(t, crypto.Hash("a"), crypto.Hash("b"))
}

func TestNodeIDIsDeterministic(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	assert.Equal(t, crypto.NodeID(kp.Public), crypto.NodeID(kp.Public))
}

func TestNodeIDLength(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	assert.Len(t, crypto.NodeID(kp.Public), 64)
}

func TestNodeIDDistinctForDifferentKeys(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	assert.NotEqual(t, crypto.NodeID(kp1.Public), crypto.NodeID(kp2.Public))
}
