// Package crypto provides the cryptographic primitives used by the PoT block layer:
// Ed25519 key generation, signing, and verification, plus SHA-256 hashing.
//
// All block signatures in the PoT protocol use Ed25519. The block layer always signs
// the hex-decoded hash bytes of a block — never raw message content — so that the
// signature commits to the fully assembled, canonical block rather than to any single field.
//
// Transition (handover) blocks carry two independent signatures over the same hash bytes:
// one from the outgoing Leading Node and one from the incoming Leading Node.
// This two-party commitment is the cryptographic proof of a legitimate turn handover,
// as specified in the PoT thesis: https://arxiv.org/pdf/2304.07384v1
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeyPair holds an Ed25519 public/private key pair for a PoT node.
// The Public key is shared with peers; the Private key never leaves the node.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeyPair creates a new random Ed25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate key pair: %w", err)
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// Sign returns the Ed25519 signature of data using key.
// In the block layer, data is always the hex-decoded hash bytes of the block
// being signed — see block.applySignature for the call site.
func Sign(key ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(key, data)
}

// Verify reports whether sig is a valid Ed25519 signature of data by key.
// In the block layer, data is the hex-decoded hash bytes of the block,
// matching exactly what was passed to Sign.
func Verify(key ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(key, data, sig)
}

// Hash returns the hex-encoded SHA-256 digest of s.
// Used for block hash computation and node ID derivation.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NodeID derives a stable string identifier from a public key.
// It is the hex-encoded SHA-256 of the raw public key bytes.
// A hash is used rather than the raw key because it produces a fixed-length,
// printable string suitable for use as a map key and in JSON block payloads.
func NodeID(pub ed25519.PublicKey) string {
	return Hash(string(pub))
}
