// Package signing re-exports the Layer 1 signing types and functions for use by external modules.
// Internal callers within layer1 should continue to import internal/signing directly.
package signing

import (
	"crypto/ecdsa"

	internal "github.com/Dev-31/provenance-layer1/internal/signing"
)

// Re-export types by aliasing.
type Signature = internal.Signature
type Signer = internal.Signer

// NewSigner creates an in-memory ephemeral signer.
func NewSigner() (*Signer, error) { return internal.NewSigner() }

// NewSignerFromKey wraps an existing key with an explicit key ID.
func NewSignerFromKey(key *ecdsa.PrivateKey, kid string) *Signer {
	return internal.NewSignerFromKey(key, kid)
}

// NewSignerFromFile loads (or generates) a persistent ECDSA key from keyPath.
func NewSignerFromFile(keyPath string) (*Signer, error) { return internal.NewSignerFromFile(keyPath) }

// Verify checks an ES256 Signature against a public key.
func Verify(data []byte, sig *Signature, pub *ecdsa.PublicKey) error {
	return internal.Verify(data, sig, pub)
}

// KeyID returns an SSH-style fingerprint for a public key.
func KeyID(pub *ecdsa.PublicKey) (string, error) { return internal.KeyID(pub) }

// LoadOrGenerate loads the private key from keyPath; if absent, generates and saves.
func LoadOrGenerate(keyPath string) (*ecdsa.PrivateKey, error) {
	return internal.LoadOrGenerate(keyPath)
}

// LoadPublicKey reads a PEM-encoded EC public key from path.
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) { return internal.LoadPublicKey(path) }

// SavePublicKey writes key to path as a PEM-encoded PUBLIC KEY.
func SavePublicKey(key *ecdsa.PublicKey, path string) error {
	return internal.SavePublicKey(key, path)
}

// GenerateAndSave generates a new P-256 ECDSA key, writes it to keyPath, and returns it.
func GenerateAndSave(keyPath string) (*ecdsa.PrivateKey, error) {
	return internal.GenerateAndSave(keyPath)
}
