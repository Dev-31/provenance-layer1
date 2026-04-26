package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Signature is the ECDSA-ES256 attestation attached to a manifest.
type Signature struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Value string `json:"value"`
}

// Signer holds an ECDSA private key and signs manifest payloads.
type Signer struct {
	privateKey *ecdsa.PrivateKey
	kid        string
}

// NewSigner creates an in-memory ephemeral signer. Suitable for tests.
// For persistent signing use NewSignerFromFile.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive kid: %w", err)
	}
	return &Signer{privateKey: key, kid: kid}, nil
}

// NewSignerFromKey wraps an existing key with an explicit key ID.
func NewSignerFromKey(key *ecdsa.PrivateKey, kid string) *Signer {
	return &Signer{privateKey: key, kid: kid}
}

// NewSignerFromFile loads (or generates) a persistent ECDSA key from keyPath.
// The key ID is derived from the public key fingerprint.
func NewSignerFromFile(keyPath string) (*Signer, error) {
	key, err := LoadOrGenerate(keyPath)
	if err != nil {
		return nil, err
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive kid: %w", err)
	}
	return &Signer{privateKey: key, kid: kid}, nil
}

// Sign computes an ES256 signature over data (which must be the manifest payload —
// canonical JSON with the signature field absent).
func (s *Signer) Sign(data []byte) (*Signature, error) {
	hash := sha256.Sum256(data)
	raw, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	return &Signature{
		Alg:   "ES256",
		Kid:   s.kid,
		Value: base64.RawURLEncoding.EncodeToString(raw),
	}, nil
}

// PublicKey returns the public half of the signing key.
func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return &s.privateKey.PublicKey
}

// KID returns the key identifier embedded in signatures.
func (s *Signer) KID() string { return s.kid }

// Verify checks sig against this signer's public key.
func (s *Signer) Verify(data []byte, sig *Signature) error {
	return Verify(data, sig, s.PublicKey())
}

// Verify checks an ES256 Signature against a public key.
// data must be the same canonical payload that was signed.
func Verify(data []byte, sig *Signature, pub *ecdsa.PublicKey) error {
	if sig.Alg != "ES256" {
		return fmt.Errorf("unsupported algorithm %q (want ES256)", sig.Alg)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, hash[:], raw) {
		return fmt.Errorf("signature mismatch: manifest is TAMPERED")
	}
	return nil
}
