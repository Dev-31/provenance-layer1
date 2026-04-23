package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Signer struct {
	privateKey *ecdsa.PrivateKey
}

type SignatureResult struct {
	Signature string `json:"signature"`
	Algorithm string `json:"alg"`
	Kid       string `json:"kid"`
}

func NewSigner() (*Signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	
	return &Signer{privateKey: privateKey}, nil
}

func NewSignerFromKey(privateKey *ecdsa.PrivateKey) *Signer {
	return &Signer{privateKey: privateKey}
}

func (s *Signer) Sign(data []byte) (*SignatureResult, error) {
	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &SignatureResult{
		Signature: base64.RawURLEncoding.EncodeToString(signature),
		Algorithm: "ES256",
		Kid:       "provenance-layer1",
	}, nil
}

func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return &s.privateKey.PublicKey
}