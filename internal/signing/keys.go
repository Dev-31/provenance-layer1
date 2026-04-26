package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const defaultKeyDir  = ".provenance"
const defaultKeyFile = "signing.key"
const defaultPubFile = "signing.pub"

// DefaultKeyPath returns ~/.provenance/signing.key.
func DefaultKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultKeyDir, defaultKeyFile), nil
}

// DefaultPubKeyPath returns ~/.provenance/signing.pub.
func DefaultPubKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultKeyDir, defaultPubFile), nil
}

// GenerateAndSave generates a new P-256 ECDSA key, writes it to keyPath (mode
// 0600), and returns it. The parent directory is created if absent.
func GenerateAndSave(keyPath string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := SavePrivateKey(key, keyPath); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadOrGenerate loads the private key from keyPath; if the file does not exist
// it generates a new key, saves it, and returns it.
func LoadOrGenerate(keyPath string) (*ecdsa.PrivateKey, error) {
	key, err := LoadPrivateKey(keyPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No key at %s — generating new P-256 key.\n", keyPath)
		return GenerateAndSave(keyPath)
	}
	return key, err
}

// SavePrivateKey writes key to path as a PEM-encoded EC PRIVATE KEY (mode 0600).
func SavePrivateKey(key *ecdsa.PrivateKey, path string) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// LoadPrivateKey reads a PEM-encoded EC private key from path.
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a valid EC PRIVATE KEY PEM block", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}

// SavePublicKey writes key to path as a PEM-encoded PUBLIC KEY (mode 0644).
func SavePublicKey(key *ecdsa.PublicKey, path string) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// LoadPublicKey reads a PEM-encoded EC public key from path.
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: not a valid PUBLIC KEY PEM block", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA public key", path)
	}
	return ecPub, nil
}

// KeyID returns an SSH-style fingerprint: "SHA256:<base64(sha256(PKIX-DER))>".
// This value is embedded in every Signature.Kid field.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:]), nil
}
