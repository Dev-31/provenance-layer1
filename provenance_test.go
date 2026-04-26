package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	canjson "github.com/dev-sopariwala/provenance-layer1/internal/json"
	"github.com/dev-sopariwala/provenance-layer1/internal/manifest"
	"github.com/dev-sopariwala/provenance-layer1/internal/signing"
	"github.com/stretchr/testify/require"
)

// TestSignerRoundtrip verifies that Sign → Verify succeeds with the same key.
func TestSignerRoundtrip(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)

	data := []byte("hello provenance")
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	require.Equal(t, "ES256", sig.Alg)
	require.NotEmpty(t, sig.Kid)
	require.NotEmpty(t, sig.Value)

	require.NoError(t, signer.Verify(data, sig))
}

// TestVerifyTamperedData confirms that changing the payload breaks verification.
func TestVerifyTamperedData(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)

	sig, err := signer.Sign([]byte("original"))
	require.NoError(t, err)

	err = signer.Verify([]byte("tampered"), sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TAMPERED")
}

// TestKeyPersistence checks that a key written to disk can be loaded and used
// to verify signatures produced before the reload.
func TestKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")

	signer1, err := signing.NewSignerFromFile(keyPath)
	require.NoError(t, err)

	data := []byte("persistent signing")
	sig, err := signer1.Sign(data)
	require.NoError(t, err)

	// Load the same key from disk.
	signer2, err := signing.NewSignerFromFile(keyPath)
	require.NoError(t, err)

	// Key IDs must match.
	require.Equal(t, signer1.KID(), signer2.KID())

	// Signature produced by signer1 must verify under signer2.
	require.NoError(t, signer2.Verify(data, sig))
}

// TestKeyIDStability ensures the derived key ID is deterministic across loads.
func TestKeyIDStability(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")

	s1, err := signing.NewSignerFromFile(keyPath)
	require.NoError(t, err)

	s2, err := signing.NewSignerFromFile(keyPath)
	require.NoError(t, err)

	require.Equal(t, s1.KID(), s2.KID())
}

// TestManifestPayloadExcludesSignature verifies that Payload() produces the
// same bytes before and after the Signature field is filled in.
func TestManifestPayloadExcludesSignature(t *testing.T) {
	m := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Agent: manifest.AgentInfo{
			ID:       "test-agent",
			Version:  "1.0.0",
			Provider: "test-provider",
		},
		Invocation: manifest.InvocationInfo{
			TimestampUTC: "2026-04-26T12:00:00Z",
			HumanInLoop:  false,
			WorkingDir:   "/tmp/test",
		},
		Verification: manifest.VerificationInfo{TestsRun: false},
	}

	payload1, err := m.Payload()
	require.NoError(t, err)

	// Attach a fake signature.
	m.Signature = &signing.Signature{Alg: "ES256", Kid: "test", Value: "abc123"}

	payload2, err := m.Payload()
	require.NoError(t, err)

	// Payload must be identical — signature field is excluded from both.
	require.Equal(t, payload1, payload2)
}

// TestManifestSignAndVerify exercises the full sign → verify roundtrip at the
// manifest level, including the canonical JSON contract.
func TestManifestSignAndVerify(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)

	m := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Agent: manifest.AgentInfo{ID: "agent", Version: "1.0", Provider: "gemini"},
		Invocation: manifest.InvocationInfo{
			TimestampUTC: manifest.Now(),
			HumanInLoop:  true,
			WorkingDir:   "/workspace",
		},
		Verification: manifest.VerificationInfo{
			TestsRun:     true,
			TestExitCode: 0,
			TestCommand:  "go test ./...",
			DurationMs:   421,
		},
	}

	payload, err := m.Payload()
	require.NoError(t, err)

	sig, err := signer.Sign(payload)
	require.NoError(t, err)
	m.Signature = sig

	// Re-derive payload after signature is embedded and verify.
	payload2, err := m.Payload()
	require.NoError(t, err)
	require.NoError(t, signer.Verify(payload2, sig))
}

// TestManifestTamperDetection confirms that modifying any field after signing
// causes verification to fail.
func TestManifestTamperDetection(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)

	m := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Agent:         manifest.AgentInfo{ID: "agent", Version: "1.0", Provider: "gemini"},
		Invocation:    manifest.InvocationInfo{TimestampUTC: manifest.Now(), WorkingDir: "/w"},
		Verification:  manifest.VerificationInfo{TestsRun: true, TestExitCode: 0},
	}

	payload, err := m.Payload()
	require.NoError(t, err)
	sig, err := signer.Sign(payload)
	require.NoError(t, err)
	m.Signature = sig

	// Tamper: change exit code from 0 to 1 (the "tests passed" fabrication attack).
	m.Verification.TestExitCode = 1

	tamperedPayload, err := m.Payload()
	require.NoError(t, err)
	err = signer.Verify(tamperedPayload, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TAMPERED")
}

// TestCanonicalJSONDeterminism confirms same input always yields same bytes.
func TestCanonicalJSONDeterminism(t *testing.T) {
	data := map[string]interface{}{
		"z": 1,
		"a": "hello",
		"m": map[string]interface{}{"b": 2, "a": 1},
	}

	b1, err := canjson.CanonicalizeJSON(data)
	require.NoError(t, err)
	b2, err := canjson.CanonicalizeJSON(data)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

// TestCanonicalJSONKeyOrder verifies that object keys are sorted alphabetically.
func TestCanonicalJSONKeyOrder(t *testing.T) {
	data := map[string]interface{}{
		"z": 1, "a": 2, "m": 3,
	}
	b, err := canjson.CanonicalizeJSON(data)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &parsed))

	// Marshal with Go's stdlib (sorts keys) and compare raw bytes.
	expected, err := canjson.CanonicalizeJSON(parsed)
	require.NoError(t, err)
	require.Equal(t, string(expected), string(b))

	// Spot-check: "a" must appear before "m" which must appear before "z".
	aIdx := indexOf(string(b), `"a"`)
	mIdx := indexOf(string(b), `"m"`)
	zIdx := indexOf(string(b), `"z"`)
	require.Less(t, aIdx, mIdx)
	require.Less(t, mIdx, zIdx)
}

// TestPublicKeyPersistence verifies SavePublicKey → LoadPublicKey roundtrip.
func TestPublicKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	key, err := signing.GenerateAndSave(keyPath)
	require.NoError(t, err)

	require.NoError(t, signing.SavePublicKey(&key.PublicKey, pubPath))

	pub, err := signing.LoadPublicKey(pubPath)
	require.NoError(t, err)

	// Key IDs derived from original and loaded public keys must match.
	kid1, err := signing.KeyID(&key.PublicKey)
	require.NoError(t, err)
	kid2, err := signing.KeyID(pub)
	require.NoError(t, err)
	require.Equal(t, kid1, kid2)
}

// TestHashText verifies the "sha256:" prefix format.
func TestHashText(t *testing.T) {
	h := manifest.HashText("hello")
	require.True(t, len(h) > 7)
	require.Equal(t, "sha256:", h[:7])
}

// TestWrongKeyCannotVerify ensures a different key cannot forge a valid signature.
func TestWrongKeyCannotVerify(t *testing.T) {
	signer1, _ := signing.NewSigner()
	signer2, _ := signing.NewSigner()

	data := []byte("important data")
	sig, err := signer1.Sign(data)
	require.NoError(t, err)

	// signer2's public key must reject signer1's signature.
	err = signing.Verify(data, sig, signer2.PublicKey())
	require.Error(t, err)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Ensure the test file compiles even though there is no main() here.
// (This is a package main test file; the test runner provides its own main.)
var _ = os.DevNull
