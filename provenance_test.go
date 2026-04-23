package main

import (
	"encoding/json"
	"testing"

	"github.com/dev-sopariwala/provenance-layer1/internal/signing"
	canjson "github.com/dev-sopariwala/provenance-layer1/internal/json"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)
	require.NotNil(t, signer)

	testData := []byte("Hello, provenance!")
	signature, err := signer.Sign(testData)
	require.NoError(t, err)
	require.NotEmpty(t, signature.Signature)
	require.Equal(t, "ES256", signature.Algorithm)
	require.Equal(t, "provenance-layer1", signature.Kid)
}

func TestJSONCanonicalization(t *testing.T) {
	data := map[string]interface{}{
		"name":  "John Doe",
		"age":   30,
		"admin": true,
		"roles": []string{"admin", "user"},
	}

	canonicalJSON, err := canjson.CanonicalizeJSON(data)
	require.NoError(t, err)
	require.NotEmpty(t, canonicalJSON)

	// Ensure consistent formatting
	var parsed map[string]interface{}
	err = json.Unmarshal(canonicalJSON, &parsed)
	require.NoError(t, err)

	require.Equal(t, "John Doe", parsed["name"])
	require.Equal(t, 30.0, parsed["age"]) // JSON floats
	require.Equal(t, true, parsed["admin"])
}