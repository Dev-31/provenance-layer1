package json

import (
	"bytes"
	"encoding/json"
	"sort"
)

// CanonicalizeJSON implements RFC 8785 canonical JSON formatting
func CanonicalizeJSON(data interface{}) ([]byte, error) {
	// Marshal to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Parse back to interface{} for canonicalization
	var obj interface{}
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return nil, err
	}

	// Canonically format
	return canonicalizeInterface(obj)
}

func canonicalizeInterface(obj interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "")
	
	if err := encoder.Encode(obj); err != nil {
		return nil, err
	}

	// Remove trailing newline
	result := bytes.TrimSpace(buf.Bytes())
	return result, nil
}

// CanonicalizeMap recursively canonicalizes a map[string]interface{}
func CanonicalizeMap(data map[string]interface{}) ([]byte, error) {
	return CanonicalizeJSON(data)
}