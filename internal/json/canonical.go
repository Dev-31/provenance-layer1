package json

import (
	"bytes"
	"encoding/json"
)

// CanonicalizeJSON returns a deterministic, compact JSON encoding of data.
//
// The approach: marshal → unmarshal to interface{} → re-marshal.
// The round-trip converts structs to map[string]interface{}, and Go's
// json.Marshal sorts map keys alphabetically — satisfying RFC 8785's
// key-ordering requirement for all nested objects.
func CanonicalizeJSON(data interface{}) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}

	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
