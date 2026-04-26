package json

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalizeJSONEmpty(t *testing.T) {
	b, err := CanonicalizeJSON(map[string]interface{}{})
	require.NoError(t, err)
	require.Equal(t, "{}", string(b))
}

func TestCanonicalizeJSONKeyOrder(t *testing.T) {
	data := map[string]interface{}{"z": 3, "a": 1, "m": 2}
	b, err := CanonicalizeJSON(data)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))

	aPos := indexOfKey(string(b), "a")
	mPos := indexOfKey(string(b), "m")
	zPos := indexOfKey(string(b), "z")
	require.Less(t, aPos, mPos, "a must precede m")
	require.Less(t, mPos, zPos, "m must precede z")
}

func TestCanonicalizeJSONHTMLNotEscaped(t *testing.T) {
	data := map[string]interface{}{"url": "https://example.com/a?b=1&c=2"}
	b, err := CanonicalizeJSON(data)
	require.NoError(t, err)
	require.Contains(t, string(b), "&", "HTML entities must not be escaped")
}

func TestCanonicalizeJSONDeterministic(t *testing.T) {
	data := map[string]interface{}{"b": 2, "a": 1}
	b1, err := CanonicalizeJSON(data)
	require.NoError(t, err)
	b2, err := CanonicalizeJSON(data)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestCanonicalizeJSONNoTrailingNewline(t *testing.T) {
	b, err := CanonicalizeJSON(map[string]interface{}{"k": "v"})
	require.NoError(t, err)
	require.False(t, len(b) > 0 && b[len(b)-1] == '\n', "must not end with newline")
}

func indexOfKey(s, key string) int {
	target := `"` + key + `"`
	for i := 0; i <= len(s)-len(target); i++ {
		if s[i:i+len(target)] == target {
			return i
		}
	}
	return -1
}
