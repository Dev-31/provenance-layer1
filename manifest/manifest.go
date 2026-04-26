// Package manifest re-exports the Layer 1 manifest types for use by external modules.
// Internal callers within layer1 should continue to import internal/manifest directly.
package manifest

import (
	internal "github.com/Dev-31/provenance-layer1/internal/manifest"
	isigning "github.com/Dev-31/provenance-layer1/internal/signing"
)

// Re-export the schema version constant.
const SchemaVersion = internal.SchemaVersion

// Re-export types by aliasing to the internal types.
type Manifest = internal.Manifest
type PRInfo = internal.PRInfo
type AgentInfo = internal.AgentInfo
type InvocationInfo = internal.InvocationInfo
type VerificationInfo = internal.VerificationInfo

// Signature is re-exported from the signing package so callers only need to import manifest.
type Signature = isigning.Signature

// HashText returns "sha256:<hex>" for a string.
func HashText(s string) string { return internal.HashText(s) }

// HashBytes returns "sha256:<hex>" for arbitrary bytes.
func HashBytes(b []byte) string { return internal.HashBytes(b) }

// Now returns the current UTC time formatted as RFC 3339.
func Now() string { return internal.Now() }
