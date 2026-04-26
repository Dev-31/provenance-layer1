// Package manifest defines the Layer 1 provenance attestation format.
//
// A Manifest is the tamper-evident record attached to every AI-submitted PR.
// The signing contract is: sign Payload() (canonical JSON with Signature==nil),
// then embed the resulting Signature in the manifest before writing to disk.
// Verification reverses this: clear Signature, call Payload(), re-verify.
package manifest

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/Dev-31/provenance-layer1/internal/git"
	canjson "github.com/Dev-31/provenance-layer1/internal/json"
	"github.com/Dev-31/provenance-layer1/internal/signing"
)

const SchemaVersion = "1.0"

// Manifest is the root attestation object written to provenance.json.
type Manifest struct {
	SchemaVersion string           `json:"schema_version"`
	PR            *PRInfo          `json:"pr,omitempty"`
	Agent         AgentInfo        `json:"agent"`
	Invocation    InvocationInfo   `json:"invocation"`
	Verification  VerificationInfo `json:"verification"`
	Signature     *signing.Signature `json:"signature,omitempty"`
}

// PRInfo identifies the pull request being attested.
type PRInfo struct {
	Repo    string `json:"repo"`
	Number  int    `json:"number,omitempty"`
	HeadSHA string `json:"head_sha,omitempty"`
}

// AgentInfo identifies the AI agent that authored the contribution.
type AgentInfo struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Provider string `json:"provider"`
}

// InvocationInfo records the context in which the agent was invoked.
type InvocationInfo struct {
	TimestampUTC string       `json:"timestamp_utc"`
	HumanInLoop  bool         `json:"human_in_loop"`
	PromptHash   string       `json:"prompt_hash,omitempty"`
	WorkingDir   string       `json:"working_directory"`
	GitInfo      *git.GitInfo `json:"git_info,omitempty"`
}

// VerificationInfo records what tests were run and their outcome.
// When TestsRun is false all other fields are meaningless and should be ignored.
type VerificationInfo struct {
	TestsRun     bool    `json:"tests_run"`
	TestExitCode int     `json:"test_exit_code"`
	TestCommand  string  `json:"test_command,omitempty"`
	StdoutHash   string  `json:"stdout_hash,omitempty"`
	DurationMs   int64   `json:"duration_ms,omitempty"`
	CoveragePct  float64 `json:"coverage_pct,omitempty"`
}

// Payload returns the canonical JSON bytes that must be signed.
// It serialises the manifest with Signature set to nil so that the signature
// field is excluded — identical to what was signed before Signature was filled in.
func (m *Manifest) Payload() ([]byte, error) {
	unsigned := *m
	unsigned.Signature = nil
	return canjson.CanonicalizeJSON(unsigned)
}

// HashText returns "sha256:<hex>" for a string (used for prompt hashing).
func HashText(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x", h)
}

// HashBytes returns "sha256:<hex>" for arbitrary bytes (used for stdout hashing).
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", h)
}

// Now returns the current UTC time formatted as RFC 3339.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
