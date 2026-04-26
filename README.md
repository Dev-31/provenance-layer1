# provenance-layer1

A Go CLI that attaches a **cryptographically signed provenance manifest** to every AI-submitted pull request. The manifest records who the AI agent was, what LLM provider it used, whether tests passed, and the exact git state — then seals the whole thing with an ECDSA-P256 signature so any tampering is immediately detectable.

This is **Layer 1** of a broader AI contribution trust system: tamper-evident attestation at the source, before any CI or code-review gate.

---

## How it works

```
keygen → sign (run tests, capture git state, embed all metadata) → verify
```

1. **`keygen`** — generate an ECDSA P-256 key pair, stored at `~/.provenance/`
2. **`sign`** — run your test suite, capture git head + working directory, build a canonical JSON manifest, sign it, write `provenance.json`
3. **`verify`** — re-canonicalise the manifest, re-verify the signature; any field mutation → `STATUS: TAMPERED`

The signing contract: `Payload()` serialises the manifest with `Signature: null`, signs those bytes, then embeds the signature. Verification reverses this exactly.

---

## Installation

```bash
go install github.com/Dev-31/provenance-layer1/cmd/provenance-sign@latest
```

Requires Go 1.21+.

---

## Quick start

```bash
# 1. Generate your key pair (once, stored in ~/.provenance/)
provenance-sign keygen

# 2. Sign a manifest (runs tests, captures git state)
provenance-sign sign \
  --agent-id "my-agent" \
  --provider "gemini-flash-2.0" \
  --test-command "go test ./..." \
  --output provenance.json

# 3. Verify
provenance-sign verify --manifest provenance.json
```

On success:
```
STATUS: APPROVED
  agent:   my-agent v1.1.0 (gemini-flash-2.0)
  signed:  2026-04-26T14:00:00Z
  key id:  sha256:ab12cd34...
  tests:   PASS (exit 0, 312ms)
```

Tamper with any field in `provenance.json`, then re-verify:
```
STATUS: TAMPERED — signature verification failed
```

---

## Full command reference

### `sign`

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-id` | `unknown` | Agent identifier (e.g. `openclaw-executor`) |
| `--agent-version` | `1.1.0` | Agent version string |
| `--provider` | `unknown` | LLM provider (e.g. `gemini-flash-2.0`) |
| `--human-in-loop` | `false` | Set `true` if a human reviewed before submission |
| `--prompt` | — | Prompt text — SHA-256 hashed, never stored verbatim |
| `--test-command` | — | Shell command to run (e.g. `go test ./...`) |
| `--force` | `false` | Sign even when tests fail (exit code is still recorded) |
| `--pr-repo` | — | GitHub repo slug (`owner/repo`) |
| `--pr-number` | — | Pull request number |
| `--pr-head-sha` | — | PR head commit SHA |
| `--key` | `~/.provenance/signing.key` | ECDSA private key path |
| `--output` | `provenance.json` | Output path for the signed manifest |

### `verify`

| Flag | Default | Description |
|------|---------|-------------|
| `--manifest` | `provenance.json` | Path to provenance manifest |
| `--pubkey` | `~/.provenance/signing.pub` | Public key PEM path |

### `keygen`

| Flag | Default | Description |
|------|---------|-------------|
| `--key` | `~/.provenance/signing.key` | Output path for private key |

### `pubkey`

Prints the public key PEM for a given private key (useful for sharing with verifiers):

```bash
provenance-sign pubkey > my-agent.pub
```

---

## Manifest format

```json
{
  "schema_version": "1.0",
  "agent": {
    "id": "openclaw-executor",
    "version": "1.1.0",
    "provider": "gemini-flash-2.0"
  },
  "invocation": {
    "timestamp_utc": "2026-04-26T14:00:00Z",
    "human_in_loop": false,
    "prompt_hash": "sha256:abc123...",
    "working_directory": "/home/user/project",
    "git_info": {
      "commit_hash": "abc123def456",
      "branch": "main",
      "is_dirty": false
    }
  },
  "verification": {
    "tests_run": true,
    "test_exit_code": 0,
    "test_command": "go test ./...",
    "stdout_hash": "sha256:def456...",
    "duration_ms": 312
  },
  "pr": {
    "repo": "owner/repo",
    "number": 42,
    "head_sha": "abc123def456"
  },
  "signature": {
    "alg": "ES256",
    "kid": "sha256:ab12cd34...",
    "sig": "base64url-encoded-signature"
  }
}
```

---

## Use with GitHub Actions

Drop `provenance.json` as a PR artifact so reviewers (or an automated gate) can verify it:

```yaml
# .github/workflows/provenance.yml
name: Provenance

on: [pull_request]

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22" }

      - name: Install provenance-sign
        run: go install github.com/Dev-31/provenance-layer1/cmd/provenance-sign@latest

      - name: Generate ephemeral key
        run: provenance-sign keygen

      - name: Sign
        run: |
          provenance-sign sign \
            --agent-id "${{ github.actor }}" \
            --test-command "go test ./..." \
            --pr-repo "${{ github.repository }}" \
            --pr-number "${{ github.event.pull_request.number }}" \
            --pr-head-sha "${{ github.event.pull_request.head.sha }}"

      - name: Verify
        run: provenance-sign verify

      - uses: actions/upload-artifact@v4
        with:
          name: provenance
          path: provenance.json
```

---

## Testing

```bash
go test ./...
```

11 tests cover: key generation, persistence, round-trip sign/verify, payload canonicalisation, tamper detection on every mutable field, and the full CLI keygen→sign→verify flow.

---

## Roadmap

- **Layer 2** — GitHub Actions gate: reject PRs whose `provenance.json` is missing, expired, or TAMPERED
- **Layer 3** — Transparency log: append-only ledger of all signed manifests (Rekor-compatible)
- **Layer 4** — Identity binding: tie the signing key to an OAuth identity so `kid` maps to a real agent account

---

## License

MIT
