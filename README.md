# provenance-sign

A Go CLI tool for creating cryptographically signed provenance attestations with ECDSA-ES256 signatures and RFC 8785 canonical JSON formatting.

## Features

- ECDSA ES256 signatures (RFC 7518)
- RFC 8785 canonical JSON serialization
- Git commit hash capture and working directory state
- Configurable input/output
- Test runner integration ready

## Installation

```bash
go install github.com/dev-sopariwala/provenance-layer1/cmd/provenance-sign@latest
```

## Usage

Generate a provenance signature:
```bash
provenance-sign
```

Sign a file:
```bash
provenance-sign -input data.json -output provenance.json
```

Sign JSON data directly:
```bash
provenance-sign -data '{"build_id": "123", "version": "1.0.0"}'
```

## Output Format

```json
{
  "timestamp": "2024-04-21T10:30:00Z",
  "git_info": {
    "commit_hash": "abc123def456",
    "branch": "main",
    "is_dirty": false
  },
  "working_directory": "/home/user/project",
  "data": {...},
  "signature": {
    "signature": "base64-encoded-signature",
    "alg": "ES256",
    "kid": "provenance-layer1"
  }
}
```

## Testing

```bash
go test ./...
```