package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Dev-31/provenance-layer1/internal/git"
	"github.com/Dev-31/provenance-layer1/internal/manifest"
	"github.com/Dev-31/provenance-layer1/internal/signing"
)

const Version = "1.1.0"

func main() {
	if len(os.Args) == 1 {
		printUsage()
		os.Exit(0)
	}
	// Backward compat: bare flags (no subcommand word) → sign.
	if strings.HasPrefix(os.Args[1], "-") {
		runSign(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "keygen":
		runKeygen(os.Args[2:])
	case "pubkey":
		runPubkey(os.Args[2:])
	case "version":
		fmt.Printf("provenance-sign %s\n", Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// runSign builds and cryptographically signs a provenance manifest (FR-10–FR-14).
func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)

	// Agent identity
	agentID      := fs.String("agent-id",      "unknown", "Agent identifier (e.g. openclaw-executor)")
	agentVersion := fs.String("agent-version",  Version,  "Agent version string")
	provider     := fs.String("provider",       "unknown", "LLM provider (e.g. gemini-flash-2.0)")

	// Invocation context
	humanInLoop := fs.Bool("human-in-loop", false, "Human reviewed the output before submission")
	prompt      := fs.String("prompt",      "",    "Prompt text — hashed, never stored verbatim")

	// Test execution (FR-12, FR-13)
	testCmd := fs.String("test-command", "", "Shell command to run tests (e.g. 'go test ./...')")
	force   := fs.Bool("force",          false, "Sign even when tests fail (exit code recorded)")

	// PR metadata
	prRepo    := fs.String("pr-repo",     "", "GitHub repo slug (owner/repo)")
	prNumber  := fs.Int("pr-number",      0,  "Pull request number")
	prHeadSHA := fs.String("pr-head-sha", "", "PR head commit SHA")

	// Key & output
	keyPath := fs.String("key",    "", "ECDSA private key path (default: ~/.provenance/signing.key)")
	output  := fs.String("output", "provenance.json", "Output path for the signed manifest")

	fs.Parse(args)

	signer, err := signing.NewSignerFromFile(resolveKeyPath(*keyPath))
	dieIf(err, "load signing key")

	// Run test command if provided.
	verif := manifest.VerificationInfo{TestsRun: false}
	if *testCmd != "" {
		fmt.Fprintf(os.Stderr, "▶ running: %s\n", *testCmd)
		exitCode, stdoutHash, durationMs, runErr := runCommand(*testCmd)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "warning: test command error: %v\n", runErr)
		}
		verif = manifest.VerificationInfo{
			TestsRun:     true,
			TestExitCode: exitCode,
			TestCommand:  *testCmd,
			StdoutHash:   stdoutHash,
			DurationMs:   durationMs,
		}
		if exitCode != 0 {
			if !*force {
				die("tests failed (exit %d) — use --force to sign anyway", exitCode)
			}
			fmt.Fprintf(os.Stderr, "warning: signing with failing tests (--force)\n")
		} else {
			fmt.Fprintf(os.Stderr, "✓ tests passed\n")
		}
	}

	gitInfo, _ := git.GetGitHead()
	workDir, _ := git.GetWorkingDirectory()

	m := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Agent: manifest.AgentInfo{
			ID:       *agentID,
			Version:  *agentVersion,
			Provider: *provider,
		},
		Invocation: manifest.InvocationInfo{
			TimestampUTC: manifest.Now(),
			HumanInLoop:  *humanInLoop,
			WorkingDir:   workDir,
			GitInfo:      gitInfo,
		},
		Verification: verif,
	}
	if *prompt != "" {
		m.Invocation.PromptHash = manifest.HashText(*prompt)
	}
	if *prRepo != "" {
		m.PR = &manifest.PRInfo{
			Repo:    *prRepo,
			Number:  *prNumber,
			HeadSHA: *prHeadSHA,
		}
	}

	// Payload = canonical JSON with Signature absent. Sign it, then embed.
	payload, err := m.Payload()
	dieIf(err, "canonicalize manifest")

	sig, err := signer.Sign(payload)
	dieIf(err, "sign manifest")
	m.Signature = sig

	out, err := json.MarshalIndent(m, "", "  ")
	dieIf(err, "marshal manifest")
	dieIf(os.WriteFile(*output, out, 0644), "write manifest")

	fmt.Printf("✓ manifest written to %s\n", *output)
	fmt.Printf("  key id: %s\n", sig.Kid)
}

// runVerify verifies a local provenance.json against a public key (FR-20–FR-23).
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "provenance.json", "Path to provenance manifest")
	pubkeyPath   := fs.String("pubkey",   "",                "Public key PEM path (default: ~/.provenance/signing.pub)")
	fs.Parse(args)

	data, err := os.ReadFile(*manifestPath)
	dieIf(err, "read manifest")

	var m manifest.Manifest
	dieIf(json.Unmarshal(data, &m), "parse manifest")

	if m.Signature == nil {
		fmt.Println("STATUS: UNVERIFIED — manifest has no signature")
		os.Exit(2)
	}

	kp := *pubkeyPath
	if kp == "" {
		kp, err = signing.DefaultPubKeyPath()
		dieIf(err, "resolve pubkey path")
	}
	pub, err := signing.LoadPublicKey(kp)
	dieIf(err, "load public key")

	payload, err := m.Payload()
	dieIf(err, "canonicalize manifest")

	if err := signing.Verify(payload, m.Signature, pub); err != nil {
		fmt.Printf("STATUS: TAMPERED — %v\n", err)
		os.Exit(2)
	}

	fmt.Println("STATUS: APPROVED")
	fmt.Printf("  agent:   %s v%s (%s)\n", m.Agent.ID, m.Agent.Version, m.Agent.Provider)
	fmt.Printf("  signed:  %s\n", m.Invocation.TimestampUTC)
	fmt.Printf("  key id:  %s\n", m.Signature.Kid)
	if m.Verification.TestsRun {
		result := "PASS"
		if m.Verification.TestExitCode != 0 {
			result = "FAIL"
		}
		fmt.Printf("  tests:   %s (exit %d, %dms)\n",
			result, m.Verification.TestExitCode, m.Verification.DurationMs)
	} else {
		fmt.Println("  tests:   not run")
	}
	if m.PR != nil {
		fmt.Printf("  pr:      %s#%d @ %s\n", m.PR.Repo, m.PR.Number, m.PR.HeadSHA)
	}
}

// runKeygen generates a new ECDSA P-256 key pair.
func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", "", "Output path for private key (default: ~/.provenance/signing.key)")
	fs.Parse(args)

	kp := resolveKeyPath(*keyPath)
	key, err := signing.GenerateAndSave(kp)
	dieIf(err, "generate key")

	pubPath := strings.TrimSuffix(kp, ".key") + ".pub"
	dieIf(signing.SavePublicKey(&key.PublicKey, pubPath), "save public key")

	kid, err := signing.KeyID(&key.PublicKey)
	dieIf(err, "derive key id")

	fmt.Printf("private key: %s\n", kp)
	fmt.Printf("public key:  %s\n", pubPath)
	fmt.Printf("key id:      %s\n", kid)
}

// runPubkey prints the public key PEM for a given private key file.
func runPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key (default: ~/.provenance/signing.key)")
	fs.Parse(args)

	key, err := signing.LoadPrivateKey(resolveKeyPath(*keyPath))
	dieIf(err, "load key")

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	dieIf(err, "marshal public key")
	pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: der})

	kid, err := signing.KeyID(&key.PublicKey)
	dieIf(err, "derive key id")
	fmt.Fprintf(os.Stderr, "key id: %s\n", kid)
}

// runCommand executes cmd, streams output to stderr, and returns the exit code,
// a SHA-256 hash of stdout, and the elapsed wall-clock time in milliseconds.
func runCommand(cmd string) (exitCode int, stdoutHash string, durationMs int64, err error) {
	start := time.Now()

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return 0, "", 0, fmt.Errorf("empty command")
	}

	c := exec.Command(parts[0], parts[1:]...)
	var stdoutBuf bytes.Buffer
	c.Stdout = io.MultiWriter(os.Stderr, &stdoutBuf)
	c.Stderr = os.Stderr

	runErr := c.Run()
	durationMs = time.Since(start).Milliseconds()

	h := sha256.Sum256(stdoutBuf.Bytes())
	stdoutHash = fmt.Sprintf("sha256:%x", h)

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stdoutHash, durationMs, nil
		}
		return -1, stdoutHash, durationMs, runErr
	}
	return 0, stdoutHash, durationMs, nil
}

func resolveKeyPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	kp, err := signing.DefaultKeyPath()
	dieIf(err, "resolve key path")
	return kp
}

func dieIf(err error, ctx string) {
	if err != nil {
		die("%s: %v", ctx, err)
	}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `provenance-sign %s — Layer 1 attestation CLI

Usage:
  provenance-sign sign    [flags]   Sign a provenance manifest
  provenance-sign verify  [flags]   Verify a local provenance.json
  provenance-sign keygen  [flags]   Generate a new ECDSA key pair
  provenance-sign pubkey  [flags]   Print public key for a private key
  provenance-sign version           Print version

Run 'provenance-sign <command> -help' for flag details.
`, Version)
}
