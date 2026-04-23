package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dev-sopariwala/provenance-layer1/internal/git"
	"github.com/dev-sopariwala/provenance-layer1/internal/json"
	"github.com/dev-sopariwala/provenance-layer1/internal/signing"
)

type ProvenanceData struct {
	Timestamp   string                 `json:"timestamp"`
	GitInfo     *git.GitInfo           `json:"git_info"`
	WorkingDir  string                 `json:"working_directory"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Signature   *signing.SignatureResult `json:"signature,omitempty"`
}

var (
	inputFile   = flag.String("input", "", "Input JSON file to sign (optional)")
	outputFile  = flag.String("output", "provenance.json", "Output file for provenance signature")
	keyFile     = flag.String("key", "", "Private key file (generate if not provided)")
	data        = flag.String("data", "", "JSON data string to sign (optional)")
	versionFlag = flag.Bool("version", false, "Show version information")
)

const Version = "1.0.0"

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Printf("provenance-sign version %s\n", Version)
		os.Exit(0)
	}

	// Create signer
	signer, err := signing.NewSigner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signer: %v\n", err)
		os.Exit(1)
	}

	// Get git info
	gitInfo, err := git.GetGitHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to get git info: %v\n", err)
		gitInfo = &git.GitInfo{
			CommitHash: "unknown",
			Branch:     "unknown",
			IsDirty:    false,
		}
	}

	// Get working directory
	workingDir, err := git.GetWorkingDirectory()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to get working directory: %v\n", err)
		workingDir = "unknown"
	}

	// Prepare provenance data
	provenance := ProvenanceData{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		GitInfo:    gitInfo,
		WorkingDir: workingDir,
		Data:       make(map[string]interface{}),
	}

	// Load additional data
	var additionalData map[string]interface{}
	if *inputFile != "" {
		content, err := os.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(content, &additionalData); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing input JSON: %v\n", err)
			os.Exit(1)
		}
		provenance.Data = additionalData
	} else if *data != "" {
		if err := json.Unmarshal([]byte(*data), &additionalData); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing data JSON: %v\n", err)
			os.Exit(1)
		}
		provenance.Data = additionalData
	}

	// Canonicalize and sign
	canonicalJSON, err := json.CanonicalizeJSON(provenance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error canonicalizing JSON: %v\n", err)
		os.Exit(1)
	}

	signature, err := signer.Sign(canonicalJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing data: %v\n", err)
		os.Exit(1)
	}

	provenance.Signature = signature

	// Marshal final result
	result, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
		os.Exit(1)
	}

	// Write output
	if err := os.WriteFile(*outputFile, result, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Provenance signature written to %s\n", *outputFile)
	fmt.Printf("Signature: %s\n", result)
}