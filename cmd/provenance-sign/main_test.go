package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunCommandQuotedArgs verifies that test commands with quoted args work.
func TestRunCommandQuotedArgs(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "check.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho hello world\n"), 0755)

	exitCode, stdoutHash, durationMs, err := runCommand("sh " + script)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.True(t, strings.HasPrefix(stdoutHash, "sha256:"))
	require.Greater(t, durationMs, int64(0))
}
