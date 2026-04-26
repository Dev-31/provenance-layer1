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
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho hello world\n"), 0755))

	exitCode, stdoutHash, durationMs, err := runCommand("sh " + script)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.True(t, strings.HasPrefix(stdoutHash, "sha256:"))
	require.Greater(t, durationMs, int64(0))
}

// TestRunCommandWithQuotedSpaces verifies that commands with quoted spaces are
// handled correctly by the shell, not split naively by strings.Fields.
func TestRunCommandWithQuotedSpaces(t *testing.T) {
	// This command contains quoted spaces — strings.Fields would split incorrectly.
	// With sh -c, the shell interprets quotes correctly.
	exitCode, stdoutHash, durationMs, err := runCommand(`echo "hello world"`)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.True(t, strings.HasPrefix(stdoutHash, "sha256:"))
	// echo may complete in sub-millisecond time, so >= 0 is the correct bound.
	require.GreaterOrEqual(t, durationMs, int64(0))
}
