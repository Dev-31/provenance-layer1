package git

import (
	"fmt"
	"os/exec"
	"strings"
)

type GitInfo struct {
	CommitHash string `json:"commit_hash"`
	Branch     string `json:"branch"`
	IsDirty    bool   `json:"is_dirty"`
}

// GetGitHead returns Git HEAD information
func GetGitHead() (*GitInfo, error) {
	// Get commit hash
	hash, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git HEAD: %w", err)
	}

	// Get branch name
	branch, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git branch: %w", err)
	}

	// Check if working directory is dirty
	dirty := false
	output, err := exec.Command("git", "status", "--porcelain").Output()
	if err == nil && len(output) > 0 {
		dirty = true
	}

	gitInfo := &GitInfo{
		CommitHash: strings.TrimSpace(string(hash)),
		Branch:     strings.TrimSpace(string(branch)),
		IsDirty:    dirty,
	}

	return gitInfo, nil
}

// GetWorkingDirectory returns the current working directory
func GetWorkingDirectory() (string, error) {
	output, err := exec.Command("pwd").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}