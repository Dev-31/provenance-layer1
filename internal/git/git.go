package git

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type GitInfo struct {
	CommitHash string `json:"commit_hash"`
	Branch     string `json:"branch"`
	IsDirty    bool   `json:"is_dirty"`
}

// GetGitHead returns HEAD commit hash, branch name, and dirty-working-tree flag.
func GetGitHead() (*GitInfo, error) {
	hash, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-parse HEAD: %w", err)
	}

	branch, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-parse branch: %w", err)
	}

	dirty := false
	if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil && len(out) > 0 {
		dirty = true
	}

	return &GitInfo{
		CommitHash: strings.TrimSpace(string(hash)),
		Branch:     strings.TrimSpace(string(branch)),
		IsDirty:    dirty,
	}, nil
}

// GetWorkingDirectory returns the process working directory.
func GetWorkingDirectory() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	return dir, nil
}
