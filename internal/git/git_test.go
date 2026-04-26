package git

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetWorkingDirectory(t *testing.T) {
	dir, err := GetWorkingDirectory()
	require.NoError(t, err)
	require.NotEmpty(t, dir)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestGetGitHead_InGitRepo(t *testing.T) {
	info, err := GetGitHead()
	if err != nil {
		t.Skip("not inside a git repo:", err)
	}
	require.NotEmpty(t, info.CommitHash)
	require.Len(t, info.CommitHash, 40)
	require.NotEmpty(t, info.Branch)
}
