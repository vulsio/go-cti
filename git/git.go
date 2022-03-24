package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/utils"
)

// Operations :
type Operations interface {
	CloneRepo(string, string) (map[string]struct{}, error)
	Grep(string, string) ([]string, error)
}

// Config :
type Config struct {
}

// CloneRepo :
func (gc Config) CloneRepo(url, repoPath string) (map[string]struct{}, error) {
	exists, err := utils.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, xerrors.Errorf("Failed to exists check. err: %w", err)
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		log15.Info("initializing", "repo", repoPath)
		if filepath.Base(repoPath) != "cti" {
			return nil, xerrors.Errorf("Failed to initializing repository. err: repoPath incorrect, %s", repoPath)
		}
		if err = os.RemoveAll(repoPath); err != nil {
			return nil, xerrors.Errorf("Failed to remove directory. err: %w", err)
		}
	}

	log15.Info("git clone", "repo", repoPath)
	if err = os.MkdirAll(repoPath, 0700); err != nil {
		return nil, xerrors.Errorf("Failed to make directory. err: %w", err)
	}
	if err := clone(url, repoPath); err != nil {
		return nil, xerrors.Errorf("Failed to clone repository. err: %w", err)
	}

	if err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		updatedFiles[path] = struct{}{}
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("Failed to walk directory. err: %w", err)
	}

	return updatedFiles, nil
}

func clone(url, repoPath string) error {
	commandAndArgs := []string{"clone", "--depth", "1", url, repoPath}
	cmd := exec.Command("git", commandAndArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("Failed to clone. err: %w", err)
	}
	return nil
}

// Grep :
func (gc Config) Grep(regex string, repoPath string) ([]string, error) {
	commandAndArgs := generateGitArgs(repoPath)

	grepCmd := []string{"grep", "-i", "-o", "--full-name", "-E", regex}
	output, err := utils.Exec("git", append(commandAndArgs, grepCmd...))
	if err != nil {
		return nil, xerrors.Errorf("Failed to git grep. err: %w", err)
	}
	matchedFiles := strings.Split(strings.TrimSpace(output), "\n")

	m := map[string]bool{}
	uniqFiles := []string{}
	for _, file := range matchedFiles {
		if !m[file] {
			m[file] = true
			uniqFiles = append(uniqFiles, file)
		}
	}

	return uniqFiles, nil
}

func generateGitArgs(repoPath string) []string {
	gitDir := filepath.Join(repoPath, ".git")
	return []string{"--git-dir", gitDir, "--work-tree", repoPath}
}
