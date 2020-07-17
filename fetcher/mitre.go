package fetcher

import (
	// "bytes"
	// "encoding/json"
	// "io"
	"path/filepath"

	"github.com/inconshreveable/log15"
	// "golang.org/x/xerrors"

	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/utils"
)

const (
	repoURL = "https://github.com/mitre/cti.git"
)

// Config : Config parameters used in Git.
type Config struct {
	GitClient git.Operations
}

// FetchMitreCti :
func (c Config) FetchMitreCti() (err error) {
	// Clone vuln-list repository
	dir := filepath.Join(utils.CacheDir(), "cti")
	updatedFiles, err := c.GitClient.CloneRepo(repoURL, dir)
	if err != nil {
		// return nil, err
		return err
	}
	log15.Info("Updated files", "count", len(updatedFiles))

	return nil
}
