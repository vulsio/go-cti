package fetcher

import (
	"fmt"
	// "bytes"
	// "encoding/json"
	// "io"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	// "golang.org/x/xerrors"

	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/utils"
)

const (
	repoURL = "https://github.com/mitre/cti.git"
)

var (
	cveRegex1 = "CVE-[0-9]{4}-[0-9]{4}"
	cveRegex2 = "CVE-[0-9]{4}-[0-9]{5}"
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

	matchedFiles, err := c.GitClient.Grep(cveRegex1, dir)
	if err != nil {
		return err
	}

	for _, m := range matchedFiles {
		s := strings.Split(m, ":")
		filePath := s[0]
		cveID := strings.ToUpper(s[1])
		fmt.Println(filePath, cveID)
	}


	matchedFiles2, err := c.GitClient.Grep(cveRegex2, dir)
	if err != nil {
		return err
	}

	for _, m := range matchedFiles2 {
		s := strings.Split(m, ":")
		filePath := s[0]
		cveID := strings.ToUpper(s[1])
		fmt.Println(filePath, cveID)
	}
	
	return nil
}
