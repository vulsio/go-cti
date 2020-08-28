package fetcher

import (
	// "bytes"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	// "golang.org/x/xerrors"

	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

const (
	repoURL = "https://github.com/mitre/cti.git"
	cveRegex1 = "CVE-[0-9]{4}-[0-9]{4}"
	cveRegex2 = "CVE-[0-9]{4}-[0-9]{5}"
)

// Config : Config parameters used in Git.
type Config struct {
	GitClient git.Operations
}

// FetchMitreCti :
func (c Config) FetchMitreCti() (records []*models.Cti, err error) {
	// Clone cyber threat repository
	dir := filepath.Join(utils.CacheDir(), "cti")
	updatedFiles, err := c.GitClient.CloneRepo(repoURL, dir)
	if err != nil {
		return nil, err
	}
	log15.Info("Updated files", "count", len(updatedFiles))

	cvePatterns := []string{
		cveRegex1,
		cveRegex2,
	}
	for _, p := range cvePatterns {
		matched, err := c.GitClient.Grep(p, dir)
		if err != nil {
			return nil, err
		}
		for _, m := range matched {
			s := strings.Split(m, ":")
			path := filepath.Join(dir, s[0])
			cveID := strings.ToUpper(s[1])

			bytes, err := ioutil.ReadFile(path)
			items := json.Unmarshal(bytes, &Capec{}) 

			for _, item := range items {
				record, err := convertToModel(item, cveID)
				if err != nil {
					return nil, err
				}
				records = append(records, record)
			}
		}
	}
	
	return records, nil
}

func convertToModel(path string, cveID string) (*models.Cti, error) {

	return &models.Cti{
		Name:        item.Name,
		Description: item.Description,
		CveID:       cveID,
	}, nil
}