package fetcher

import (
	// "bytes"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cheggaaa/pb"
	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

var (
	ignoreJSON = regexp.MustCompile(`stix-capec.json|enterprise-attack.json|mobile-attack.json|pre-attack.json`)
)

const (
	repoURL     = "https://github.com/mitre/cti.git"
	cvePattern1 = "CVE-[0-9]{4}-[0-9]{4}"
	cvePattern2 = "CVE-[0-9]{4}-[0-9]{5}"
	// ignoreJSON1 = "stix-capec.json"
	// ignoreJSON2 = "enterprise-attack.json"
	// ignoreJSON3 = "mobile-attack.json"
	// ignoreJSON4 = "pre-attack.json"
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
		cvePattern1,
		cvePattern2,
	}
	for _, p := range cvePatterns {
		matched, err := c.GitClient.Grep(p, dir)
		if err != nil {
			return nil, err
		}

		bar := pb.StartNew(len(matched))
		for _, m := range matched {
			s := strings.Split(m, ":")
			if ignoreJSON.MatchString(s[0]) {
				continue
			}
			path := filepath.Join(dir, s[0])
			cveID := strings.ToUpper(s[1])

			var capec Capec
			bytes, err := ioutil.ReadFile(path)
			if err = json.Unmarshal(bytes, &capec); err != nil {
				return nil, err
			}

			for _, item := range capec.Objects {
				record, err := convertToModel(cveID, item)
				if err != nil {
					return nil, xerrors.Errorf("failed to convert model: %w", err)
				}
				records = append(records, record)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return records, nil
}

func convertToModel(cveID string, item CapecObjects) (*models.Cti, error) {
	// KillChainPhases
	kills := []models.KillChain{}
	for _, k := range item.KillChainPhases {
		kill := models.KillChain{
			Name:  k.KillChainName,
			Phase: k.PhaseName,
		}
		kills = append(kills, kill)
	}

	// References
	refs := []models.Reference{}
	for _, r := range item.ExternalReferences {
		ref := models.Reference{
			ExternalID:  r.ExternalID,
			Link:        r.URL,
			Description: r.Description,
		}
		refs = append(refs, ref)
	}

	return &models.Cti{
		Name:        item.Name,
		Type:        item.Type,
		Description: item.Description,
		CveID:       cveID,
		KillChains:  kills,
		References:  refs,
	}, nil
}
