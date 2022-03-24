package fetcher

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

var (
	ignoreJSON = regexp.MustCompile(`(stix-capec|enterprise-attack|mobile-attack|pre-attack)\.json`)
)

const (
	repoURL  = "https://github.com/mitre/cti.git"
	cveRegex = `CVE-[0-9]{4}-[0-9]{4,}`
)

// Config : Config parameters used in Git.
type Config struct {
	GitClient git.Operations
}

// FetchMitreCti :
func (c Config) FetchMitreCti() ([]models.Cti, error) {
	// Clone cyber threat repository
	dir := filepath.Join(utils.CacheDir(), "cti")
	if _, err := c.GitClient.CloneRepo(repoURL, dir); err != nil {
		return nil, xerrors.Errorf("Failed to GitClient.CloneRepo. err: %w", err)
	}

	// Get what have CVE ID
	matched, err := c.GitClient.Grep(cveRegex, dir)
	if err != nil {
		return nil, xerrors.Errorf("Failed to GitClient.Grep. err: %w", err)
	}

	ctiHashMap := map[string]bool{}
	ctis := []models.Cti{}
	for _, m := range matched {
		s := strings.Split(m, ":")
		if ignoreJSON.MatchString(s[0]) {
			continue
		}
		path := filepath.Join(dir, s[0])
		cveID := strings.ToUpper(s[1])

		var capec Capec
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, xerrors.Errorf("Failed to read file. err: %w", err)
		}
		if err := json.Unmarshal(b, &capec); err != nil {
			return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
		}

		for _, item := range capec.Objects {
			cti, err := convertToModel(cveID, item)
			if err != nil {
				return nil, xerrors.Errorf("Failed to convert model: %w", err)
			}

			var buf bytes.Buffer
			enc := gob.NewEncoder(&buf)
			if err := enc.Encode(cti); err != nil {
				return nil, xerrors.Errorf("Failed to encode CTI. err: %w", err)
			}
			if hash := fmt.Sprintf("%s#%x", cveID, md5.Sum(buf.Bytes())); !ctiHashMap[hash] {
				ctiHashMap[hash] = true
				ctis = append(ctis, cti)
			}
		}
	}

	return ctis, nil
}

func convertToModel(cveID string, item CapecObjects) (models.Cti, error) {
	publish := ParsedOrDefaultTime(time.RFC3339, item.Created)
	var modified time.Time
	if item.Modified == "" {
		modified = publish
	} else {
		modified = ParsedOrDefaultTime(time.RFC3339, item.Modified)
	}

	// Common Attack Pattern Enumeration and Classification
	xcapec := models.Capec{}
	if item.XCapecVersion != "" {
		xcapec = models.Capec{
			Abstruct: item.XCapecAbstraction,
			Severity: item.XCapecTypicalSeverity,
			Status:   item.XCapecStatus,
			Version:  item.XCapecVersion,
		}
	}

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

	return models.Cti{
		Name:             item.Name,
		Type:             item.Type,
		Description:      item.Description,
		CveID:            cveID,
		Capec:            xcapec,
		KillChains:       kills,
		References:       refs,
		PublishedDate:    publish,
		LastModifiedDate: modified,
	}, nil
}

// ParsedOrDefaultTime returns time.Parse(layout, value), or time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC) if it failed to parse
func ParsedOrDefaultTime(layout, value string) time.Time {
	defaultTime := time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if value == "" {
		return defaultTime
	}
	t, err := time.Parse(layout, value)
	if err != nil {
		log15.Warn("Failed to parse string", "timeformat", layout, "target string", value, "err", err)
		return defaultTime
	}
	return t
}
