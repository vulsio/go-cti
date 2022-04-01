package fetcher

import (
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/fetcher/attack"
	"github.com/vulsio/go-cti/fetcher/capec"
	"github.com/vulsio/go-cti/fetcher/cwe"
	"github.com/vulsio/go-cti/fetcher/nvd"
	"github.com/vulsio/go-cti/models"
)

// FetchCti :
func FetchCti() ([]models.Cti, []models.Mapping, error) {
	attacks, err := attack.Fetch()
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch MITRE ATT&CK. err: %w", err)
	}

	capecs, err := capec.Fetch()
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch CAPEC. err: %w", err)
	}
	ctis := append(attacks, capecs...)

	cweToCapecs, err := cwe.Fetch()
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch CWE. err: %w", err)
	}

	cveToCwes, err := nvd.Fetch()
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch NVD CVE. err: %w", err)
	}

	return ctis, buildMappings(ctis, cweToCapecs, cveToCwes), nil
}

func buildMappings(ctis []models.Cti, cweToCapecs, cveToCwes map[string][]string) []models.Mapping {
	capecToCwes := map[string][]string{}
	capecToAttacks := map[string][]string{}
	for _, cti := range ctis {
		if cti.Type != models.CAPECType {
			continue
		}

		for _, weak := range cti.Capec.RelatedWeaknesses {
			capecToCwes[cti.CtiID] = append(capecToCwes[cti.CtiID], weak.CweID)
		}

		for _, attackID := range cti.Capec.AttackIDs {
			capecToAttacks[cti.CtiID] = append(capecToAttacks[cti.CtiID], attackID.AttackID)
		}
	}

	for capecID, cweIDs := range capecToCwes {
		for _, cweID := range cweIDs {
			cweToCapecs[cweID] = append(cweToCapecs[cweID], capecID)
		}
	}

	mappings := []models.Mapping{}
	for cveID, cweIDs := range cveToCwes {
		uniqCtiIDs := map[string]struct{}{}
		for _, cweID := range cweIDs {
			for _, capecID := range cweToCapecs[cweID] {
				uniqCtiIDs[capecID] = struct{}{}
				for _, attackID := range capecToAttacks[capecID] {
					uniqCtiIDs[attackID] = struct{}{}
				}
			}
		}

		if len(uniqCtiIDs) > 0 {
			ctiIDs := []models.CtiID{}
			for ctiID := range uniqCtiIDs {
				ctiIDs = append(ctiIDs, models.CtiID{
					CtiID: ctiID,
				})
			}
			mappings = append(mappings, models.Mapping{
				CveID:  cveID,
				CtiIDs: ctiIDs,
			})
		}
	}
	return mappings
}
