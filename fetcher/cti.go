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
func FetchCti() ([]models.Technique, []models.CveToTechniques, []models.Attacker, error) {
	attackTechniques, attackers, err := attack.Fetch()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed to fetch MITRE ATT&CK. err: %w", err)
	}

	capecTechniques, err := capec.Fetch()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed to fetch CAPEC. err: %w", err)
	}
	techniques := append(attackTechniques, capecTechniques...)

	cweToCapecs, err := cwe.Fetch()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed to fetch CWE. err: %w", err)
	}

	cveToCwes, err := nvd.Fetch()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed to fetch NVD CVE. err: %w", err)
	}

	return techniques, buildCveToTechniques(techniques, cweToCapecs, cveToCwes), attackers, nil
}

func buildCveToTechniques(techniques []models.Technique, cweToCapecs, cveToCwes map[string][]string) []models.CveToTechniques {
	capecToCwes := map[string][]string{}
	capecToAttacks := map[string][]string{}
	for _, technique := range techniques {
		if technique.Type != models.CAPECType {
			continue
		}

		for _, weak := range technique.Capec.RelatedWeaknesses {
			capecToCwes[technique.TechniqueID] = append(capecToCwes[technique.TechniqueID], weak.CweID)
		}

		for _, attackID := range technique.Capec.AttackIDs {
			capecToAttacks[technique.TechniqueID] = append(capecToAttacks[technique.TechniqueID], attackID.AttackID)
		}
	}

	for capecID, cweIDs := range capecToCwes {
		for _, cweID := range cweIDs {
			cweToCapecs[cweID] = append(cweToCapecs[cweID], capecID)
		}
	}

	mappings := []models.CveToTechniques{}
	for cveID, cweIDs := range cveToCwes {
		uniqTechniqueIDs := map[string]struct{}{}
		for _, cweID := range cweIDs {
			for _, capecID := range cweToCapecs[cweID] {
				uniqTechniqueIDs[capecID] = struct{}{}
				for _, attackID := range capecToAttacks[capecID] {
					uniqTechniqueIDs[attackID] = struct{}{}
				}
			}
		}

		if len(uniqTechniqueIDs) > 0 {
			techniqueIDs := []models.CveToTechniqueID{}
			for techniqueID := range uniqTechniqueIDs {
				techniqueIDs = append(techniqueIDs, models.CveToTechniqueID{
					TechniqueID: techniqueID,
				})
			}
			mappings = append(mappings, models.CveToTechniques{
				CveID:        cveID,
				TechniqueIDs: techniqueIDs,
			})
		}
	}
	return mappings
}
