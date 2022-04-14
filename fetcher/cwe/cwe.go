package cwe

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/utils"
)

const cweURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// Fetch CWE data
func Fetch() (map[string][]string, error) {
	log15.Info("Fetching CWE...")

	res, err := utils.FetchURL(cweURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CWE XML. err: %w", err)
	}
	mappings, err := parse(res)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse CWE XML. err: %w", err)
	}
	return mappings, nil
}

func parse(res []byte) (map[string][]string, error) {
	reader, err := zip.NewReader(bytes.NewReader(res), int64(len(res)))
	if err != nil {
		return nil, xerrors.Errorf("Failed to new zip Reader. err: %w", err)
	}

	cweIDtoCapecIDs := map[string][]string{}
	for _, file := range reader.File {
		if file.Name != "cwec_v4.6.xml" {
			continue
		}

		r, err := file.Open()
		if err != nil {
			return nil, xerrors.Errorf("Failed to open file. err: %w", err)
		}
		defer r.Close()

		var catalog weaknessCatalog
		if err := xml.NewDecoder(r).Decode(&catalog); err != nil {
			return nil, xerrors.Errorf("Failed to decode xml. err: %w", err)
		}

		for _, weakness := range catalog.Weaknesses.Weakness {
			cweID := fmt.Sprintf("CWE-%s", weakness.ID)
			for _, attackPattern := range weakness.RelatedAttackPatterns.RelatedAttackPattern {
				cweIDtoCapecIDs[cweID] = append(cweIDtoCapecIDs[cweID], fmt.Sprintf("CAPEC-%s", attackPattern.CAPECID))
			}
		}
	}
	return cweIDtoCapecIDs, nil
}
