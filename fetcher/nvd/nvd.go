package nvd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/utils"
)

const nvdURLFormat = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

func Fetch() (map[string][]string, error) {
	years := []string{"recent", "modified"}
	for y := 2002; y <= time.Now().Year(); y++ {
		years = append(years, fmt.Sprintf("%d", y))
	}

	cveToCwes := map[string][]string{}
	for _, y := range years {
		log15.Info("Fetching NVD CVE...", "year", y)
		res, err := utils.FetchURL(fmt.Sprintf(nvdURLFormat, y))
		if err != nil {
			return nil, xerrors.Errorf("Failed to fetch NVD CVE %s. err: %w", y, err)
		}
		if err := parse(res, cveToCwes); err != nil {
			return nil, xerrors.Errorf("Failed to parse NVD CVE %s. err: %w", y, err)
		}
	}
	return cveToCwes, nil
}

func parse(res []byte, cveToCwes map[string][]string) error {
	r, err := gzip.NewReader(bytes.NewReader(res))
	if err != nil {
		return xerrors.Errorf("Failed to new gzip reader. err: %w", err)
	}
	defer r.Close()

	var nvddata nvd
	if err := json.NewDecoder(r).Decode(&nvddata); err != nil {
		return xerrors.Errorf("Failed to decode JSON. err: %w", err)
	}

	for _, item := range nvddata.CveItems {
		if _, ok := cveToCwes[item.Cve.CveDataMeta.ID]; ok {
			continue
		}

		rejected := false
		for _, description := range item.Cve.Description.DescriptionData {
			if strings.Contains(description.Value, "** REJECT **") {
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		for _, data := range item.Cve.Problemtype.ProblemtypeData {
			for _, description := range data.Description {
				if strings.HasPrefix(description.Value, "CWE-") {
					cveToCwes[item.Cve.CveDataMeta.ID] = append(cveToCwes[item.Cve.CveDataMeta.ID], description.Value)
				}
			}
		}
	}
	return nil
}
