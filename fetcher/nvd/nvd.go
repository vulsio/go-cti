package nvd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/utils"
)

const repositoryURL = "https://github.com/vulsio/vuls-data-raw-nvd-api-cve/archive/refs/heads/main.tar.gz"

// Fetch NVD CVE data
func Fetch() (map[string][]string, error) {
	log15.Info("Fetching NVD CVE...")
	bs, err := utils.FetchURL(repositoryURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch NVD repository. err: %w", err)
	}
	return parse(bs)
}

func parse(bs []byte) (map[string][]string, error) {
	cveToCwes := map[string][]string{}

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, xerrors.Errorf("Failed to create gzip reader. err: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("Failed to next tar reader. err: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if !strings.HasPrefix(filepath.Base(hdr.Name), "CVE-") {
			continue
		}

		if err := func() error {
			ss := strings.Split(filepath.Base(hdr.Name), "-")
			if len(ss) != 3 {
				return xerrors.Errorf("Failed to parse year. err: invalid ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}.json", filepath.Base(hdr.Name))
			}
			if _, err := time.Parse("2006", ss[1]); err != nil {
				return xerrors.Errorf("Failed to parse year. err: invalid ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}.json", filepath.Base(hdr.Name))
			}

			var nvddata nvd
			if err := json.NewDecoder(tr).Decode(&nvddata); err != nil {
				return xerrors.Errorf("Failed to decode JSON. err: %w", err)
			}

			for _, w := range nvddata.Weaknesses {
				for _, d := range w.Description {
					if strings.HasPrefix(d.Value, "CWE-") && !slices.Contains(cveToCwes[nvddata.ID], d.Value) {
						cveToCwes[nvddata.ID] = append(cveToCwes[nvddata.ID], d.Value)
					}
				}
			}

			return nil
		}(); err != nil {
			return nil, xerrors.Errorf("Failed to extract %s. err: %w", hdr.Name, err)
		}
	}

	return cveToCwes, nil
}
