package nvd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

// Fetch NVD CVE data
func Fetch() (map[string][]string, error) {
	log15.Info("Fetching NVD CVE...")

	dir, err := os.MkdirTemp("", "go-cti")
	if err != nil {
		return nil, xerrors.Errorf("Failed to create temp directory. err: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := fetch(dir); err != nil {
		return nil, xerrors.Errorf("Failed to fetch vuls-data-raw-nvd-api-cve. err: %w", err)
	}

	return parse(dir)
}

func fetch(dir string) error {
	ctx := context.TODO()
	repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-nvd-api-cve")
	if err != nil {
		return xerrors.Errorf("Failed to create client for ghcr.io/vulsio/vuls-data-db:vuls-data-raw-nvd-api-cve. err: %w", err)
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return xerrors.Errorf("Failed to fetch manifest. err: %w", err)
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return xerrors.Errorf("Failed to decode manifest. err: %w", err)
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return xerrors.Errorf("Failed to find digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return xerrors.Errorf("Failed to fetch content. err: %w", err)
	}
	defer r.Close()

	zr, err := zstd.NewReader(r)
	if err != nil {
		return xerrors.Errorf("Failed to new zstd reader. err: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("Failed to next tar reader. err: %w", err)
		}

		p := filepath.Join(dir, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0755); err != nil {
				return xerrors.Errorf("Failed to mkdir %s. err: %w", p, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return xerrors.Errorf("Failed to mkdir %s. err: %w", p, err)
			}

			if err := func() error {
				f, err := os.Create(p)
				if err != nil {
					return xerrors.Errorf("Failed to create %s. err: %w", p, err)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return xerrors.Errorf("Failed to copy to %s. err: %w", p, err)
				}

				return nil
			}(); err != nil {
				return xerrors.Errorf("Failed to create %s. err: %w", p, err)
			}
		}
	}

	cmd := exec.Command("git", "-C", filepath.Join(dir, "vuls-data-raw-nvd-api-cve"), "restore", ".")
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("Failed to exec %q. err: %w", cmd.String(), err)
	}

	return nil
}

func parse(dir string) (map[string][]string, error) {
	cveToCwes := make(map[string][]string)

	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasPrefix(filepath.Base(path), "CVE-") || filepath.Ext(path) != ".json" {
			return nil
		}

		ss := strings.Split(filepath.Base(path), "-")
		if len(ss) != 3 {
			return xerrors.Errorf("Failed to parse year. err: invalid ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}.json", filepath.Base(path))
		}
		if _, err := time.Parse("2006", ss[1]); err != nil {
			return xerrors.Errorf("Failed to parse year. err: invalid ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}.json", filepath.Base(path))
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("Failed to open %s. err: %w", path, err)
		}
		defer f.Close()

		var nvddata nvd
		if err := json.NewDecoder(f).Decode(&nvddata); err != nil {
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
	}); err != nil {
		return nil, xerrors.Errorf("Failed to walk %s. err: %w", dir, err)
	}

	return cveToCwes, nil
}
