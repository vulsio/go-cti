package nvd

import (
	"os"
	"testing"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		base     map[string][]string
		expected map[string][]string
	}{
		{
			in:   "testdata/nvd.json.gz",
			base: map[string][]string{},
			expected: map[string][]string{
				"CVE-2020-0002": {"CWE-787", "CWE-416"},
			},
		},
		{
			in: "testdata/nvd.json.gz",
			base: map[string][]string{
				"CVE-2020-0002": {"CWE-787"},
			},
			expected: map[string][]string{
				"CVE-2020-0002": {"CWE-787"},
			},
		},
	}

	for i, tt := range tests {
		res, err := os.ReadFile(tt.in)
		if err != nil {
			t.Fatalf("[%d] Failed to read file. err: %s", i, err)
		}
		if err := parse(res, tt.base); err != nil {
			t.Fatalf("[%d] Failed to parse. err: %s", i, err)
		}
		if !maps.EqualFunc(tt.base, tt.expected, func(v1 []string, v2 []string) bool {
			return slices.Equal(v1, v2)
		}) {
			t.Errorf("[%d] parse expected: %v, actual: %v\n", i, tt.expected, tt.base)
		}
	}
}
