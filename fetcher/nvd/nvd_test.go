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
			in:   "testdata/main.tar.gz",
			base: map[string][]string{},
			expected: map[string][]string{
				"CVE-2020-0002": {"CWE-787", "CWE-416"},
			},
		},
	}

	for i, tt := range tests {
		bs, err := os.ReadFile(tt.in)
		if err != nil {
			t.Fatalf("[%d] Failed to read file. err: %s", i, err)
		}
		actual, err := parse(bs)
		if err != nil {
			t.Fatalf("[%d] Failed to parse. err: %s", i, err)
		}
		if !maps.EqualFunc(actual, tt.expected, func(v1 []string, v2 []string) bool {
			return slices.Equal(v1, v2)
		}) {
			t.Errorf("[%d] parse expected: %v, actual: %v\n", i, tt.expected, actual)
		}
	}
}
