package cwe

import (
	"os"
	"testing"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		expected map[string][]string
	}{
		{
			in: "testdata/cwec.xml.zip",
			expected: map[string][]string{
				"CWE-1021": {"CAPEC-103", "CAPEC-181", "CAPEC-222", "CAPEC-504", "CAPEC-506", "CAPEC-654"},
			},
		},
	}

	for i, tt := range tests {
		res, err := os.ReadFile(tt.in)
		if err != nil {
			t.Fatalf("[%d] Failed to read file. err: %s", i, err)
		}
		actual, err := parse(res)
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
