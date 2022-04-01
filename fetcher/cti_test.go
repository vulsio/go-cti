package fetcher

import (
	"testing"

	"github.com/vulsio/go-cti/models"
	"golang.org/x/exp/slices"
)

func TestBuildMappings(t *testing.T) {
	type args struct {
		ctis        []models.Cti
		cweToCapecs map[string][]string
		cveToCwes   map[string][]string
	}

	tests := []struct {
		in       args
		expected []models.Mapping
	}{
		{
			in: args{
				ctis: []models.Cti{
					{
						CtiID: "CAPEC-1",
						Type:  models.CAPECType,
						Capec: &models.Capec{
							AttackIDs: []models.AttackID{
								{AttackID: "T1083"},
							},
						},
					},
				},
				cweToCapecs: map[string][]string{
					"CWE-284": {"CAPEC-1"},
				},
				cveToCwes: map[string][]string{
					"CVE-2020-10627": {"CWE-284"},
					"CVE-2020-0002":  {"CWE-787", "CWE-416"},
				},
			},
			expected: []models.Mapping{
				{
					CveID: "CVE-2020-10627",
					CtiIDs: []models.CtiID{
						{CtiID: "CAPEC-1"},
						{CtiID: "T1083"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		if actual := buildMappings(tt.in.ctis, tt.in.cweToCapecs, tt.in.cveToCwes); !slices.EqualFunc(actual, tt.expected, func(e1 models.Mapping, e2 models.Mapping) bool {
			return e1.CveID == e2.CveID && slices.Equal(e1.CtiIDs, e2.CtiIDs)
		}) {
			t.Errorf("[%d] buildMappings expected: %v, actual: %v\n", i, tt.expected, actual)
		}
	}
}
