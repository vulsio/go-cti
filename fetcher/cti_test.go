package fetcher

import (
	"testing"

	"golang.org/x/exp/slices"

	"github.com/vulsio/go-cti/models"
)

func TestBuildCveToTechniquess(t *testing.T) {
	type args struct {
		techniques  []models.Technique
		cweToCapecs map[string][]string
		cveToCwes   map[string][]string
	}

	tests := []struct {
		in       args
		expected []models.CveToTechniques
	}{
		{
			in: args{
				techniques: []models.Technique{
					{
						TechniqueID: "CAPEC-1",
						Type:        models.CAPECType,
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
			expected: []models.CveToTechniques{
				{
					CveID: "CVE-2020-10627",
					TechniqueIDs: []models.CveToTechniqueID{
						{TechniqueID: "CAPEC-1"},
						{TechniqueID: "T1083"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		if actual := buildCveToTechniques(tt.in.techniques, tt.in.cweToCapecs, tt.in.cveToCwes); !slices.EqualFunc(actual, tt.expected, func(e1 models.CveToTechniques, e2 models.CveToTechniques) bool {
			return e1.CveID == e2.CveID && slices.Equal(e1.TechniqueIDs, e2.TechniqueIDs)
		}) {
			t.Errorf("[%d] buildCveToTechniques expected: %v, actual: %v\n", i, tt.expected, actual)
		}
	}
}
