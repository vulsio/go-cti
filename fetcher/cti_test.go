package fetcher

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

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
		opts := []cmp.Option{
			cmpopts.SortSlices(func(i, j models.CveToTechniqueID) bool {
				return i.TechniqueID < j.TechniqueID
			}),
		}
		if diff := cmp.Diff(buildCveToTechniques(tt.in.techniques, tt.in.cweToCapecs, tt.in.cveToCwes), tt.expected, opts...); diff != "" {
			t.Errorf("[%d] buildCveToTechniques diff: (-got +want)\n%s", i, diff)
		}
	}
}
