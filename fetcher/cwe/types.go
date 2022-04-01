package cwe

type weaknessCatalog struct {
	Weaknesses struct {
		Weakness []struct {
			ID                    string `xml:"ID,attr"`
			RelatedAttackPatterns struct {
				RelatedAttackPattern []struct {
					CAPECID string `xml:"CAPEC_ID,attr"`
				} `xml:"Related_Attack_Pattern"`
			} `xml:"Related_Attack_Patterns"`
		} `xml:"Weakness"`
	} `xml:"Weaknesses"`
}
