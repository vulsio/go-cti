package nvd

// https://scap.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
type nvd struct {
	CveItems []struct {
		Cve struct {
			CveDataMeta struct {
				ID string `json:"ID"`
			} `json:"CVE_data_meta"`
			Problemtype struct {
				ProblemtypeData []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"problemtype_data"`
			} `json:"problemtype"`
			Description struct {
				DescriptionData []struct {
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
	} `json:"CVE_Items"`
}
