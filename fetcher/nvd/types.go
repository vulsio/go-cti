package nvd

// https://github.com/MaineK00n/vuls-data-update/blob/38e5f8203f3ba90ce565e4a8eb650c17412ea88d/pkg/fetch/nvd/api/cve/types.go#L18
type nvd struct {
	ID         string `json:"id"`
	Weaknesses []struct {
		Source      string `json:"source"`
		Type        string `json:"type"`
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses,omitempty"`
}
