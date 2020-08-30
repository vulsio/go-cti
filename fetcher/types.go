package fetcher

import (
	"time"
)

// Capec :
type Capec struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	SpecVersion string `json:"spec_version"`
	Objects     []struct {
		Type               string    `json:"type"`
		ID                 string    `json:"id"`
		CreatedByRef       string    `json:"created_by_ref"`
		Aliases            []string  `json:"aliases"`
		Created            time.Time `json:"created"`
		Modified           time.Time `json:"modified"`
		Name               string    `json:"name"`
		Description        string    `json:"description"`
		ExternalReferences []struct {
			SourceName  string `json:"source_name"`
			URL         string `json:"url,omitempty"`
			ExternalID  string `json:"external_id"`
			Description string `json:"description,omitempty"`
		} `json:"external_references"`
		KillChainPhases []struct {
			KillChainName string `json:"kill_chain_name"`
			PhaseName     string `json:"phase_name"`
		} `json:"kill_chain_phases"`
		ObjectMarkingRefs []string `json:"object_marking_refs"`
		// Capec
		XCapecAbstraction  string `json:"x_capec_abstraction"`
		XCapecConsequences struct {
			AccessControl   []string `json:"Access_Control"`
			Authorization   []string `json:"Authorization"`
			Availability    []string `json:"Availability"`
			Confidentiality []string `json:"Confidentiality"`
			Integrity       []string `json:"Integrity"`
		} `json:"x_capec_consequences"`
		XCapecExampleInstances   []string `json:"x_capec_example_instances"`
		XCapecLikelihoodOfAttack string   `json:"x_capec_likelihood_of_attack"`
		XCapecPrerequisites      []string `json:"x_capec_prerequisites"`
		XCapecResourcesRequired  []string `json:"x_capec_resources_required"`
		XCapecSkillsRequired     struct {
			Low    string `json:"Low"`
			Medium string `json:"Medium"`
			High   string `json:"High"`
		} `json:"x_capec_skills_required"`
		XCapecStatus          string `json:"x_capec_status"`
		XCapecTypicalSeverity string `json:"x_capec_typical_severity"`
		XCapecVersion         string `json:"x_capec_version"`
		// Mitre
		XMitreIsSubtechnique bool     `json:"x_mitre_is_subtechnique"`
		XMitreContributors   []string `json:"x_mitre_contributors"`
		XMitreVersion        string   `json:"x_mitre_version"`
		XMitreDataSources    []string `json:"x_mitre_data_sources"`
		XMitreDetection      string   `json:"x_mitre_detection"`
		XMitrePlatforms      []string `json:"x_mitre_platforms"`
	} `json:"objects"`
}
