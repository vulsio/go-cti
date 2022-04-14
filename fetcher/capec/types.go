package capec

import "time"

type root struct {
	Type    string      `json:"type"`
	ID      string      `json:"id"`
	Objects []ctiObject `json:"objects"`
}

type ctiObject struct {
	ID                 string      `json:"id"`
	Type               string      `json:"type"`
	Name               string      `json:"name,omitempty"`
	Description        string      `json:"description,omitempty"`
	ExternalReferences []reference `json:"external_references,omitempty"`
	RelationshipType   string      `json:"relationship_type,omitempty"`
	SourceRef          string      `json:"source_ref,omitempty"`
	TargetRef          string      `json:"target_ref,omitempty"`
	Created            time.Time   `json:"created"`
	Modified           time.Time   `json:"modified,omitempty"`

	XCapecStatus              string              `json:"x_capec_status,omitempty"`
	XCapecExtendedDescription string              `json:"x_capec_extended_description,omitempty"`
	XCapecAbstraction         string              `json:"x_capec_abstraction,omitempty"`
	XCapecTypicalSeverity     string              `json:"x_capec_typical_severity,omitempty"`
	XCapecAlternateTerms      []string            `json:"x_capec_alternate_terms,omitempty"`
	XCapecConsequences        map[string][]string `json:"x_capec_consequences,omitempty"`
	XCapecSkillsRequired      map[string]string   `json:"x_capec_skills_required,omitempty"`
	XCapecDomains             []string            `json:"x_capec_domains,omitempty"`
	XCapecExampleInstances    []string            `json:"x_capec_example_instances,omitempty"`
	XCapecExecutionFlow       string              `json:"x_capec_execution_flow,omitempty"`
	XCapecLikelihoodOfAttack  string              `json:"x_capec_likelihood_of_attack,omitempty"`
	XCapecPrerequisites       []string            `json:"x_capec_prerequisites,omitempty"`
	XCapecResourcesRequired   []string            `json:"x_capec_resources_required,omitempty"`
	XCapecCanPrecedeRefs      []string            `json:"x_capec_can_precede_refs,omitempty"`
	XCapecChildOfRefs         []string            `json:"x_capec_child_of_refs,omitempty"`
	XCapecParentOfRefs        []string            `json:"x_capec_parent_of_refs,omitempty"`
	XCapecPeerOfRefs          []string            `json:"x_capec_peer_of_refs,omitempty"`
	XCapecCanFollowRefs       []string            `json:"x_capec_can_follow_refs,omitempty"`
}

type attackPattern struct {
	id                  string
	name                string
	status              string
	abstraction         string
	likelihoodOfAttack  string
	typicalSeverity     string
	description         string
	extendedDescription string
	alternateTerms      string
	executionFlow       string
	exampleInstances    string
	domains             string
	consequences        []string
	prerequisites       string
	resourcesRequired   string
	skillRequired       []string
	relatedWeaknesses   []string
	references          []reference
	parentOfRefs        []string
	childOfRefs         []string
	canFollowRefs       []string
	canPrecedeRefs      []string
	peerOfRefs          []string
	attackIDs           []string
	created             time.Time
	modified            time.Time
}

type reference struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id,omitempty"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

type additionalInfoObject struct {
	objType     string
	name        string
	description string
}

type relationshipObject struct {
	id               string
	description      string
	relationshipType string
	sourceRef        string
	targetRef        string
	references       []reference
}
