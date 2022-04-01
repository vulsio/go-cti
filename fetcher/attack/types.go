package attack

import "time"

type root struct {
	Type        string      `json:"type"`
	Objects     []ctiObject `json:"objects"`
	ID          string      `json:"id"`
	SpecVersion string      `json:"spec_version"`
}

type ctiObject struct {
	Created           time.Time `json:"created"`
	Modified          time.Time `json:"modified,omitempty"`
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	Name              string    `json:"name,omitempty"`
	Description       string    `json:"description,omitempty"`
	CreatedByRef      string    `json:"created_by_ref,omitempty"`
	ObjectMarkingRefs []string  `json:"object_marking_refs,omitempty"`
	KillChainPhases   []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases,omitempty"`
	ExternalReferences []reference `json:"external_references,omitempty"`
	Revoked            bool        `json:"revoked,omitempty"`
	TargetRef          string      `json:"target_ref,omitempty"`
	SourceRef          string      `json:"source_ref,omitempty"`
	TacticRefs         []string    `json:"tactic_refs,omitempty"`
	RelationshipType   string      `json:"relationship_type,omitempty"`
	IdentityClass      string      `json:"identity_class,omitempty"`
	Aliases            []string    `json:"aliases,omitempty"`
	Labels             []string    `json:"labels,omitempty"`
	Definition         struct {
		Statement string `json:"statement"`
	} `json:"definition,omitempty"`
	DefinitionType            string   `json:"definition_type,omitempty"`
	XMitreShortname           string   `json:"x_mitre_shortname,omitempty"`
	XMitreDetection           string   `json:"x_mitre_detection,omitempty"`
	XMitreDataSources         []string `json:"x_mitre_data_sources,omitempty"`
	XMitreVersion             string   `json:"x_mitre_version,omitempty"`
	XMitrePermissionsRequired []string `json:"x_mitre_permissions_required,omitempty"`
	XMitrePlatforms           []string `json:"x_mitre_platforms,omitempty"`
	XMitreIsSubtechnique      bool     `json:"x_mitre_is_subtechnique,omitempty"`
	// XMitreContributors         []string `json:"x_mitre_contributors,omitempty"`
	XMitreSystemRequirements   []string `json:"x_mitre_system_requirements,omitempty"`
	XMitreDefenseBypassed      []string `json:"x_mitre_defense_bypassed,omitempty"`
	XMitreEffectivePermissions []string `json:"x_mitre_effective_permissions,omitempty"`
	XMitreImpactType           []string `json:"x_mitre_impact_type,omitempty"`
	XMitreNetworkRequirements  bool     `json:"x_mitre_network_requirements,omitempty"`
	XMitreRemoteSupport        bool     `json:"x_mitre_remote_support,omitempty"`
	XMitreDeprecated           bool     `json:"x_mitre_deprecated,omitempty"`
	// XMitreOldAttackID          string   `json:"x_mitre_old_attack_id,omitempty"`
	// XMitreAliases              []string `json:"x_mitre_aliases,omitempty"`
	// XMitreCollectionLayers []string `json:"x_mitre_collection_layers,omitempty"`
	XMitreDataSourceRef string `json:"x_mitre_data_source_ref,omitempty"`
}
type attackPattern struct {
	id                   string
	name                 string
	description          string
	dataSources          string
	permissionRequired   string
	effectivePermissions string
	platforms            string
	impactType           string
	networkRequirements  bool
	remoteSupport        bool
	defenseByPassed      string
	killChainPhases      []string
	detection            string
	references           []reference
	capecIDs             []string
	created              time.Time
	modified             time.Time
	deprecated           bool
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
	deprecated  bool
}

type relationshipObject struct {
	id               string
	description      string
	relationshipType string
	sourceRef        string
	targetRef        string
	references       []reference
}
type dataComponent struct {
	name          string
	description   string
	dataSourceRef string
}
