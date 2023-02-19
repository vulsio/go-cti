package models

import (
	"time"

	"gorm.io/gorm"
)

// LatestSchemaVersion manages the Schema version used in the latest go-cti.
const LatestSchemaVersion = 1

// FetchMeta has meta information
type FetchMeta struct {
	gorm.Model    `json:"-"`
	GoCTIRevision string
	SchemaVersion uint
	LastFetchedAt time.Time
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}

// CTIType :
type CTIType string

// TechniqueSourceType :
type TechniqueSourceType string

// MitreAttackerType :
type MitreAttackerType string

// AttackSoftwareType :
type AttackSoftwareType string

var (
	// TechniqueType :
	TechniqueType CTIType = "Technique"
	// AttackerType :
	AttackerType CTIType = "Attacker"

	// MitreAttackType :
	MitreAttackType TechniqueSourceType = "MITRE-ATTACK"
	// CAPECType :
	CAPECType TechniqueSourceType = "CAPEC"

	// GroupType :
	GroupType MitreAttackerType = "Group"
	// SoftwareType :
	SoftwareType MitreAttackerType = "Software"
	// CampaignType :
	CampaignType MitreAttackerType = "Campaign"

	// MalwareType :
	MalwareType AttackSoftwareType = "Malware"
	// ToolType :
	ToolType AttackSoftwareType = "Tool"
)

// CveToTechniques :
type CveToTechniques struct {
	ID           int64              `json:"-"`
	CveID        string             `gorm:"type:varchar(255);index:idx_mapping_cve_id" json:"cve_id"`
	TechniqueIDs []CveToTechniqueID `json:"technique_ids"`
}

// CveToTechniqueID :
type CveToTechniqueID struct {
	ID                int64  `json:"-"`
	CveToTechniquesID int64  `json:"-"`
	TechniqueID       string `gorm:"type:varchar(255)" json:"technique_id"`
}

// Technique : Cyber Threat Intelligence
type Technique struct {
	ID          int64                `json:"-"`
	TechniqueID string               `gorm:"type:varchar(255)" json:"technique_id"`
	Type        TechniqueSourceType  `gorm:"type:varchar(255)" json:"type"`
	Name        string               `gorm:"type:varchar(255)" json:"name"`
	Description string               `gorm:"type:text" json:"description"`
	References  []TechniqueReference `json:"references"`
	Mitigations []Mitigation         `json:"mitigations"`
	MitreAttack *MitreAttack         `json:"mitre_attack"`
	Capec       *Capec               `json:"capec"`
	Created     time.Time            `json:"created"`
	Modified    time.Time            `json:"modified"`
}

// Reference is Child model of Technique
type Reference struct {
	SourceName  string `gorm:"type:varchar(255)" json:"source_name"`
	Description string `gorm:"type:text" json:"description"`
	URL         string `gorm:"type:text" json:"url"`
}

// TechniqueReference is Child model of Technique
type TechniqueReference struct {
	ID          int64 `json:"-"`
	TechniqueID int64 `gorm:"index:idx_technique_reference_technique_id" json:"-"`
	Reference   `gorm:"embedded"`
}

// Mitigation is Child model of Technique
type Mitigation struct {
	ID          int64  `json:"-"`
	TechniqueID int64  `gorm:"index:idx_mitigation_technique_id" json:"-"`
	Name        string `gorm:"type:text" json:"name"`
	Description string `gorm:"type:text" json:"description"`
}

// MitreAttack is Child model of Technique
type MitreAttack struct {
	ID                   int64                 `json:"-"`
	TechniqueID          int64                 `gorm:"index:idx_mitre_attack_technique_id" json:"-"`
	CapecIDs             []CapecID             `json:"capec_ids"`
	Detection            string                `gorm:"type:text" json:"detection"`
	KillChainPhases      []KillChainPhase      `json:"kill_chain_phases"`
	DataSources          []DataSource          `json:"data_sources"`
	Procedures           []Procedure           `json:"procedures"`
	Platforms            []TechniquePlatform   `json:"platforms"`
	PermissionsRequired  []PermissionRequired  `json:"permissions_required"`
	EffectivePermissions []EffectivePermission `json:"effective_permissions"`
	DefenseBypassed      []DefenseBypassed     `json:"defense_bypassed"`
	ImpactType           []ImpactType          `json:"impact_type"`
	NetworkRequirements  bool                  `json:"network_requirements"`
	RemoteSupport        bool                  `json:"remote_support"`
	SubTechniques        []SubTechnique        `json:"sub_techniques"`
}

// CapecID is Child model of MitreAttack
type CapecID struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_capec_id_mitre_attack_id" json:"-"`
	CapecID       string `gorm:"type:varchar(255)" json:"capec_id"`
}

// KillChainPhase is Child model of MitreAttack
type KillChainPhase struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_kill_chain_phase_mitre_attack_id" json:"-"`
	Tactic        string `gorm:"type:varchar(255)" json:"tactic"`
}

// DataSource is Child model of MitreAttack
type DataSource struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_data_source_mitre_attack_id" json:"-"`
	Name          string `gorm:"type:varchar(255)" json:"name"`
	Description   string `gorm:"type:text" json:"description"`
}

// Procedure is Child model of MitreAttack
type Procedure struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_procedure_mitre_attack_id" json:"-"`
	Name          string `gorm:"type:varchar(255)" json:"name"`
	Description   string `gorm:"type:text" json:"description"`
}

// TechniquePlatform is Child model of MitreAttack
type TechniquePlatform struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_technique_platform_mitre_attack_id" json:"-"`
	Platform      string `gorm:"type:varchar(255)" json:"platform"`
}

// PermissionRequired is Child model of MitreAttack
type PermissionRequired struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_permission_required_mitre_attack_id" json:"-"`
	Permission    string `gorm:"type:varchar(255)" json:"permission"`
}

// EffectivePermission is Child model of MitreAttack
type EffectivePermission struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_effective_permission_mitre_attack_id" json:"-"`
	Permission    string `gorm:"type:varchar(255)" json:"permission"`
}

// DefenseBypassed is Child model of MitreAttack
type DefenseBypassed struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_defense_bypassed_mitre_attack_id" json:"-"`
	Defense       string `gorm:"type:varchar(255)" json:"defense"`
}

// ImpactType is Child model of MitreAttack
type ImpactType struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_impact_type_mitre_attack_id" json:"-"`
	Type          string `gorm:"type:varchar(255)" json:"type"`
}

// SubTechnique is Child model of MitreAttack
type SubTechnique struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_sub_technique_mitre_attack_id" json:"-"`
	Name          string `gorm:"type:varchar(255)" json:"name"`
}

// Capec is Child model of Technique
type Capec struct {
	ID                  int64              `json:"-"`
	TechniqueID         int64              `gorm:"index:idx_capec_technique_id" json:"-"`
	AttackIDs           []AttackID         `json:"attack_ids"`
	Status              string             `gorm:"type:varchar(255)" json:"status"`
	ExtendedDescription string             `gorm:"type:text" json:"extended_description"`
	TypicalSeverity     string             `gorm:"type:varchar(255)" json:"typical_severity"`
	LikelihoodOfAttack  string             `gorm:"type:varchar(255)" json:"likelihood_of_attack"`
	Relationships       []Relationship     `json:"relationship"`
	Domains             []Domain           `json:"domains"`
	AlternateTerms      []AlternateTerm    `json:"alternate_terms"`
	ExampleInstances    []ExampleInstance  `json:"example_instances"`
	Prerequisites       []Prerequisite     `json:"prerequisites"`
	ResourcesRequired   []ResourceRequired `json:"resources_required"`
	SkillsRequired      []SkillRequired    `json:"skills_required"`
	Abstraction         string             `gorm:"type:varchar(255)" json:"abstraction"`
	ExecutionFlow       string             `gorm:"type:text" json:"execution_flow"`
	Consequences        []Consequence      `json:"consequences"`
	RelatedWeaknesses   []RelatedWeakness  `json:"related_weaknesses"`
}

// AttackID is Child model of Capec
type AttackID struct {
	ID       int64  `json:"-"`
	CapecID  int64  `gorm:"index:idx_attack_id_capec_id" json:"-"`
	AttackID string `gorm:"type:varchar(255)" json:"capec_id"`
}

// Relationship is Child model of Capec
type Relationship struct {
	ID       int64  `json:"-"`
	CapecID  int64  `gorm:"index:idx_relationship_capec_id" json:"-"`
	Nature   string `gorm:"type:varchar(255)" json:"nature"`
	Relation string `gorm:"type:varchar(255)" json:"relation"`
}

// Domain is Child model of Capec
type Domain struct {
	ID      int64  `json:"-"`
	CapecID int64  `gorm:"index:idx_domain_capec_id" json:"-"`
	Domain  string `gorm:"type:varchar(255)" json:"domain"`
}

// AlternateTerm is Child model of Capec
type AlternateTerm struct {
	ID      int64  `json:"-"`
	CapecID int64  `gorm:"index:idx_alternate_term_capec_id" json:"-"`
	Term    string `gorm:"type:varchar(255)" json:"term"`
}

// ExampleInstance is Child model of Capec
type ExampleInstance struct {
	ID       int64  `json:"-"`
	CapecID  int64  `gorm:"index:idx_example_instance_capec_id" json:"-"`
	Instance string `gorm:"type:text" json:"instance"`
}

// Prerequisite is Child model of Capec
type Prerequisite struct {
	ID           int64  `json:"-"`
	CapecID      int64  `gorm:"index:idx_prerequisite_capec_id" json:"-"`
	Prerequisite string `gorm:"type:text" json:"prerequisite"`
}

// ResourceRequired is Child model of Capec
type ResourceRequired struct {
	ID       int64  `json:"-"`
	CapecID  int64  `gorm:"index:idx_resource_required_capec_id" json:"-"`
	Resource string `gorm:"type:text" json:"prerequisite"`
}

// SkillRequired is Child model of Capec
type SkillRequired struct {
	ID      int64  `json:"-"`
	CapecID int64  `gorm:"index:idx_skill_required_capec_id" json:"-"`
	Skill   string `gorm:"type:text" json:"skill"`
}

// Consequence is Child model of Capec
type Consequence struct {
	ID          int64  `json:"-"`
	CapecID     int64  `gorm:"index:idx_consequence_capec_id" json:"-"`
	Consequence string `gorm:"type:text" json:"consequence"`
}

// RelatedWeakness is Child model of Capec
type RelatedWeakness struct {
	ID      int64  `json:"-"`
	CapecID int64  `gorm:"index:idx_related_weakness_capec_id" json:"-"`
	CweID   string `gorm:"type:varchar(255)" json:"cwe_id"`
}

// Attacker : MITRE ATT&CK Group and Software
type Attacker struct {
	ID             int64               `json:"-"`
	AttackerID     string              `gorm:"type:varchar(255)" json:"attacker_id"`
	Type           MitreAttackerType   `gorm:"type:varchar(255)" json:"type"`
	Name           string              `gorm:"type:varchar(255)" json:"name"`
	Description    string              `gorm:"type:text" json:"description"`
	TechniquesUsed []TechniqueUsed     `json:"techniques_used"`
	References     []AttackerReference `json:"references"`
	Group          *AttackerGroup      `json:"group"`
	Software       *AttackerSoftware   `json:"software"`
	// Campaign       *AttackerCampaign   `json:"campaign"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

// TechniqueUsed is Child model of Attacker
type TechniqueUsed struct {
	ID          int64  `json:"-"`
	AttackerID  int64  `gorm:"index:idx_technique_used_attacker_id" json:"-"`
	TechniqueID string `gorm:"type:varchar(255)" json:"technique_id"`
	Name        string `gorm:"type:varchar(255)" json:"name"`
	Use         string `gorm:"type:text" json:"use"`
}

// AttackerReference is Child model of Attacker
type AttackerReference struct {
	ID         int64 `json:"-"`
	AttackerID int64 `gorm:"index:idx_attacker_reference_attacker_id" json:"-"`
	Reference  `gorm:"embedded"`
}

// AttackerGroup is Child model of Attacker
type AttackerGroup struct {
	ID               int64             `json:"-"`
	AttackerID       int64             `gorm:"index:idx_attacker_group_attacker_id" json:"-"`
	AssociatedGroups []AssociatedGroup `json:"associated_group"`
	SoftwaresUsed    []SoftwareUsed    `json:"softwares_used"`
}

// AssociatedGroup is Child models of Group
type AssociatedGroup struct {
	ID              int64  `json:"-"`
	AttackerGroupID int64  `gorm:"index:idx_associated_group_attacker_group_id" json:"-"`
	Name            string `gorm:"type:varchar(255)" json:"name"`
	Description     string `gorm:"type:text" json:"description"`
}

// SoftwareUsed is Child models of Group
type SoftwareUsed struct {
	ID              int64  `json:"-"`
	AttackerGroupID int64  `gorm:"index:idx_software_used_attacker_group_id" json:"-"`
	Name            string `gorm:"type:varchar(255)" json:"name"`
	Description     string `gorm:"type:text" json:"description"`
}

// AttackerSoftware is Child model of Attacker
type AttackerSoftware struct {
	ID                  int64                `json:"-"`
	AttackerID          int64                `gorm:"index:idx_attacker_software_attacker_id" json:"-"`
	Type                AttackSoftwareType   `gorm:"type:varchar(255)" json:"type"`
	AssociatedSoftwares []AssociatedSoftware `json:"associated_softwares"`
	Platforms           []SoftwarePlatform   `json:"platforms"`
	GroupsUsed          []GroupUsed          `json:"groups_used"`
}

// AssociatedSoftware is Child models of Software
type AssociatedSoftware struct {
	ID                 int64  `json:"-"`
	AttackerSoftwareID int64  `gorm:"index:idx_associated_software_attacker_software_id" json:"-"`
	Name               string `gorm:"type:varchar(255)" json:"name"`
	Description        string `gorm:"type:text" json:"description"`
}

// SoftwarePlatform is Child models of Software
type SoftwarePlatform struct {
	ID                 int64  `json:"-"`
	AttackerSoftwareID int64  `gorm:"index:idx_software_platform_attacker_software_id" json:"-"`
	Platform           string `gorm:"type:varchar(255)" json:"platform"`
}

// GroupUsed is Child models of Software
type GroupUsed struct {
	ID                 int64  `json:"-"`
	AttackerSoftwareID int64  `gorm:"index:idx_group_used_attacker_software_id" json:"-"`
	Name               string `gorm:"type:varchar(255)" json:"name"`
	Description        string `gorm:"type:text" json:"description"`
}

// type AttackerCampaign struct {
// 	ID         int64                      `json:"-"`
// 	AttackerID int64                      `gorm:"index:idx_attacker_campaign_attacker_id" json:"-"`
// 	Softwares  []AttackerCampaignSoftware `json:"softwares"`
// 	Groups     []AttackerCampaignGroup    `json:"groups"`
// }

// type AttackerCampaignSoftware struct {
// 	ID                 int64  `json:"-"`
// 	AttackerCampaignID int64  `gorm:"index:idx_attacker_campaign_software_attacker_campaign_id" json:"-"`
// 	Name               string `gorm:"type:varchar(255)" json:"name"`
// 	Description        string `gorm:"type:text" json:"description"`
// }

// type AttackerCampaignGroup struct {
// 	ID                 int64  `json:"-"`
// 	AttackerCampaignID int64  `gorm:"index:idx_attacker_campaign_group_attacker_campaign_id" json:"-"`
// 	Name               string `gorm:"type:varchar(255)" json:"name"`
// 	Description        string `gorm:"type:text" json:"description"`
// }

// CTI for response
type CTI struct {
	Type      CTIType    `json:"type"`
	Technique *Technique `json:"technique,omitempty"`
	Attacker  *Attacker  `json:"attacker,omitempty"`
}
