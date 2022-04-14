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

var (
	// MitreAttackType :
	MitreAttackType CTIType = "MITRE-ATTACK"
	// CAPECType :
	CAPECType CTIType = "CAPEC"
)

// Mapping :
type Mapping struct {
	ID     int64   `json:"-"`
	CveID  string  `gorm:"type:varchar(255);index:idx_mapping_cve_id" json:"cve_id"`
	CtiIDs []CtiID `json:"cti_ids"`
}

// CtiID :
type CtiID struct {
	ID        int64  `json:"-"`
	MappingID int64  `json:"-"`
	CtiID     string `gorm:"type:varchar(255)" json:"cti_id"`
}

// Cti : Cyber Threat Intelligence
type Cti struct {
	ID          int64        `json:"-"`
	CtiID       string       `gorm:"type:varchar(255)" json:"cti_id"`
	Type        CTIType      `gorm:"type:varchar(255)" json:"type"`
	Name        string       `gorm:"type:varchar(255)" json:"name"`
	Description string       `gorm:"type:text" json:"description"`
	References  []Reference  `json:"references"`
	Mitigations []Mitigation `json:"mitigations"`
	MitreAttack *MitreAttack `json:"mitre_attack"`
	Capec       *Capec       `json:"capec"`
	Created     time.Time    `json:"created"`
	Modified    time.Time    `json:"modified"`
}

// Reference is Child model of Cti
type Reference struct {
	ID          int64  `json:"-"`
	CtiID       int64  `gorm:"index:idx_reference_cti_id" json:"-"`
	SourceName  string `gorm:"type:varchar(255)" json:"source_name"`
	Description string `gorm:"type:text" json:"description"`
	URL         string `gorm:"type:text" json:"url"`
}

// Mitigation is Child model of Cti
type Mitigation struct {
	ID          int64  `json:"-"`
	CtiID       int64  `gorm:"index:idx_mitigation_cti_id" json:"-"`
	Name        string `gorm:"type:text" json:"name"`
	Description string `gorm:"type:text" json:"description"`
}

// MitreAttack is Child model of Cti
type MitreAttack struct {
	ID                   int64          `json:"-"`
	CtiID                int64          `gorm:"index:idx_mitre_attack_cti_id" json:"-"`
	CapecIDs             []CapecID      `json:"capec_ids"`
	Detection            string         `gorm:"type:text" json:"detection"`
	KillChainPhases      string         `gorm:"type:varchar(255)" json:"kill_chain_phases"`
	DataSources          []DataSource   `json:"data_sources"`
	Procedures           []Procedure    `json:"procedures"`
	Platforms            string         `gorm:"type:varchar(255)" json:"platforms"`
	PermissionsRequired  string         `gorm:"type:varchar(255)" json:"permissions_required"`
	EffectivePermissions string         `gorm:"type:varchar(255)" json:"effective_permissions"`
	DefenseBypassed      string         `gorm:"type:varchar(255)" json:"defense_bypassed"`
	ImpactType           string         `gorm:"type:varchar(255)" json:"impact_type"`
	NetworkRequirements  bool           `json:"network_requirements"`
	RemoteSupport        bool           `json:"remote_support"`
	SubTechniques        []SubTechnique `json:"sub_techniques"`
}

// CapecID is Child model of MitreAttack
type CapecID struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_capec_id_mitre_attack_id" json:"-"`
	CapecID       string `gorm:"type:varchar(255)" json:"capec_id"`
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

// SubTechnique is Child model of MitreAttack
type SubTechnique struct {
	ID            int64  `json:"-"`
	MitreAttackID int64  `gorm:"index:idx_sub_technique_mitre_attack_id" json:"-"`
	Name          string `gorm:"type:varchar(255)" json:"name"`
}

// Capec is Child model of Cti
type Capec struct {
	ID                  int64             `json:"-"`
	CtiID               int64             `gorm:"index:idx_capec_cti_id" json:"-"`
	AttackIDs           []AttackID        `json:"attack_ids"`
	Status              string            `gorm:"type:varchar(255)" json:"status"`
	ExtendedDescription string            `gorm:"type:text" json:"extended_description"`
	TypicalSeverity     string            `gorm:"type:varchar(255)" json:"typical_severity"`
	LikelihoodOfAttack  string            `gorm:"type:varchar(255)" json:"likelihood_of_attack"`
	Relationships       []Relationship    `json:"relationship"`
	Domains             string            `gorm:"type:varchar(255)" json:"domains"`
	AlternateTerms      string            `gorm:"type:varchar(255)" json:"alternate_terms"`
	ExampleInstances    string            `gorm:"type:text" json:"example_instances"`
	Prerequisites       string            `gorm:"type:text" json:"prerequisites"`
	ResourcesRequired   string            `gorm:"type:text" json:"resources_required"`
	SkillsRequired      []SkillRequired   `json:"skills_required"`
	Abstraction         string            `gorm:"type:varchar(255)" json:"abstraction"`
	ExecutionFlow       string            `gorm:"type:text" json:"execution_flow"`
	Consequences        []Consequence     `json:"consequences"`
	RelatedWeaknesses   []RelatedWeakness `json:"related_weaknesses"`
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
