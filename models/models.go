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

// Cti : Cyber Threat Intelligence
type Cti struct {
	ID               int64  `json:"-"`
	Name             string `gorm:"type:varchar(255)" json:"name"`
	Type             string `gorm:"type:varchar(255)" json:"type"`
	Description      string `gorm:"type:text" json:"description"`
	CveID            string `gorm:"index:idx_cti_cve_id;type:varchar(255)" json:"cveID"`
	Capec            Capec
	KillChains       []KillChain
	References       []Reference
	PublishedDate    time.Time `gorm:"type:date" json:"publishedDate"`
	LastModifiedDate time.Time `gorm:"type:date" json:"lastModifiedDate"`
}

// Capec is Child model of Cti
type Capec struct {
	ID       int64  `json:"-"`
	CtiID    int64  `json:"-" gorm:"index:idx_capes_cti_id"`
	Abstruct string `gorm:"type:varchar(255)" json:"abstruct"`
	Status   string `gorm:"type:varchar(255)" json:"status"`
	Severity string `gorm:"type:varchar(255)" json:"severity"`
	Terms    string `gorm:"type:varchar(255)" json:"terms"`
	Version  string `gorm:"type:varchar(255)" json:"version"`
}

// KillChain is Child model of Cti
type KillChain struct {
	ID    int64  `json:"-"`
	CtiID int64  `json:"-" gorm:"index:idx_kill_chain_cti_id"`
	Name  string `gorm:"type:varchar(255)" json:"name"`
	Phase string `gorm:"type:varchar(255)" json:"phase"`
}

// Reference is Child model of Cti
type Reference struct {
	ID          int64  `json:"-"`
	CtiID       int64  `json:"-" gorm:"index:idx_reference_cti_id"`
	ExternalID  string `gorm:"type:varchar(255)" json:"name"`
	Link        string `gorm:"type:varchar(255)" json:"link"`
	Description string `gorm:"type:text" json:"description"`
}
