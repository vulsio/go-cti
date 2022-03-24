package models

import (
	"time"
)

// LastUpdated :
type LastUpdated struct {
	Date time.Time
}

// Cti : Cyber Threat Intelligence
type Cti struct {
	ID       int64 `gorm:"primary_key"`
	Name        string
	Type        string
	Description string
	CveID       string
	Capec       *Capec
	KillChains  []KillChain
	References  []Reference
	// PublishedDate    time.Time
	// LastModifiedDate time.Time
}

// Capec is Child model of Cti
type Capec struct {
	ID       int64 `gorm:"primary_key"`
	CtiID    int64 `sql:"type:bigint REFERENCES ctis(id)"`
	Abstruct string
	Status   string
	Severity string
	Terms    string
	Version  string
}

// KillChain is Child model of Cti
type KillChain struct {
	ID       int64 `gorm:"primary_key"`
	CtiID    int64 `sql:"type:bigint REFERENCES ctis(id)"`
	Name  string
	Phase string
}

// Reference is Child model of Cti
type Reference struct {
	ID       int64 `gorm:"primary_key"`
	CtiID    int64 `sql:"type:bigint REFERENCES ctis(id)"`
	ExternalID  string
	Link        string `sql:"type:text"`
	Description string `sql:"type:text"`
}
