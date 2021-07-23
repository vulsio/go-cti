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
	ID          int64 `json:",omitempty"`
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
	Abstruct string
	Status   string
	Severity string
	Terms    string
	Version  string
}

// KillChain is Child model of Cti
type KillChain struct {
	Name  string
	Phase string
}

// Reference is Child model of Cti
type Reference struct {
	ExternalID  string
	Link        string `sql:"type:text"`
	Description string `sql:"type:text"`
}
