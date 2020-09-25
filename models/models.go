package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// LastUpdated :
type LastUpdated struct {
	Date time.Time
}

// Cti : Cyber Threat Intelligence
type Cti struct {
	gorm.Model  `json:"-" xml:"-"`
	Name        string
	Description string
	CveID       string
	KillChains  []KillChain `json:",omitempty" gorm:"many2many:cti_kills;"`
	References  []Reference `json:",omitempty" gorm:"many2many:cti_refs;"`
}

// KillChain is Child model of Cti
type KillChain struct {
	ID    uint `json:",omitempty"`
	Name  string
	Phase string
}

// Reference is Child model of Cti
type Reference struct {
	ID          uint `json:",omitempty"`
	ExternalID  string
	Link        string `sql:"type:text"`
	Description string `sql:"type:text"`
}
