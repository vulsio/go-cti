package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// LastUpdated :
type LastUpdated struct {
	Date time.Time
}

// Cti :
type Cti struct {
	gorm.Model  `json:"-" xml:"-"`
	Name        string
	Description string
	CveID       string
	References  []Reference `json:",omitempty" gorm:"many2many:cti_refs;"`
}

// Reference is Child model of ...
type Reference struct {
	ID   uint   `json:",omitempty"`
	Link string `sql:"type:text"`
}
