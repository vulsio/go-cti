package db

import (
	"fmt"

	"github.com/cheggaaa/pb"
	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	sqlite3 "github.com/mattn/go-sqlite3"

	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	// Required SQLite3.
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

const (
	dialectSqlite3    = "sqlite3"
	dialectMysql      = "mysql"
	dialectPostgreSQL = "postgres"
)

// RDBDriver :
type RDBDriver struct {
	name string
	conn *gorm.DB
}

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	r.conn, err = gorm.Open(dbType, dbPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, fmt.Errorf(msg)
			}
		}
		return false, fmt.Errorf(msg)
	}
	r.conn.LogMode(debugSQL)
	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if err = r.conn.Close(); err != nil {
		return fmt.Errorf("Failed to close DB. Type: %s. err: %s", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.Cti{},
		&models.Capec{},
		&models.KillChain{},
		&models.Reference{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	var errs gorm.Errors
	errs = errs.Add(r.conn.Model(&models.Cti{}).AddIndex("idx_cti_cve_id", "cve_id").Error)

	for _, e := range errs {
		if e != nil {
			return fmt.Errorf("Failed to create index. err: %s", e)
		}
	}
	return nil
}

// InsertCti :
func (r *RDBDriver) InsertCti(records []*models.Cti) (err error) {
	log15.Info("Inserting Threat Intelligences having CVEs...")
	return r.deleteAndInsertCti(r.conn, records)
}

func (r *RDBDriver) deleteAndInsertCti(conn *gorm.DB, records []*models.Cti) (err error) {
	bar := pb.StartNew(len(records))
	tx := conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// select old record
	old := models.Cti{}
	result := tx.Where(&models.Cti{}).First(&old)
	if !result.RecordNotFound() {
		// Delete all old records
		var errs gorm.Errors
		errs = errs.Add(tx.Unscoped().Delete(models.Capec{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(models.KillChain{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(models.Reference{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(models.Cti{}).Error)
		errs = utils.DeleteNil(errs)
		if len(errs.GetErrors()) > 0 {
			return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
		}
	}

	for _, record := range records {
		if err = tx.Create(record).Error; err != nil {
			return fmt.Errorf("Failed to insert. err: %s", err)
		}
		bar.Increment()
	}
	bar.Finish()
	log15.Info("CveID mitre/cti Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RDBDriver) GetModuleByCveID(cveID string) []*models.Cti {
	cti := []*models.Cti{}
	var errs gorm.Errors

	errs = errs.Add(r.conn.Where(&models.Cti{CveID: cveID}).Find(&cti).Error)
	for _, m := range cti {
		errs = errs.Add(r.conn.Model(&m).Related(&m.References, "references").Error)
	}

	for _, e := range errs.GetErrors() {
		if !gorm.IsRecordNotFoundError(e) {
			log15.Error("Failed to get module info by CVE", "err", e)
		}
	}
	return cti
}
