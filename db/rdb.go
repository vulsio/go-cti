package db

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/vulsio/go-cti/config"
	"github.com/vulsio/go-cti/models"
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
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool, _ Option) (locked bool, err error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
	default:
		err = xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}

	if err != nil {
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
			}
		}
		return false, xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
	}

	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}

	var sqlDB *sql.DB
	if sqlDB, err = r.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	if err = sqlDB.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.FetchMeta{},

		&models.Mapping{},
		&models.CtiID{},

		&models.Cti{},
		&models.Reference{},
		&models.Mitigation{},

		&models.MitreAttack{},
		&models.CapecID{},
		&models.DataSource{},
		&models.Procedure{},
		&models.SubTechnique{},

		&models.Capec{},
		&models.AttackID{},
		&models.Relationship{},
		&models.SkillRequired{},
		&models.Consequence{},
		&models.RelatedWeakness{},
	); err != nil {
		return xerrors.Errorf("Failed to migrate. err: %w", err)
	}

	return nil
}

// IsGoCTIModelV1 determines if the DB was created at the time of go-cti Model v1
func (r *RDBDriver) IsGoCTIModelV1() (bool, error) {
	if r.conn.Migrator().HasTable(&models.FetchMeta{}) {
		return false, nil
	}

	var (
		count int64
		err   error
	)
	switch r.name {
	case dialectSqlite3:
		err = r.conn.Table("sqlite_master").Where("type = ?", "table").Count(&count).Error
	case dialectMysql:
		err = r.conn.Table("information_schema.tables").Where("table_schema = ?", r.conn.Migrator().CurrentDatabase()).Count(&count).Error
	case dialectPostgreSQL:
		err = r.conn.Table("pg_tables").Where("schemaname = ?", "public").Count(&count).Error
	}

	if count > 0 {
		return true, nil
	}
	return false, err
}

// GetFetchMeta get FetchMeta from Database
func (r *RDBDriver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = r.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GoCTIRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion, LastFetchedAt: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GoCTIRevision = config.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}

// InsertCti :
func (r *RDBDriver) InsertCti(ctis []models.Cti, mappings []models.Mapping) (err error) {
	return r.deleteAndInsertCti(r.conn, ctis, mappings)
}

func (r *RDBDriver) deleteAndInsertCti(conn *gorm.DB, ctis []models.Cti, mappings []models.Mapping) (err error) {
	tx := conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{
		models.RelatedWeakness{}, models.Consequence{}, models.SkillRequired{}, models.Relationship{}, models.Capec{},
		models.SubTechnique{}, models.DataSource{}, models.Procedure{}, models.MitreAttack{},
		models.Mitigation{}, models.Reference{}, models.Cti{},
		models.CtiID{}, models.Mapping{},
	} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return xerrors.New("Failed to set batch-size. err: batch-size option is not set properly")
	}

	log15.Info("Inserting Cyber Threat Intelligences...")
	bar := pb.StartNew(len(ctis))
	for idx := range chunkSlice(len(ctis), batchSize) {
		if err = tx.Create(ctis[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting CVE-ID to CTI-ID Mappings...")
	bar = pb.StartNew(len(mappings))
	for idx := range chunkSlice(len(mappings), batchSize) {
		if err = tx.Create(mappings[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	return nil
}

// GetCtiByCveID :
func (r *RDBDriver) GetCtiByCveID(cveID string) ([]models.Cti, error) {
	mappings := []models.Mapping{}
	if err := r.conn.
		Preload("CtiIDs").
		Where(&models.Mapping{CveID: cveID}).
		Find(&mappings).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get CTI-IDs by CVE-ID. err: %w", err)
	}
	if len(mappings) == 0 {
		return []models.Cti{}, nil
	}

	allCTIs := []models.Cti{}
	for _, mapping := range mappings {
		for _, ctiID := range mapping.CtiIDs {
			ctis := []models.Cti{}
			if err := r.conn.
				Preload("References").
				Preload("Mitigations").
				Where(&models.Cti{CtiID: ctiID.CtiID}).
				Find(&ctis).Error; err != nil {
				return nil, xerrors.Errorf("Failed to get CTI by CVE-ID. err: %w", err)
			}
			for i := range ctis {
				switch ctis[i].Type {
				case models.MitreAttackType:
					if err := r.conn.
						Preload(clause.Associations).
						Where(&models.MitreAttack{CtiID: ctis[i].ID}).
						Take(&ctis[i].MitreAttack).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							return nil, xerrors.Errorf("Failed to get MitreAttack. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
						}
						return nil, xerrors.Errorf("Failed to get MitreAttack. err: %w", err)
					}
				case models.CAPECType:
					if err := r.conn.
						Preload(clause.Associations).
						Where(&models.Capec{CtiID: ctis[i].ID}).
						Take(&ctis[i].Capec).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							return nil, xerrors.Errorf("Failed to get Capec. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
						}
						return nil, xerrors.Errorf("Failed to get Capec. err: %w", err)
					}
				}
			}
			allCTIs = append(allCTIs, ctis...)
		}
	}
	return allCTIs, nil
}

// GetCtiByMultiCveID :
func (r *RDBDriver) GetCtiByMultiCveID(cveIDs []string) (map[string][]models.Cti, error) {
	ctis := map[string][]models.Cti{}
	for _, cveID := range cveIDs {
		c, err := r.GetCtiByCveID(cveID)
		if err != nil {
			return nil, xerrors.Errorf("Failed to get CTI by CVE-ID. err: %w", err)
		}
		ctis[cveID] = c
	}
	return ctis, nil
}
