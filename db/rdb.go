package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"slices"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/glebarez/sqlite"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
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

// https://github.com/mattn/go-sqlite3/blob/edc3bb69551dcfff02651f083b21f3366ea2f5ab/error.go#L18-L66
type errNo int

type sqliteError struct {
	Code errNo /* The error code returned by SQLite */
}

// result codes from http://www.sqlite.org/c3ref/c_abort.html
var (
	errBusy   = errNo(5) /* The database file is locked */
	errLocked = errNo(6) /* A table in the database is locked */
)

// ErrDBLocked :
var ErrDBLocked = xerrors.New("database is locked")

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool, _ Option) (err error) {
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
		if err != nil {
			parsedErr, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
			}

			var errMsg sqliteError
			if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
				return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
			}

			switch errMsg.Code {
			case errBusy, errLocked:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, ErrDBLocked)
			default:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
			}
		}

		r.conn.Exec("PRAGMA foreign_keys = ON")
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	default:
		return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}
	return nil
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

		&models.CveToTechniques{},
		&models.CveToTechniqueID{},

		&models.Technique{},
		&models.TechniqueReference{},
		&models.Mitigation{},

		&models.MitreAttack{},
		&models.CapecID{},
		&models.KillChainPhase{},
		&models.DataSource{},
		&models.Procedure{},
		&models.TechniquePlatform{},
		&models.PermissionRequired{},
		&models.EffectivePermission{},
		&models.DefenseBypassed{},
		&models.ImpactType{},
		&models.SubTechnique{},

		&models.Capec{},
		&models.AttackID{},
		&models.Relationship{},
		&models.Domain{},
		&models.AlternateTerm{},
		&models.ExampleInstance{},
		&models.Prerequisite{},
		&models.ResourceRequired{},
		&models.SkillRequired{},
		&models.Consequence{},
		&models.RelatedWeakness{},

		&models.Attacker{},
		&models.TechniqueUsed{},
		&models.AttackerReference{},

		&models.AttackerGroup{},
		&models.AssociatedGroup{},
		&models.SoftwareUsed{},

		&models.AttackerSoftware{},
		&models.AssociatedSoftware{},
		&models.SoftwarePlatform{},
		&models.GroupUsed{},
	); err != nil {
		switch r.name {
		case dialectSqlite3:
			if r.name == dialectSqlite3 {
				parsedErr, marshalErr := json.Marshal(err)
				if marshalErr != nil {
					return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
				}

				var errMsg sqliteError
				if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
					return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
				}

				switch errMsg.Code {
				case errBusy, errLocked:
					return xerrors.Errorf("Failed to migrate. err: %w", ErrDBLocked)
				default:
					return xerrors.Errorf("Failed to migrate. err: %w", err)
				}
			}
		case dialectMysql, dialectPostgreSQL:
			return xerrors.Errorf("Failed to migrate. err: %w", err)
		default:
			return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
		}
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
func (r *RDBDriver) InsertCti(techniques []models.Technique, mappings []models.CveToTechniques, attackers []models.Attacker) (err error) {
	return r.deleteAndInsertCti(r.conn, techniques, mappings, attackers)
}

func (r *RDBDriver) deleteAndInsertCti(conn *gorm.DB, techniques []models.Technique, mappings []models.CveToTechniques, attackers []models.Attacker) (err error) {
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
		models.GroupUsed{}, models.SoftwarePlatform{}, models.AssociatedSoftware{}, models.AttackerSoftware{},
		models.SoftwareUsed{}, models.AssociatedGroup{}, models.AttackerGroup{},
		models.AttackerReference{}, models.TechniqueUsed{}, models.Attacker{},
		models.RelatedWeakness{}, models.Consequence{}, models.SkillRequired{}, models.ResourceRequired{}, models.Prerequisite{}, models.ExampleInstance{}, models.AlternateTerm{}, models.Domain{}, models.Relationship{}, models.AttackID{}, models.Capec{},
		models.SubTechnique{}, models.ImpactType{}, models.DefenseBypassed{}, models.EffectivePermission{}, models.PermissionRequired{}, models.TechniquePlatform{}, models.Procedure{}, models.DataSource{}, models.KillChainPhase{}, models.CapecID{}, models.MitreAttack{},
		models.Mitigation{}, models.TechniqueReference{}, models.Technique{},
		models.CveToTechniqueID{}, models.CveToTechniques{},
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

	log15.Info("Inserting Techniques...")
	bar := pb.StartNew(len(techniques)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	for chunk := range slices.Chunk(techniques, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()

	log15.Info("Inserting CVE-ID to CTI-ID CveToTechniques...")
	bar = pb.StartNew(len(mappings)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	for chunk := range slices.Chunk(mappings, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()

	log15.Info("Inserting Attackers...")
	bar = pb.StartNew(len(attackers)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	for chunk := range slices.Chunk(attackers, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()

	return nil
}

// GetCtiByCtiID :
func (r *RDBDriver) GetCtiByCtiID(ctiID string) (models.CTI, error) {
	techniqueIDs, attackerIDs, err := classCtiIDs([]string{ctiID})
	if err != nil {
		return models.CTI{}, xerrors.Errorf("Failed to classCtiIDs. err: %w", err)
	}

	cti := models.CTI{}
	if len(techniqueIDs) > 0 {
		cti.Type = models.TechniqueType

		if err := r.conn.
			Preload("References").
			Preload("Mitigations").
			Where(&models.Technique{TechniqueID: techniqueIDs[0]}).
			Take(&cti.Technique).Error; err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to get Technique by CTI-ID. err: %w", err)
		}

		switch cti.Technique.Type {
		case models.MitreAttackType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.MitreAttack{TechniqueID: cti.Technique.ID}).
				Take(&cti.Technique.MitreAttack).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return models.CTI{}, xerrors.Errorf("Failed to get MitreAttack. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return models.CTI{}, xerrors.Errorf("Failed to get MitreAttack. err: %w", err)
			}
		case models.CAPECType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.Capec{TechniqueID: cti.Technique.ID}).
				Take(&cti.Technique.Capec).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return models.CTI{}, xerrors.Errorf("Failed to get Capec. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return models.CTI{}, xerrors.Errorf("Failed to get Capec. err: %w", err)
			}
		}
	} else {
		cti.Type = models.AttackerType

		if err := r.conn.
			Preload("TechniquesUsed").
			Preload("References").
			Where("attacker_id IN ?", attackerIDs).
			Take(&cti.Attacker).Error; err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to get Attacker by CTI-ID. err: %w", err)
		}

		switch cti.Attacker.Type {
		case models.GroupType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.AttackerGroup{AttackerID: cti.Attacker.ID}).
				Take(&cti.Attacker.Group).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return models.CTI{}, xerrors.Errorf("Failed to get Group. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return models.CTI{}, xerrors.Errorf("Failed to get Group. err: %w", err)
			}
		case models.SoftwareType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.AttackerSoftware{AttackerID: cti.Attacker.ID}).
				Take(&cti.Attacker.Software).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return models.CTI{}, xerrors.Errorf("Failed to get Software. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return models.CTI{}, xerrors.Errorf("Failed to get Software. err: %w", err)
			}
		}
	}

	return cti, nil
}

// GetCtisByMultiCtiID :
func (r *RDBDriver) GetCtisByMultiCtiID(ctiIDs []string) ([]models.CTI, error) {
	techniqueIDs, attackerIDs, err := classCtiIDs(ctiIDs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to classCtiIDs. err: %w", err)
	}

	ctis := []models.CTI{}

	techniques := []models.Technique{}
	if err := r.conn.
		Preload("References").
		Preload("Mitigations").
		Where("technique_id IN ?", techniqueIDs).
		Find(&techniques).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get Techniques by CTI-IDs. err: %w", err)
	}
	for i := range techniques {
		switch techniques[i].Type {
		case models.MitreAttackType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.MitreAttack{TechniqueID: techniques[i].ID}).
				Take(&techniques[i].MitreAttack).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, xerrors.Errorf("Failed to get MitreAttack. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return nil, xerrors.Errorf("Failed to get MitreAttack. err: %w", err)
			}
		case models.CAPECType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.Capec{TechniqueID: techniques[i].ID}).
				Take(&techniques[i].Capec).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, xerrors.Errorf("Failed to get Capec. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return nil, xerrors.Errorf("Failed to get Capec. err: %w", err)
			}
		}
		ctis = append(ctis, models.CTI{
			Type:      models.TechniqueType,
			Technique: &techniques[i],
		})
	}

	attackers := []models.Attacker{}
	if err := r.conn.
		Preload("TechniquesUsed").
		Preload("References").
		Where("attacker_id IN ?", attackerIDs).
		Find(&attackers).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get Attackers by CTI-IDs. err: %w", err)
	}

	for i := range attackers {
		switch attackers[i].Type {
		case models.GroupType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.AttackerGroup{AttackerID: attackers[i].ID}).
				Take(&attackers[i].Group).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, xerrors.Errorf("Failed to get Group. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return nil, xerrors.Errorf("Failed to get Group. err: %w", err)
			}
		case models.SoftwareType:
			if err := r.conn.
				Preload(clause.Associations).
				Where(&models.AttackerSoftware{AttackerID: attackers[i].ID}).
				Take(&attackers[i].Software).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, xerrors.Errorf("Failed to get Software. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. err: %w", err)
				}
				return nil, xerrors.Errorf("Failed to get Software. err: %w", err)
			}
		}
		ctis = append(ctis, models.CTI{
			Type:     models.AttackerType,
			Attacker: &attackers[i],
		})
	}
	return ctis, nil
}

// GetTechniqueIDsByCveID :
func (r *RDBDriver) GetTechniqueIDsByCveID(cveID string) ([]string, error) {
	var mappingID int64
	if err := r.conn.
		Model(&models.CveToTechniques{}).
		Select("id").
		Where(&models.CveToTechniques{CveID: cveID}).
		Take(&mappingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []string{}, nil
		}
		return nil, xerrors.Errorf("Failed to get ID by CVE-ID. err: %w", err)
	}

	techniqueIDs := []string{}
	if err := r.conn.
		Model(&models.CveToTechniqueID{}).
		Select("technique_id").
		Where(&models.CveToTechniqueID{CveToTechniquesID: mappingID}).
		Find(&techniqueIDs).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get TechniqueIDs by ID. err: %w", err)
	}

	return techniqueIDs, nil
}

// GetTechniqueIDsByMultiCveID :
func (r *RDBDriver) GetTechniqueIDsByMultiCveID(cveIDs []string) (map[string][]string, error) {
	var mappings []models.CveToTechniques
	if err := r.conn.
		Preload("TechniqueIDs").
		Where("cve_id IN ?", cveIDs).
		Find(&mappings).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get TechniqueIDs by CVE-IDs. err: %w", err)
	}

	techniqueIDs := map[string][]string{}
	for _, mapping := range mappings {
		for _, techniqueID := range mapping.TechniqueIDs {
			techniqueIDs[mapping.CveID] = append(techniqueIDs[mapping.CveID], techniqueID.TechniqueID)
		}
	}

	return techniqueIDs, nil
}

// GetAttackerIDsByTechniqueIDs :
func (r *RDBDriver) GetAttackerIDsByTechniqueIDs(techniqueIDs []string) ([]string, error) {
	attackers := []models.Attacker{}
	if err := r.conn.
		Preload("TechniquesUsed").
		Find(&attackers).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get Attackers by TechniqueIDs. err: %w", err)
	}

	attackerIDs := []string{}
	for _, attacker := range attackers {
		if len(attacker.TechniquesUsed) == 0 {
			continue
		}

		attackerUsedTechniques := map[string]struct{}{}
		for _, attackerUsedTechnique := range attacker.TechniquesUsed {
			attackerUsedTechniques[attackerUsedTechnique.TechniqueID] = struct{}{}
		}

		for _, techniqueID := range techniqueIDs {
			delete(attackerUsedTechniques, techniqueID)
			if len(attackerUsedTechniques) == 0 {
				break
			}
		}
		if len(attackerUsedTechniques) == 0 {
			attackerIDs = append(attackerIDs, attacker.AttackerID)
		}
	}

	return attackerIDs, nil
}
