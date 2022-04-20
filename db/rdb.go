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
		&models.ImapctType{},
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
		models.SubTechnique{}, models.ImapctType{}, models.DefenseBypassed{}, models.EffectivePermission{}, models.PermissionRequired{}, models.TechniquePlatform{}, models.Procedure{}, models.DataSource{}, models.KillChainPhase{}, models.CapecID{}, models.MitreAttack{},
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
	bar := pb.StartNew(len(techniques))
	for idx := range chunkSlice(len(techniques), batchSize) {
		if err = tx.Create(techniques[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting CVE-ID to CTI-ID CveToTechniques...")
	bar = pb.StartNew(len(mappings))
	for idx := range chunkSlice(len(mappings), batchSize) {
		if err = tx.Create(mappings[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting Attackers...")
	bar = pb.StartNew(len(attackers))
	for idx := range chunkSlice(len(attackers), batchSize) {
		if err = tx.Create(attackers[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
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
