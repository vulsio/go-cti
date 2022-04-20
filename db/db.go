package db

import (
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/models"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool, option Option) (bool, error)
	MigrateDB() error
	CloseDB() error

	IsGoCTIModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	InsertCti([]models.Technique, []models.CveToTechniques, []models.Attacker) error
	GetCtiByCtiID(string) (models.CTI, error)
	GetCtisByMultiCtiID([]string) ([]models.CTI, error)
	GetTechniqueIDsByCveID(string) ([]string, error)
	GetTechniqueIDsByMultiCveID([]string) (map[string][]string, error)
	GetAttackerIDsByTechniqueIDs([]string) ([]string, error)
}

// Option :
type Option struct {
	RedisTimeout time.Duration
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool, option Option) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, false, xerrors.Errorf("Failed to new db. err: %w", err)
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	isV1, err := driver.IsGoCTIModelV1()
	if err != nil {
		return nil, false, xerrors.Errorf("Failed to IsGoCTIModelV1. err: %w", err)
	}
	if isV1 {
		return nil, false, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, false, xerrors.Errorf("Failed to migrate db. err: %w", err)
	}
	return driver, false, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, xerrors.Errorf("Invalid database dialect, %s", dbType)
}

// IndexChunk has a starting point and an ending point for Chunk
type IndexChunk struct {
	From, To int
}

func chunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}

func classCtiIDs(ctiIDs []string) ([]string, []string, error) {
	techniques := []string{}
	attackers := []string{}
	for _, ctiID := range ctiIDs {
		if strings.HasPrefix(ctiID, "T") || strings.HasPrefix(ctiID, "CAPEC") {
			techniques = append(techniques, ctiID)
		} else if strings.HasPrefix(ctiID, "G") || strings.HasPrefix(ctiID, "S") {
			attackers = append(attackers, ctiID)
		} else {
			return nil, nil, xerrors.Errorf(`Failed to class CTI-IDs. err: invalid CTI-ID(%s). The prefix of the CTI-ID must be "T", "CAPEC", "G", or "S".`, ctiID)
		}
	}
	return techniques, attackers, nil
}
