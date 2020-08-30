package db

import (
	"fmt"

	"github.com/inconshreveable/log15"

	"github.com/vulsio/go-cti/models"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool) (bool, error)
	DropDB() error
	MigrateDB() error
	CloseDB() error
	InsertCti([]*models.Cti) error
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool, isFetch bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, false, fmt.Errorf("Failed to new db: %w", err)
	}

	log15.Info("Opening DB", "db", driver.Name())
	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	if isFetch {
		log15.Info("Init DB", "db", driver.Name())
		if err := driver.DropDB(); err != nil {
			return driver, false, fmt.Errorf("Failed to drop tables: %w", err)
		}
	}

	log15.Info("Migrating DB", "db", driver.Name())
	if err := driver.MigrateDB(); err != nil {
		return driver, false, fmt.Errorf("Failed to migrate db: %w", err)
	}
	return driver, false, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
		// case dialectRedis:
		// 	return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect, %s", dbType)
}
