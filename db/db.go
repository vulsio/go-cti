package db

import (
	"fmt"

	"github.com/vulsio/go-cti/models"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool) (bool, error)
	MigrateDB() error
	CloseDB() error
	InsertCti([]*models.Cti) error
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, false, fmt.Errorf("Failed to new db: %w", err)
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

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
