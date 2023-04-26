package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/db"
)

// Start :
func Start(logToFile bool, logDir string, driver db.DB) error {
	e := echo.New()
	e.Debug = viper.GetBool("debug")

	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: os.Stderr}))
	e.Use(middleware.Recover())

	// setup access logger
	if logToFile {
		logPath := filepath.Join(logDir, "access.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return xerrors.Errorf("Failed to open a log file: %s", err)
		}
		defer f.Close()
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: f}))
	}

	// Routes
	e.GET("/health", health())
	e.GET("/ctis/:cti", getCtiByCtiID(driver))
	e.POST("/multi-ctis", getCtiByMultiCtiID(driver))
	e.GET("/cves/:cve", getTechniqueIDsByCveID(driver))
	e.POST("/multi-cves", getTechniqueIDsByMultiCveID(driver))
	e.POST("/attackers", getAttackerIDsByTechniqueIDs(driver))

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
	log15.Info("Listening...", "URL", bindURL)

	return e.Start(bindURL)
}

func health() echo.HandlerFunc {
	return func(context echo.Context) error {
		return context.String(http.StatusOK, "")
	}
}

type param struct {
	Args []string `json:"args"`
}

func getCtiByCtiID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		ctiID := context.Param("cti")
		log15.Debug("Params", "CTI-ID", ctiID)

		cti, err := driver.GetCtiByCtiID(ctiID)
		if err != nil {
			return xerrors.Errorf("Failed to get CTI by CTI-ID. err: %w", err)
		}
		return context.JSON(http.StatusOK, cti)
	}
}

func getCtiByMultiCtiID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		ctiIDs := param{}
		if err := context.Bind(&ctiIDs); err != nil {
			return err
		}
		log15.Debug("Params", "CTI-IDs", ctiIDs.Args)

		ctis, err := driver.GetCtisByMultiCtiID(ctiIDs.Args)
		if err != nil {
			return xerrors.Errorf("Failed to get CTIs by CTI-IDs. err: %w", err)
		}
		return context.JSON(http.StatusOK, ctis)
	}
}

func getTechniqueIDsByCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cve := context.Param("cve")
		log15.Debug("Params", "CVE-ID", cve)

		ids, err := driver.GetTechniqueIDsByCveID(cve)
		if err != nil {
			return xerrors.Errorf("Failed to get TechniqueIDs by CVE-ID. err: %w", err)
		}
		return context.JSON(http.StatusOK, ids)
	}
}

func getTechniqueIDsByMultiCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cveIDs := param{}
		if err := context.Bind(&cveIDs); err != nil {
			return err
		}
		log15.Debug("Params", "CVE-IDs", cveIDs.Args)

		vulns, err := driver.GetTechniqueIDsByMultiCveID(cveIDs.Args)
		if err != nil {
			return xerrors.Errorf("Failed to get TechniqueIDs by CVE-IDs. err: %w", err)
		}
		return context.JSON(http.StatusOK, vulns)
	}
}

func getAttackerIDsByTechniqueIDs(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		techIDs := param{}
		if err := context.Bind(&techIDs); err != nil {
			return err
		}
		log15.Debug("Params", "TechniqueIDs", techIDs.Args)

		attackerIDs, err := driver.GetAttackerIDsByTechniqueIDs(techIDs.Args)
		if err != nil {
			return xerrors.Errorf("Failed to get AttackerIDs by TechniqueIDs. err: %w", err)
		}
		return context.JSON(http.StatusOK, attackerIDs)
	}
}
