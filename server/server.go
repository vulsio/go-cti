package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
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
	e.GET("/cves/:cve", getVulnByCveID(driver))
	e.POST("/multi-cves", getVulnByMultiCveID(driver))

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
	log15.Info("Listening...", "URL", bindURL)

	return e.Start(bindURL)
}

func health() echo.HandlerFunc {
	return func(context echo.Context) error {
		return context.String(http.StatusOK, "")
	}
}

func getVulnByCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cve := context.Param("cve")
		log15.Debug("Params", "CVE", cve)

		vuln, err := driver.GetCtiByCveID(cve)
		if err != nil {
			return xerrors.Errorf("Failed to get CTI by CVE. err: %w", err)
		}
		return context.JSON(http.StatusOK, vuln)
	}
}

type param struct {
	Args []string `json:"args"`
}

func getVulnByMultiCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cveIDs := param{}
		if err := context.Bind(&cveIDs); err != nil {
			return err
		}
		log15.Debug("Params", "CVEIDs", cveIDs.Args)

		vulns, err := driver.GetCtiByMultiCveID(cveIDs.Args)
		if err != nil {
			return xerrors.Errorf("Failed to get CTI by CVE. err: %w", err)
		}
		return context.JSON(http.StatusOK, vulns)
	}
}
