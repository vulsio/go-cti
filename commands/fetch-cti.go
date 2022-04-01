package commands

import (
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/db"
	"github.com/vulsio/go-cti/fetcher"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

var fetchMitreCtiCmd = &cobra.Command{
	Use:   "threat",
	Short: "Fetch the data of mitre/cti cve's list",
	Long:  `Fetch the data of mitre/cti cve's list`,
	RunE:  fetchMitreCti,
}

func init() {
	fetchCmd.AddCommand(fetchMitreCtiCmd)
}

func fetchMitreCti(_ *cobra.Command, _ []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	log15.Info("Fetching Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings")
	ctis, mappings, err := fetcher.FetchCti()
	if err != nil {
		return xerrors.Errorf("Failed to fetch Cyber Threat Intelligence. err: %w", err)
	}
	log15.Info("Fetched Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings", "ctis", len(ctis), "mappings", len(mappings))

	log15.Info("Insert Cyber Threat Intelligences and CVE-ID to CTI-ID Mappings into go-cti.", "db", driver.Name())
	if err := driver.InsertCti(ctis, mappings); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
