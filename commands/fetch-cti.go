package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulsio/go-cti/db"
	"github.com/vulsio/go-cti/fetcher"
	"github.com/vulsio/go-cti/git"
	"github.com/vulsio/go-cti/models"
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

func fetchMitreCti(cmd *cobra.Command, args []string) (err error) {
	driver, locked, err := db.NewDB(
		viper.GetString("dbtype"),
		viper.GetString("dbpath"),
		viper.GetBool("debug-sql"),
	)
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}
	defer func() {
		_ = driver.CloseDB()
	}()

	log15.Info("Fetching mitre/cti")
	gc := &git.Config{}
	fc := fetcher.Config{
		GitClient: gc,
	}
	var records []*models.Cti
	if records, err = fc.FetchMitreCti(); err != nil {
		log15.Error("Failed to fetch mitre/cti", "err", err)
		return err
	}
	log15.Info("Cyber Threat Intelligence with CVEs", "count", len(records))

	log15.Info("Insert info into go-ctidb.", "db", driver.Name())
	if err := driver.InsertCti(records); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}
	return nil
}
