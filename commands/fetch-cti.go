package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	// "github.com/spf13/viper"

	"github.com/vulsio/go-cti/fetcher"
	"github.com/vulsio/go-cti/git"
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

	log15.Info("Fetching mitre/cti")
	gc := &git.Config{}
	fc := fetcher.Config{
		GitClient: gc,
	}
	if err = fc.FetchMitreCti(); err != nil {
		log15.Error("Failed to fetch mitre/cti", "err", err)
		return err
	}

	return nil
}
