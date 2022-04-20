package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/db"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/server"
	"github.com/vulsio/go-cti/utils"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start go-cti HTTP server",
	Long:  `Start go-cti HTTP server`,
	RunE:  executeServer,
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().String("bind", "", "HTTP server bind to IP address")
	_ = viper.BindPFlag("bind", serverCmd.PersistentFlags().Lookup("bind"))
	viper.SetDefault("bind", "127.0.0.1")

	serverCmd.PersistentFlags().String("port", "", "HTTP server port number")
	_ = viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port"))
	viper.SetDefault("port", "1329")

}

func executeServer(_ *cobra.Command, _ []string) (err error) {
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
		return xerrors.Errorf("Failed to start server. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	log15.Info("Starting HTTP Server...")
	if err = server.Start(viper.GetBool("log-to-file"), viper.GetString("log-dir"), driver); err != nil {
		return xerrors.Errorf("Failed to start server. err: %w", err)
	}

	return nil
}
