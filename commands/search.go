package commands

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/db"
	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

// fetchCmd represents the fetch command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search the data of mitre/cti form DB",
	Long:  `Search the data of mitrc/cti form DB`,
	Args:  cobra.ExactArgs(1),
	RunE:  searchCti,
}

func init() {
	RootCmd.AddCommand(searchCmd)
}

func searchCti(_ *cobra.Command, args []string) error {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(
		viper.GetString("dbtype"),
		viper.GetString("dbpath"),
		viper.GetBool("debug-sql"),
		db.Option{},
	)
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
		return xerrors.Errorf("Failed to search command. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	matched, err := regexp.MatchString(`^CVE-[0-9]{4}-[0-9]{4,}$`, args[0])
	if err != nil {
		return xerrors.Errorf("Failed to search CTI. err: %w", err)
	}
	if !matched {
		return xerrors.Errorf("Failed to search CTI. err: invalid argument. expected format: CVE-xxxx-xxxx, actual: %s", args[0])
	}

	ctis, err := driver.GetCtiByCveID(args[0])
	if err != nil {
		return xerrors.Errorf("Failed to get CTI. err: %w", err)
	}
	if len(ctis) == 0 {
		return nil
	}

	result, err := json.MarshalIndent(ctis, "", "  ")
	if err != nil {
		return xerrors.Errorf("Failed to marshal json. err: %w", err)
	}
	fmt.Printf("%s\n", string(result))
	return nil
}
