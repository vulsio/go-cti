package commands

import (
	"encoding/json"
	"fmt"

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
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			fmt.Println("[usage] $ go-cti search (cti|cve|attacker) $id1(, $id2...)")
			return xerrors.New("Failed to search. err: argument is missing")
		}
		if !(args[0] == "cti" || args[0] == "cve" || args[0] == "attacker") {
			fmt.Println("[usage] $ go-cti search (cti|cve|attacker) $id1(, $id2...)")
			return xerrors.New(`Failed to search. err: search target is inappropriate, select "cti", "cve" or "attacker".`)
		}
		return nil
	},
	RunE: searchCti,
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

	var result []byte
	switch args[0] {
	case "cti":
		if len(args[1:]) == 1 {
			cti, err := driver.GetCtiByCtiID(args[1])
			if err != nil {
				return xerrors.Errorf("Failed to search CTI. err: %w", err)
			}
			result, err = json.MarshalIndent(cti, "", "  ")
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}
		} else {
			ctis, err := driver.GetCtisByMultiCtiID(args[1:])
			if err != nil {
				return xerrors.Errorf("Failed to search CTIs. err: %w", err)
			}
			result, err = json.MarshalIndent(ctis, "", "  ")
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}
		}
	case "cve":
		if len(args[1:]) == 1 {
			techniques, err := driver.GetTechniqueIDsByCveID(args[1])
			if err != nil {
				return xerrors.Errorf("Failed to get CTI. err: %w", err)
			}
			if len(techniques) == 0 {
				return nil
			}
			result, err = json.MarshalIndent(techniques, "", "  ")
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}
		} else {
			techniques, err := driver.GetTechniqueIDsByMultiCveID(args[1:])
			if err != nil {
				return xerrors.Errorf("Failed to get CTI. err: %w", err)
			}
			if len(techniques) == 0 {
				return nil
			}
			result, err = json.MarshalIndent(techniques, "", "  ")
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}
		}
	case "attacker":
		attackers, err := driver.GetAttackerIDsByTechniqueIDs(args[1:])
		if err != nil {
			return xerrors.Errorf("Failed to get attackers. err: %w", err)
		}
		if len(attackers) == 0 {
			return nil
		}
		result, err = json.MarshalIndent(attackers, "", "  ")
		if err != nil {
			return xerrors.Errorf("Failed to marshal json. err: %w", err)
		}
	}
	fmt.Printf("%s\n", string(result))
	return nil
}
