package commands

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulsio/go-cti/db"
	//"github.com/vulsio/go-cti/fetcher"
	//"github.com/vulsio/go-cti/git"
	//"github.com/vulsio/go-cti/models"
)

// fetchCmd represents the fetch command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search the data of mitre/cti form DB",
	Long:  `Search the data of mitrc/cti form DB`,
	RunE:  searchCti,
}

var (
	cveIDRegexp = regexp.MustCompile(`^CVE-\d{1,}-\d{1,}$`)
)

func init() {
	RootCmd.AddCommand(searchCmd)

	searchCmd.PersistentFlags().String("type", "", "All Metasploit Framework modules by CVE: CVE  |  by EDB: EDB (default: CVE)")
	_ = viper.BindPFlag("type", searchCmd.PersistentFlags().Lookup("type"))
	viper.SetDefault("type", "CVE")

	searchCmd.PersistentFlags().String("param", "", "All Metasploit Framework modules: None  |  by CVE: [CVE-xxxx]  | by EDB: [EDB-xxxx]  (default: None)")
	_ = viper.BindPFlag("param", searchCmd.PersistentFlags().Lookup("param"))
	viper.SetDefault("param", "")
}

func searchCti(cmd *cobra.Command, args []string) (err error) {
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

	searchType := viper.GetString("type")
	param := viper.GetString("param")
	switch searchType {
	case "CVE":
		if !cveIDRegexp.Match([]byte(param)) {
			log15.Error("Specify the search type [CVE] parameters like `--param CVE-xxxx-xxxx`")
			return errors.New("Invalid CVE Param")
		}
		results := driver.GetModuleByCveID(param)
		if len(results) == 0 {
			log15.Error(fmt.Sprintf("No results of CVE which ID is %s", param))
			return errors.New("No results")
		}
		log15.Info("Get results")
		for _, result := range results {
			fmt.Printf("%s\n", result.CveID)
		}
	default:
		log15.Error("Specify the search type [CVE / EDB].")
		return errors.New("Invalid Type")
	}
	return nil
}
