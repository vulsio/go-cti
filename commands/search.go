package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulsio/go-cti/db"
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

	param := viper.GetString("param")
	if !cveIDRegexp.MatchString(param) {
		log15.Error("Specify the search parameters like `--param CVE-xxxx-xxxx`")
		return errors.New("Invalid CVE Param")
	}
	results := driver.GetModuleByCveID(param)
	if len(results) == 0 {
		log15.Info(fmt.Sprintf("No results of CVE which ID is %s", param))
		return nil
	}
	log15.Info("Get results")
	resultsByteData, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("Failed to marshal :%s", err)
	}
	log15.Info("Output as JSON")
	fmt.Printf("%s\n", string(resultsByteData))
	return nil
}
