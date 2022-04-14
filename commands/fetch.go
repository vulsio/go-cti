package commands

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of mitre/cti",
	Long:  `Fetch the data of mitre/cti`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().Int("batch-size", 50, "The number of batch size to insert.")
	_ = viper.BindPFlag("batch-size", fetchCmd.PersistentFlags().Lookup("batch-size"))
}
