package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vulsio/go-cti/config"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Long:  `Show version`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("go-cti %s %s\n", config.Version, config.Revision)
	},
}
