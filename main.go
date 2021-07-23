package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vulsio/go-cti/commands"
)

// Name ... Name
const Name string = "go-cti"

// Version ... Version
var version = "0.0.1"

func main() {
	var v = flag.Bool("v", false, "Show version")

	if envArgs := os.Getenv("GO_CTI_ARGS"); 0 < len(envArgs) {
		commands.RootCmd.SetArgs(strings.Fields(envArgs))
	} else {
		flag.Parse()
	}

	if *v {
		fmt.Printf("%s %s \n", Name, version)
		os.Exit(0)
	}

	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
