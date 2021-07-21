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

// Version of go-cti
var Version = "0.0.0"

// Revision of go-cti
var Revision string

func main() {
	var v = flag.Bool("v", false, "Show version")

	if envArgs := os.Getenv("GOVAL_DICTIONARY_ARGS"); 0 < len(envArgs) {
		if err := flag.CommandLine.Parse(strings.Fields(envArgs)); err != nil {
			fmt.Printf("Failed to parse ENV_VARs: %s", err)
			os.Exit(1)
		}
	} else {
		flag.Parse()
	}

	if *v {
		fmt.Printf("go-cti %s %s\n", Version, Revision)
		os.Exit(0)
	}

	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
