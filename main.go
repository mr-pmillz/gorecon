/*
Copyright © 2022 MrPMillz

*/
package main

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra/doc"

	"github.com/mr-pmillz/gorecon/cmd"
)

func main() {
	if val, present := os.LookupEnv("GENERATE_GORECON_DOCS"); val == "true" && present {
		if err := doc.GenMarkdownTree(cmd.RootCmd, "./docs"); err != nil {
			gologger.Fatal().Msgf("Could not generate markdown docs %s\n", err)
		}
	}

	if err := cmd.RootCmd.Execute(); err != nil {
		gologger.Fatal().Msgf("Could not run root command %s\n", err)
	}
}
