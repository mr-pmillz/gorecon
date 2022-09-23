/*
Copyright © 2022 MrPMillz

*/
package main

import (
	"log"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/mr-pmillz/gorecon/cmd"
)

func main() {
	if val, present := os.LookupEnv("GENERATE_GORECON_DOCS"); val == "true" && present {
		if err := doc.GenMarkdownTree(cmd.RootCmd, "./docs"); err != nil {
			log.Fatal(err)
		}
	}

	if err := cmd.RootCmd.Execute(); err != nil {
		log.Panic(err)
	}
}
