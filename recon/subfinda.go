package recon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/mr-pmillz/gorecon/localio"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// runSubfinder enumerates domains using subfinder.
// Currently runs without API keys
// TODO feature, add API key functionality to the base config.yaml file
func runSubfinder(domains []string, outputDir string) ([]string, error) {
	for _, domain := range domains {
		runnerInstance, err := runner.NewRunner(&runner.Options{
			Threads:            20,                              // Thread controls the number of threads to use for active enumerations
			Timeout:            30,                              // Timeout is the seconds to wait for sources to respond
			MaxEnumerationTime: 10,                              // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
			Resolvers:          resolve.DefaultResolvers,        // Use the default list of resolvers by marshaling it to the config
			Sources:            passive.DefaultSources,          // Use the default list of passive sources
			AllSources:         passive.DefaultAllSources,       // Use the default list of all passive sources
			Recursive:          passive.DefaultRecursiveSources, // Use the default list of recursive sources
			Providers:          &runner.Providers{},             // Use empty api keys for all providers
			Silent:             false,
			Verbose:            true,
			NoColor:            false,
			OutputFile:         fmt.Sprintf("%s/subfinder-%s.txt", outputDir, domain),
		})
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.Buffer{}
		err = runnerInstance.EnumerateSingleDomain(context.Background(), domain, []io.Writer{&buf})
		if err != nil {
			log.Fatal(err)
		}

		data, err := io.ReadAll(&buf)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", data)
	}

	subs, err := parseOutputFiles(domains, outputDir)
	if err != nil {
		log.Fatal(err)
	}

	return subs, nil
}

// parseOutputFiles parses subfinders output and returns a slice of subdomains
func parseOutputFiles(domains []string, outputDir string) ([]string, error) {
	var foundSubs []string
	for _, domain := range domains {
		outputFile := fmt.Sprintf("%s/subfinder-%s.txt", outputDir, domain)
		if exists, err := localio.Exists(outputFile); exists && err == nil {
			subdomains, err := localio.ReadLines(outputFile)
			if err != nil {
				localio.LogFatal(err, fmt.Sprintf("Could not read file: %s", outputFile))
			}
			foundSubs = append(foundSubs, subdomains...)
		}
	}

	return removeDuplicateStr(foundSubs), nil
}
