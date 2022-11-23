package recon

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/mr-pmillz/gorecon/v2/localio"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// runSubfinder enumerates domains using subfinder.
func runSubfinder(domains []string, opts *Options) ([]string, error) {
	for _, domain := range domains {
		runnerInstance, err := runner.NewRunner(&runner.Options{
			Threads:            20,                           // Thread controls the number of threads to use for active enumerations
			Timeout:            30,                           // Timeout is the seconds to wait for sources to respond
			MaxEnumerationTime: 10,                           // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
			Resolvers:          resolve.DefaultResolvers,     // Use the default list of resolvers by marshaling it to the config
			All:                true,                         // All specifies whether to use all (slow) sources.
			ProviderConfig:     opts.SubFinderProviderConfig, // ProviderConfig contains the location of the provider config file
			OnlyRecursive:      false,                        // Recursive specifies whether to use only recursive subdomain enumeration sources
			Silent:             false,                        // Silent suppresses any extra text and only writes subdomains to screen
			Verbose:            true,                         // Verbose flag indicates whether to show verbose output or not
			NoColor:            false,                        // NoColor disables the colored output
		})
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.Buffer{}
		err = runnerInstance.EnumerateSingleDomain(domain, []io.Writer{&buf})
		if err != nil {
			log.Fatal(err)
		}

		data, err := io.ReadAll(&buf)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", data)
		if err = os.WriteFile(fmt.Sprintf("%s/subfinder-%s.txt", opts.Output, domain), data, 0644); err != nil { //nolint:gosec
			return nil, err
		}
	}

	subs, err := parseOutputFiles(domains, opts.Output)
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
