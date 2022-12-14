package nessus

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/mr-pmillz/gorecon/v2/nessus"
	"github.com/projectdiscovery/gologger"
	"os"

	"github.com/spf13/cobra"
)

type nessusOptions = nessus.Options

type Options struct {
	nessusOptions
}

func configureCommand(cmd *cobra.Command) {
	_ = nessus.ConfigureCommand(cmd)
}

func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	if err := opts.nessusOptions.LoadFromCommand(cmd); err != nil {
		return err
	}
	return nil
}

// Command represents the nessus command
var Command = &cobra.Command{
	Use:   "nessus",
	Short: "parses nessus file",
	Long: `parses nessus file, prints and logs hosts and plugin id data etc.

Example Commands:
	gorecon nessus -n path/to/scan-results.nessus -o path/to/output-dir
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --testssl
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --async-nmap
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --async-nmap-svc-scripts
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --stream-nmap
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --nuclei
	gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --enum4linux-ng
`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			localio.LogFatal(err, "Could not load Command Opts")
		}

		if err = os.MkdirAll(opts.nessusOptions.Output, 0750); err != nil {
			gologger.Fatal().Msgf("Could not mkdir %s\n", err)
		}

		if err = nessus.Parse(&opts.nessusOptions); err != nil {
			localio.LogFatal(err, "Could not parse nessus file")
		}

	},
}

func init() {
	configureCommand(Command)
}
