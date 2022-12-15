package dnsresolver

import (
	"github.com/mr-pmillz/gorecon/v2/dnsresolver"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/projectdiscovery/gologger"
	"os"

	"github.com/spf13/cobra"
)

type dnsResolverOptions = dnsresolver.Options

type Options struct {
	dnsResolverOptions
}

func configureCommand(cmd *cobra.Command) {
	_ = dnsresolver.ConfigureCommand(cmd)
}

func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	if err := opts.dnsResolverOptions.LoadFromCommand(cmd); err != nil {
		return err
	}
	return nil
}

// Command represents the dnsresolver command
var Command = &cobra.Command{
	Use:   "dnsresolver",
	Short: "Attempts to resolve all hosts, CIDRs, and/or IPs from a provided file",
	Long: `Attempts to resolve all hosts, CIDRs, and/or IPs from a provided file. 
The dnsresolver subcommand will automatically parse the nameservers in /etc/resolv.conf using the "github.com/miekg/unbound" library's ResolvConf() method

Example Commands:
	gorecon dnsresolver -t path/to/target-list.txt -o path/to/output-dir
	gorecon dnsresolver -t path/to/target-list.txt -o path/to/output-dir -w 30
`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			localio.LogFatal(err, "Could not load Command Opts")
		}
		if opts.dnsResolverOptions.Output == "" {
			localio.LogWarningf("No output directory specified: %s, using /tmp/resolved-hosts", opts.dnsResolverOptions.Output)
			opts.dnsResolverOptions.Output = "/tmp/resolved-hosts"
		}

		if err = os.MkdirAll(opts.dnsResolverOptions.Output, 0750); err != nil {
			gologger.Fatal().Msgf("Could not mkdir %s\n", err)
		}
		absOutputDirPath, err := localio.ResolveAbsPath(opts.dnsResolverOptions.Output)
		if err != nil {
			gologger.Fatal().Msgf("Could not resolve absolute path: %s\n %s\n", opts.dnsResolverOptions.Output, err)
		}
		opts.dnsResolverOptions.Output = absOutputDirPath

		if err = dnsresolver.RunResolver(&opts.dnsResolverOptions); err != nil {
			gologger.Fatal().Msgf("Something went wrong while resolving targets")
		}
	},
}

func init() {
	configureCommand(Command)
}
