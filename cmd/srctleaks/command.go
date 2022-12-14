package srctleaks

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/mr-pmillz/gorecon/v2/srctleaks"
	"github.com/projectdiscovery/gologger"
	"os"

	"github.com/spf13/cobra"
)

type srctleaksOptions = srctleaks.Options

type Options struct {
	srctleaksOptions
}

func configureCommand(cmd *cobra.Command) {
	_ = srctleaks.ConfigureCommand(cmd)
}

func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	if err := opts.srctleaksOptions.LoadFromCommand(cmd); err != nil {
		return err
	}
	return nil
}

// Command represents the srctleaks command
var Command = &cobra.Command{
	Use:   "srctleaks",
	Short: "GitHub Public Repo OSINT",
	Long: `Checks for a public organization based upon company name arg and clones all repos then runs gitleaks on them to check for secrets.

Example Commands:
	gorecon srctleaks -c SpyVsSpyEnterprises -d made-up-spy-domain.com --github-token ${GITHUB_TOKEN} -o path/to/output/dir 
	gorecon srctleaks -c SpyVsSpyEnterprises -d made-up-spy-domain.com --github-token ${GITHUB_TOKEN} -o path/to/output/dir --check-all-org-users
	gorecon srctleaks --config config.yaml
	gorecon srctleaks --config config.yaml --check-all-org-users

`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			localio.LogFatal(err, "Could not load Command Opts")
		}

		if err = os.MkdirAll(opts.srctleaksOptions.Output, 0750); err != nil {
			gologger.Fatal().Msgf("Could not mkdir %s\n", err)
		}

		if err = srctleaks.Run(&opts.srctleaksOptions); err != nil {
			localio.LogFatal(err, "Could not run srctleaks.Run()")
		}
	},
}

func init() {
	configureCommand(Command)
}
