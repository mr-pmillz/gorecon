package srctleaks

import (
	"github.com/mr-pmillz/gorecon/localio"
	"github.com/mr-pmillz/gorecon/srctleaks"

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
	Long:  `Checks for a public organization based upon company name arg and clones all repos then runs gitleaks on them to check for secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			localio.LogFatal(err, "Could not load Command Opts")
		}
		if err = srctleaks.Run(&opts.srctleaksOptions); err != nil {
			localio.LogFatal(err, "Could not run srctleaks.Run()")
		}
	},
}

func init() {
	configureCommand(Command)
}
