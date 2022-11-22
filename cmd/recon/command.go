package recon

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/mr-pmillz/gorecon/recon"
)

type reconOptions = recon.Options

type Options struct {
	reconOptions
}

func configureCommand(cmd *cobra.Command) {
	_ = recon.ConfigureCommand(cmd)
}

// LoadFromCommand ...
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	if err := opts.reconOptions.LoadFromCommand(cmd); err != nil {
		return err
	}
	return nil
}

// Command ...
var Command = &cobra.Command{
	Use:   "recon [--domain|-d example.com]",
	Args:  cobra.MinimumNArgs(0),
	Short: "Run recon enumeration",
	Long:  "Run recon enumeration",
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			gologger.Fatal().Msgf("Could not LoadFromCommand %s\n", err)
		}

		if err = os.MkdirAll(opts.reconOptions.Output, 0750); err != nil {
			gologger.Fatal().Msgf("Could not mkdir %s\n", err)
		}

		hostScope, err := recon.NewScope(&opts.reconOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create NewScope %s\n", err)
		}

		if err = hostScope.RunAllRecon(&opts.reconOptions); err != nil {
			gologger.Fatal().Msgf("Could not RunAllRecon %s\n", err)
		}
	},
}

func init() {
	configureCommand(Command)
}
