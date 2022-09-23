package recon

import (
	"fmt"

	"github.com/mr-pmilz/gorecon/recon"
	"github.com/spf13/cobra"
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
			panic(err)
		}

		hostScope, err := recon.NewScope(&opts.reconOptions)
		if err != nil {
			fmt.Println(err.Error())
			panic(err)
		}

		if err = hostScope.RunAllRecon(&opts.reconOptions); err != nil {
			fmt.Println(err.Error())
			panic(err)
		}
	},
}

func init() {
	configureCommand(Command)
}
