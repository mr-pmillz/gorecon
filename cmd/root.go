package cmd

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"

	"github.com/mr-pmillz/gorecon/v2/cmd/nessus"
	"github.com/mr-pmillz/gorecon/v2/cmd/srctleaks"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/mr-pmillz/gorecon/v2/cmd/recon"
	"github.com/mr-pmillz/gorecon/v2/localio"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	version = "v2.3.7"
)

const (
	defaultConfigFileName = "config"
	envPrefix             = "GORECON"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:     "gorecon",
	Version: version,
	Short:   "External recon automation tool",
	Long:    `Automates recon-ng based upon cli args or yaml configuration file. More features coming soon!`,
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is APP_ROOT/config/config.yaml")
	RootCmd.AddCommand(recon.Command)
	RootCmd.AddCommand(srctleaks.Command)
	RootCmd.AddCommand(nessus.Command)
	showBanner()
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		absConfigFilePath, err := localio.ResolveAbsPath(cfgFile)
		if err != nil {
			_ = fmt.Errorf("couldn't resolve path of config file: %w", err)
			return
		}
		viper.SetConfigFile(absConfigFilePath)
	} else {
		// Search config in project root directory with name "config.yaml" (without extension).
		viper.AddConfigPath("./config")
		viper.SetConfigType("yaml")
		viper.SetConfigName(defaultConfigFileName)
	}

	// If a config file is found, read it.
	if err := viper.ReadInConfig(); err == nil {
		localio.PrintInfo("ConfigFile", viper.ConfigFileUsed(), "Using config file:")
	}

	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv() // read in environment variables that match
	bindFlags(RootCmd)
}

// bindFlags Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		err := viper.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
		if err != nil {
			return
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				return
			}
		}
	})
}

var banner = ` 
   ___             ___                                      ~ ~~  ~~ o o o          
  / __|    ___    | _ \    ___     __      ___    _ _                      o        
 | (_ |   / _ \   |   /   / -_)   / _|    / _ \  | ' \   _________,_____     o     
  \___|   \___/   |_|_\   \___|   \__|    \___/  |_||_|  |        | |DD|__mm_[].   
_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_]________|_|__|_______)< 
"'-0-0-'"'-0-0-'"'-0-0-'"'-0-0-'"'-0-0-'"'-0-0-'"'-0-0-'"=!00!!00!'"'oo-OOOO-oo\_
-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`

// showBanner prints the GoRecon Banner to stdout
func showBanner() {
	versionBanner := strings.ReplaceAll(banner, "|        |", fmt.Sprintf("] %s |", version))
	gologger.Print().Msgf("%s\n", versionBanner)
	gologger.Print().Msgf("\t  Brought to you by https://www.blackhillsinfosec.com/\n\n")
	gologger.Print().Msgf("\n")
}
