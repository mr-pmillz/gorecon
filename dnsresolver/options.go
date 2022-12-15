package dnsresolver

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/spf13/cobra"
	"os"
	"reflect"
)

type Options struct {
	Output  string
	Targets interface{}
	Workers int
}

// ConfigureCommand ...
func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("targets", "t", "", "full or relative path to a file containing a list of targets, CIDRs, hostnames, IPs")
	cmd.PersistentFlags().StringP("output", "o", "", "directory where results will be written to. if dir not exist is created.")
	cmd.PersistentFlags().IntP("workers", "w", 10, "number of goroutines to use. default is 10")
	_ = cmd.MarkFlagRequired("targets")
	_ = cmd.MarkFlagRequired("output")
	return nil
}

// LoadFromCommand ...
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	workers, err := cmd.Flags().GetInt("workers")
	if err != nil {
		return err
	}
	opts.Workers = workers

	output, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "output",
		IsFilePath: true,
		Opts:       opts.Output,
	})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(output.(string), os.ModePerm); err != nil {
		return err
	}
	opts.Output = output.(string)

	targets, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "targets",
		IsFilePath: true,
		Opts:       opts.Targets,
	})
	if err != nil {
		return err
	}
	rtTargets := reflect.TypeOf(targets)
	switch rtTargets.Kind() {
	case reflect.Slice:
		opts.Targets = targets.([]string)
	case reflect.String:
		opts.Targets = targets.(string)
	}

	return nil
}
