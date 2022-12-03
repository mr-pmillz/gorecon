package nessus

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/spf13/cobra"
)

type Options struct {
	NessusFile string
	Output     string
	TestSSL    bool
	StreamNmap bool
	AsyncNmap  bool
}

func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("nessus-file", "n", "", "full or relative path to nessus file.nessus")
	cmd.PersistentFlags().StringP("output", "o", "", "report output dir")
	cmd.PersistentFlags().BoolP("testssl", "", false, "runs Testssl.sh against all tls and ssl nessus findings hosts")
	cmd.PersistentFlags().BoolP("stream-nmap", "", false, "streams nmap synchronously with default scripts against all open ports for low through critical severity findings hosts")
	cmd.PersistentFlags().BoolP("async-nmap", "", false, "runs nmap asynchronously in 5 parallel goroutines with default scripts against all open ports for low through critical severity findings hosts")
	cmd.MarkFlagsMutuallyExclusive("async-nmap", "stream-nmap", "testssl")
	return nil
}

func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	output, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "output",
		IsFilePath: true,
		Opts:       opts.Output,
	})
	if err != nil {
		return err
	}
	opts.Output = output.(string)

	nessusFile, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "nessus-file",
		IsFilePath: true,
		Opts:       opts.NessusFile,
	})
	if err != nil {
		return err
	}
	opts.NessusFile = nessusFile.(string)

	cmdTestSSL, err := cmd.Flags().GetBool("testssl")
	if err != nil {
		return err
	}
	opts.TestSSL = cmdTestSSL

	cmdStreamNmap, err := cmd.Flags().GetBool("stream-nmap")
	if err != nil {
		return err
	}
	opts.StreamNmap = cmdStreamNmap

	cmdAsyncNmap, err := cmd.Flags().GetBool("async-nmap")
	if err != nil {
		return err
	}
	opts.AsyncNmap = cmdAsyncNmap

	return nil
}
