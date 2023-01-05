package nessus

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/spf13/cobra"
)

type Options struct {
	NessusFile          string
	Output              string
	TestSSL             bool
	StreamNmap          bool
	AsyncNmap           bool
	AsyncNmapSVCScripts bool
	Nuclei              bool
	Enum4LinuxNG        bool
}

func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("nessus-file", "n", "", "full or relative path to nessus file.nessus")
	cmd.PersistentFlags().StringP("output", "o", "", "report output dir")
	cmd.PersistentFlags().BoolP("testssl", "", false, "runs Testssl.sh against all tls and ssl nessus findings hosts")
	cmd.PersistentFlags().BoolP("stream-nmap", "", false, "streams nmap synchronously with default scripts against all open ports for low through critical severity findings hosts")
	cmd.PersistentFlags().BoolP("async-nmap", "", false, "runs nmap asynchronously in 10 parallel goroutines with default scripts against all open ports for low through critical severity findings hosts")
	cmd.PersistentFlags().BoolP("async-nmap-svc-scripts", "", false, "runs nmap asynchronously in 30 parallel goroutines with scripts fine tuned per service")
	cmd.PersistentFlags().BoolP("nuclei", "", false, "runs nuclei scan with critical,high, and medium severity templates against all web services")
	cmd.PersistentFlags().BoolP("enum4linux-ng", "", false, "runs enum4linux-ng against all hosts parsed from nessus within svc_name attribute slice []string{\"cifs\", \"smb\", \"epmap\", \"ldap\"} also runs initial crackmapexec smb against just port 445 hosts")
	cmd.MarkFlagsMutuallyExclusive("async-nmap", "stream-nmap", "testssl", "nuclei", "enum4linux-ng")
	_ = cmd.MarkFlagRequired("nessus-file")
	_ = cmd.MarkFlagRequired("output")
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

	cmdAsyncNmapSVCScripts, err := cmd.Flags().GetBool("async-nmap-svc-scripts")
	if err != nil {
		return err
	}
	opts.AsyncNmapSVCScripts = cmdAsyncNmapSVCScripts

	cmdEnum4LinuxNG, err := cmd.Flags().GetBool("enum4linux-ng")
	if err != nil {
		return err
	}
	opts.Enum4LinuxNG = cmdEnum4LinuxNG

	cmdNuclei, err := cmd.Flags().GetBool("nuclei")
	if err != nil {
		return err
	}
	opts.Nuclei = cmdNuclei

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
