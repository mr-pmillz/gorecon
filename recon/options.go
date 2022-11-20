package recon

import (
	"reflect"

	"github.com/spf13/cobra"

	"github.com/mr-pmillz/gorecon/localio"
)

type Options struct {
	Company                 string
	Creator                 string
	Domain                  interface{}
	Modules                 interface{}
	NetBlock                interface{}
	OutOfScope              interface{}
	Output                  string
	Workspace               string
	SubFinderProviderConfig string
	RunDNSRecon             bool
	ASN                     bool
}

func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("company", "c", "", "company name that your testing")
	cmd.PersistentFlags().StringP("creator", "", "", "report creator")
	cmd.PersistentFlags().StringP("domain", "d", "", "domain string or file containing domains ex. domains.txt")
	cmd.PersistentFlags().StringP("modules", "m", "", "list of recon-ng modules you want to run for domains and hosts")
	cmd.PersistentFlags().StringP("netblock", "n", "", "CIDRs you wish to scan")
	cmd.PersistentFlags().StringP("workspace", "w", "", "workspace name, use one word")
	cmd.PersistentFlags().StringP("output", "o", "", "report output dir")
	cmd.PersistentFlags().StringP("out-of-scope", "", "", "out of scope domains, IPs, or CIDRs")
	cmd.PersistentFlags().StringP("subfinder-keys-file", "", "", "file path to subfinder provider config containing api keys")
	cmd.PersistentFlags().BoolP("run-dnsrecon", "", false, "if this flag is specified, dnsrecon will be ran in addition to default enumeration")
	cmd.PersistentFlags().BoolP("asn", "", false, "if this flag is set, will query primary domain for ASN data via asnmap package")
	return nil
}

func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	company, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "company",
		IsFilePath: false,
		Opts:       opts.Company,
	})
	if err != nil {
		return err
	}
	opts.Company = company.(string)

	cmdASN, err := cmd.Flags().GetBool("asn")
	if err != nil {
		return err
	}
	opts.ASN = cmdASN

	cmdDNSRecon, err := cmd.Flags().GetBool("run-dnsrecon")
	if err != nil {
		return err
	}
	opts.RunDNSRecon = cmdDNSRecon

	subfinderConfig, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "subfinder-keys-file",
		IsFilePath: true,
		Opts:       opts.SubFinderProviderConfig,
	})
	if err != nil {
		return err
	}
	opts.SubFinderProviderConfig = subfinderConfig.(string)

	domain, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "domain",
		IsFilePath: true,
		Opts:       opts.Domain,
	})
	if err != nil {
		return err
	}
	rt := reflect.TypeOf(domain)
	switch rt.Kind() {
	case reflect.Slice:
		opts.Domain = domain.([]string)
	case reflect.String:
		opts.Domain = domain.(string)
	}

	netblock, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "netblock",
		IsFilePath: true,
		Opts:       opts.NetBlock,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(netblock)
	switch rt.Kind() {
	case reflect.Slice:
		opts.NetBlock = netblock.([]string)
	case reflect.String:
		opts.NetBlock = netblock.(string)
	}

	modules, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "modules",
		IsFilePath: true,
		Opts:       opts.Modules,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(modules)
	switch rt.Kind() {
	case reflect.Slice:
		opts.Modules = modules.([]string)
	case reflect.String:
		opts.Modules = modules.(string)
	}

	outOfScope, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "out-of-scope",
		IsFilePath: true,
		Opts:       opts.OutOfScope,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(outOfScope)
	switch rt.Kind() {
	case reflect.Slice:
		opts.OutOfScope = outOfScope.([]string)
	case reflect.String:
		opts.OutOfScope = outOfScope.(string)
	}

	creator, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "creator",
		IsFilePath: false,
		Opts:       opts.Creator,
	})
	if err != nil {
		return err
	}
	opts.Creator = creator.(string)

	workspace, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "workspace",
		IsFilePath: false,
		Opts:       opts.Workspace,
	})
	if err != nil {
		return err
	}
	opts.Workspace = workspace.(string)

	output, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "output",
		IsFilePath: true,
		Opts:       opts.Output,
	})
	if err != nil {
		return err
	}
	opts.Output = output.(string)

	return nil
}
