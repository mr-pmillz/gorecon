package recon

import (
	"github.com/spf13/cobra"
	"gorecon/localio"
)

type Options struct {
	Company   string
	Creator   string
	Domain    string
	Modules   string
	NetBlock  string
	Output    string
	Workspace string
}

func ConfigureCommand(cmd *cobra.Command) error {

	cmd.PersistentFlags().StringP("company", "c", "", "company name that your testing")
	cmd.PersistentFlags().StringP("creator", "", "BHIS", "report creator")
	cmd.PersistentFlags().StringP("domain", "d", "", "domain string or file containing domains ex. domains.txt")
	cmd.PersistentFlags().StringP("modules", "m", "", "list of recon-ng modules you want to run for domains and hosts")
	cmd.PersistentFlags().StringP("netblock", "n", "", "CIDRs you wish to scan")
	cmd.PersistentFlags().StringP("workspace", "w", "", "workspace name, use one word")
	cmd.PersistentFlags().StringP("output", "o", "~/work", "output dir, defaults to ~/work")
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

	domain, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "domain",
		IsFilePath: true,
		Opts:       opts.Domain,
	})
	if err != nil {
		return err
	}
	opts.Domain = domain.(string)

	netblock, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "netblock",
		IsFilePath: true,
		Opts:       opts.NetBlock,
	})
	if err != nil {
		return err
	}
	opts.NetBlock = netblock.(string)

	modules, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "modules",
		IsFilePath: true,
		Opts:       opts.Modules,
	})
	if err != nil {
		return err
	}
	opts.Modules = modules.(string)

	creator, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "creator",
		IsFilePath: true,
		Opts:       opts.Creator,
	})
	if err != nil {
		return err
	}
	opts.Creator = creator.(string)

	workspace, err := localio.ConfigureFlagOpts(cmd, &localio.LoadFromCommandOpts{
		Flag:       "workspace",
		IsFilePath: true,
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
