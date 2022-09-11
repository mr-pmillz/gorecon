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
	Workspace string
}

func ConfigureCommand(cmd *cobra.Command) error {

	cmd.PersistentFlags().StringP("company", "c", "", "todo")
	cmd.PersistentFlags().StringP("creator", "", "BHIS", "report creator")
	cmd.PersistentFlags().StringP("domain", "d", "", "todo")
	cmd.PersistentFlags().StringP("modules", "m", "", "list of recon-ng modules you want to run")
	cmd.PersistentFlags().StringP("netblock", "n", "", "todo")
	cmd.PersistentFlags().StringP("workspace", "w", "", "todo")
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

	return nil
}
