package recon

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gorecon/localio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runModule runs a recon-ng module against the provided domain
func runModule(workspace, module, domain string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -m %s -o source=%s -x", workspace, module, domain)); err != nil {
		return err
	}
	return nil
}

// runCompanyModule runs a recon-ng module against the provided domain
func runCompanyModule(workspace, module, company string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -m %s -o source=%s -x", workspace, module, company)); err != nil {
		return err
	}
	return nil
}

func installMarketPlaceModules(workspace string, modules []string) error {
	for _, i := range modules {
		if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -C \"marketplace install %s\" -x", workspace, i)); err != nil {
			return err
		}
	}
	return nil
}

func insertCompany(workspace, company string) error {
	command := fmt.Sprintf("recon-cli -w %s -C \"db query insert into companies (company) select '%s' where not exists (select 1 from companies where company='%s');\" -x", workspace, company, company)
	if err := localio.RunCommandPipeOutput(command); err != nil {
		return err
	}
	return nil
}

func insertDomains(workspace string, domains []string) error {
	for _, i := range domains {
		command := fmt.Sprintf("recon-cli -w %s \"-C db query insert into domains (domain) select '%s' where not exists (select 1 from domains where domain='%s');\" -x", workspace, i, i)
		if err := localio.RunCommandPipeOutput(command); err != nil {
			return err
		}
	}

	return nil
}

func insertNetblocks(workspace string, netblocks []string) error {
	for _, i := range netblocks {
		command := fmt.Sprintf("recon-cli -w %s -C \"db query insert into netblocks (netblock) select '%s' where not exists (select 1 from netblocks where netblock='%s');\" -x", workspace, i, i)
		if err := localio.RunCommandPipeOutput(command); err != nil {
			return err
		}
	}

	return nil
}

func generateReport(workspace, creator, company, output string) error {
	workReportDir, err := localio.ResolveAbsPath(output)
	if err != nil {
		return err
	}
	reportFormats := []string{"reporting/csv", "reporting/html"}
	now := time.Now()
	timestamp := now.Format("01-02-2006")

	if exists, err := localio.Exists(filepath.Dir(workReportDir)); err == nil && !exists {
		if err = os.MkdirAll(filepath.Dir(workReportDir), 0750); err != nil {
			return err
		}
	}
	for _, report := range reportFormats {
		ext := strings.Split(report, "/")[1]
		srcArg := fmt.Sprintf("-o FILENAME=%s/recon-ng-%s-%s.%s", workReportDir, company, timestamp, ext)
		command := fmt.Sprintf("recon-cli -w %s -m %s -o \"CREATOR = %s\" -o \"CUSTOMER = %s\" %s -x", workspace, report, creator, company, srcArg)
		if err := localio.RunCommandPipeOutput(command); err != nil {
			return err
		}
	}

	return nil
}

// RunReconNG runs all specified modules against the target domain
func RunReconNG(hosts *Hosts, opts *Options) error {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	gologger.Info().Str("workspace", opts.Workspace).Msg("Running Recon-ng")

	if err := localio.PrettyPrint(hosts); err != nil {
		return err
	}

	if err := insertCompany(opts.Workspace, opts.Company); err != nil {
		return err
	}

	if err := insertDomains(opts.Workspace, hosts.Domains); err != nil {
		return err
	}

	if err := insertNetblocks(opts.Workspace, hosts.CIDRs); err != nil {
		return err
	}

	// refresh install all modules
	marketPlaceRefreshAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace refresh\" -x", opts.Workspace)
	marketPlaceInstallAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace install all\" -x", opts.Workspace)
	cmds := []string{marketPlaceRefreshAllCMD, marketPlaceInstallAllCMD}
	if err := localio.RunCommandsPipeOutput(cmds); err != nil {
		return err
	}

	// install any extra modules not included in "all" ^
	modules, err := localio.ReadLines(opts.Modules)
	if err != nil {
		return err
	}
	if err = installMarketPlaceModules(opts.Workspace, modules); err != nil {
		return err
	}

	// run all modules against all base domains
	for _, domain := range hosts.Domains {
		for _, module := range modules {
			if strings.Contains(module, "domains") || strings.Contains(module, "hackertarget") {
				if err = runModule(opts.Workspace, module, domain); err != nil {
					return err
				}
			}
		}
	}

	for _, netblock := range hosts.CIDRs {
		for _, module := range modules {
			if strings.Contains(module, "hosts-hosts") || strings.Contains(module, "hosts-ports") {
				if err = runModule(opts.Workspace, module, netblock); err != nil {
					return err
				}
			}
		}
	}

	for _, module := range modules {
		if strings.Contains(module, "companies") {
			if err = runCompanyModule(opts.Workspace, module, opts.Company); err != nil {
				return err
			}
		}
	}

	if err = generateReport(opts.Workspace, opts.Creator, opts.Company, opts.Output); err != nil {
		return err
	}

	return nil
}
