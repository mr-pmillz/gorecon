package recon

import (
	"fmt"
	"github.com/mr-pmilz/gorecon/localio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// configureReconNGDependencies installs common missing recon-ng dependencies
// installs required python3 packages not included in recon-ng REQUIREMENTS file
// that are required by various marketplace modules.
// Also fixes censys modules.
// See https://github.com/lanmaster53/recon-ng/issues/149 https://github.com/censys/censys-recon-ng/issues/5
func configureReconNGDependencies() error {
	var notInstalled []string
	installed, err := localio.NewPipInstalled()
	if err != nil {
		return err
	}
	deps := []string{
		"pyaes",
		"PyPDF3",
		"censys",
	}

	for _, pkg := range deps {
		if localio.Contains(installed.Name, pkg) {
			continue
		} else {
			notInstalled = append(notInstalled, pkg)
		}
	}
	if len(notInstalled) >= 1 {
		packagesToInstall := strings.Join(notInstalled, " ")
		if localio.IsRoot() {
			cmd := fmt.Sprintf("python3 -m pip install %s", packagesToInstall)
			if err := localio.RunCommandPipeOutput(cmd); err != nil {
				return err
			}
		} else {
			cmd := fmt.Sprintf("python3 -m pip install %s --user", packagesToInstall)
			if err := localio.RunCommandPipeOutput(cmd); err != nil {
				return err
			}
		}
	}

	// fix missing recon-ng censys modules from https://github.com/censys/censys-recon-ng
	// Manually copy files as the install.sh script included with censys-recon-ng does some extra api key adds for censysio that we should ignore.
	if err = localio.GitClone("https://github.com/censys/censys-recon-ng", "/tmp/censys-recon-ng"); err != nil {
		return err
	}
	reconDir, err := localio.ResolveAbsPath("~/.recon-ng/modules/recon")
	if err != nil {
		return err
	}

	// Not pretty but it gets the job done. Perhaps an embedded bash script would look prettier, but does the same thing. meh.
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_email_address.py", fmt.Sprintf("%s/companies-contacts/censys_email_address.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_subdomains.py", fmt.Sprintf("%s/companies-domains/censys_subdomains.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_org.py", fmt.Sprintf("%s/companies-multi/censys_org.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_tls_subjects.py", fmt.Sprintf("%s/companies-multi/censys_tls_subjects.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_org.py", fmt.Sprintf("%s/companies-hosts/censys_org.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_tls_subjects.py", fmt.Sprintf("%s/companies-hosts/censys_tls_subjects.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_email_to_domains.py", fmt.Sprintf("%s/contacts-domains/censys_email_to_domains.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_companies.py", fmt.Sprintf("%s/domains-companies/censys_companies.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_domain.py", fmt.Sprintf("%s/domains-hosts/censys_domain.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_query.py", fmt.Sprintf("%s/hosts-hosts/censys_query.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_ip.py", fmt.Sprintf("%s/hosts-hosts/censys_ip.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_hostname.py", fmt.Sprintf("%s/hosts-hosts/censys_hostname.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_hostname.py", fmt.Sprintf("%s/hosts-ports/censys_hostname.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_ip.py", fmt.Sprintf("%s/hosts-ports/censys_ip.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_netblock_company.py", fmt.Sprintf("%s/netblocks-companies/censys_netblock_company.py", reconDir)); err != nil {
		return err
	}
	if err = localio.CopyFile("/tmp/censys-recon-ng/censys_netblock.py", fmt.Sprintf("%s/netblocks-hosts/censys_netblock.py", reconDir)); err != nil {
		return err
	}

	return nil
}

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
		switch ext {
		case "csv":
			command := fmt.Sprintf("recon-cli -w %s -m %s -o \"HEADERS = True\"  %s -x", workspace, report, srcArg)
			if err = localio.RunCommandPipeOutput(command); err != nil {
				return err
			}
		case "html":
			command := fmt.Sprintf("recon-cli -w %s -m %s -o \"CREATOR = %s\" -o \"CUSTOMER = %s\" %s -x", workspace, report, creator, company, srcArg)
			if err = localio.RunCommandPipeOutput(command); err != nil {
				return err
			}

			if !localio.IsHeadless() {
				htmlReport := fmt.Sprintf("%s/recon-ng-%s-%s.%s", workReportDir, company, timestamp, ext)
				if err = localio.RunCommandPipeOutput(fmt.Sprintf("firefox %s &", htmlReport)); err != nil {
					return err
				}
			}

		default:
			//Do Nothing
		}
	}

	return nil
}

// RunReconNG runs all specified modules against the target domain
func (h *Hosts) RunReconNG(opts *Options) error {
	localio.PrintInfo("workspace", opts.Workspace, "Running Recon-ng")

	if err := insertCompany(opts.Workspace, opts.Company); err != nil {
		return err
	}

	if err := insertDomains(opts.Workspace, h.Domains); err != nil {
		return err
	}

	if err := insertNetblocks(opts.Workspace, h.CIDRs); err != nil {
		return err
	}

	// refresh install all modules
	marketPlaceRefreshAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace refresh\" -x", opts.Workspace)
	marketPlaceInstallAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace install all\" -x", opts.Workspace)
	cmds := []string{marketPlaceRefreshAllCMD, marketPlaceInstallAllCMD}
	if err := localio.RunCommandsPipeOutput(cmds); err != nil {
		return err
	}

	// Ensure recon-ng deps and censysio modules are installed.
	if err := configureReconNGDependencies(); err != nil {
		return err
	}

	rt := reflect.TypeOf(opts.Modules)
	switch rt.Kind() {
	case reflect.Slice:
		modules := opts.Modules.([]string)
		if err := installMarketPlaceModules(opts.Workspace, modules); err != nil {
			return err
		}
		// Run a second time as
		if err := configureReconNGDependencies(); err != nil {
			return err
		}

		// run all modules against all base domains
		for _, domain := range h.Domains {
			for _, module := range modules {
				if strings.Contains(module, "domains") || strings.Contains(module, "hackertarget") {
					if err := runModule(opts.Workspace, module, domain); err != nil {
						return err
					}
				}
			}
		}

		for _, netblock := range h.CIDRs {
			for _, module := range modules {
				if strings.Contains(module, "hosts-hosts") || strings.Contains(module, "hosts-ports") {
					if err := runModule(opts.Workspace, module, netblock); err != nil {
						return err
					}
				}
			}
		}

		for _, module := range modules {
			if strings.Contains(module, "companies") {
				if err := runCompanyModule(opts.Workspace, module, opts.Company); err != nil {
					return err
				}
			}
		}

		for _, module := range modules {
			if err := runModule(opts.Workspace, module, "default"); err != nil {
				return err
			}
		}
	case reflect.String:
		// install any extra modules not included in "all" ^
		modules, err := localio.ReadLines(opts.Modules.(string))
		if err != nil {
			return err
		}
		if err = installMarketPlaceModules(opts.Workspace, modules); err != nil {
			return err
		}
		if err := configureReconNGDependencies(); err != nil {
			return err
		}
		// run all modules against all base domains
		for _, domain := range h.Domains {
			for _, module := range modules {
				if strings.Contains(module, "domains") || strings.Contains(module, "hackertarget") {
					if err = runModule(opts.Workspace, module, domain); err != nil {
						return err
					}
				}
			}
		}

		for _, netblock := range h.CIDRs {
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

		for _, module := range modules {
			if err = runModule(opts.Workspace, module, "default"); err != nil {
				return err
			}
		}
	}

	if err := generateReport(opts.Workspace, opts.Creator, opts.Company, opts.Output); err != nil {
		return err
	}

	return nil
}
