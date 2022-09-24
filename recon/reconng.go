package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/mr-pmillz/gorecon/localio"
)

// configureReconNGDependencies installs common missing recon-ng dependencies
// installs required python3 packages not included in recon-ng REQUIREMENTS file
// that are required by various marketplace modules.
// Also fixes censys modules.
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

	if err = copyCensysScripts(); err != nil {
		return err
	}

	return nil
}

// copyCensysScripts fixes issue with censys python3 scripts
// See https://github.com/lanmaster53/recon-ng/issues/149 https://github.com/censys/censys-recon-ng/issues/5
func copyCensysScripts() error {
	// fix missing recon-ng censys modules from https://github.com/censys/censys-recon-ng
	// Manually copy files as the install.sh script included with censys-recon-ng repo does some extra api key adds for censysio that we should ignore.
	if err := localio.GitClone("https://github.com/censys/censys-recon-ng", "/tmp/censys-recon-ng"); err != nil {
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
func runModule(workspace, module, source string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -m %s -o source=%s -x", workspace, module, source)); err != nil {
		return err
	}
	return nil
}

// runModuleDefault runs most recon-ng modules with default source
// ignores modules that rely on custom args or populated categories.
func runModulesDefault(workspace string, modules []string) error {
	ignoreModules := []string{
		"contacts-credentials",
		"recon/contacts-credentials/hibp_breach",
		"recon/contacts-credentials/hibp_paste",
		"recon/contacts-profiles/fullcontact",
		"recon/domains-contacts/hunter_io",
		"reporting",
	}
	for _, module := range modules {
		if !localio.Contains(ignoreModules, module) {
			if err := runModule(workspace, module, "default"); err != nil {
				return err
			}
		}
	}
	return nil
}

// runContactsModules runs all contacts modules after gathering emails via hunterio
func runContactsModules(workspace string) error {
	// first run hunterio to gather emails and populate the contacts db.
	hunterIO := "recon/domains-contacts/hunter_io"
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -m %s -o source=default -o count=1000 -x", workspace, hunterIO)); err != nil {
		return err
	}
	contactModules := []string{
		"recon/contacts-credentials/hibp_breach",
		"recon/contacts-credentials/hibp_paste",
		"recon/contacts-profiles/fullcontact",
	}
	if err := runModulesDefault(workspace, contactModules); err != nil {
		return err
	}
	return nil
}

func setUserAgent(workspace string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -C \"options set USER-AGENT Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0\"", workspace)); err != nil {
		return err
	}
	return nil
}

func installMarketPlaceModules(workspace string, modules []string) error {
	for _, i := range modules {
		if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -C \"marketplace install %s\"", workspace, i)); err != nil {
			return err
		}
	}
	return nil
}

func insertCompany(workspace, company string) error {
	command := fmt.Sprintf("recon-cli -w %s -C \"db query insert into companies (company) select '%s' where not exists (select 1 from companies where company='%s');\"", workspace, company, company)
	if err := localio.RunCommandPipeOutput(command); err != nil {
		return err
	}
	return nil
}

func insertDomains(workspace string, domains []string) error {
	for _, i := range domains {
		command := fmt.Sprintf("recon-cli -w %s \"-C db query insert into domains (domain) select '%s' where not exists (select 1 from domains where domain='%s');\"", workspace, i, i)
		if err := localio.RunCommandPipeOutput(command); err != nil {
			return err
		}
	}

	return nil
}

func insertNetblocks(workspace string, netblocks []string) error {
	for _, i := range netblocks {
		command := fmt.Sprintf("recon-cli -w %s -C \"db query insert into netblocks (netblock) select '%s' where not exists (select 1 from netblocks where netblock='%s');\"", workspace, i, i)
		if err := localio.RunCommandPipeOutput(command); err != nil {
			return err
		}
	}

	return nil
}

// generateReport creates html and csv report files
func generateReport(workspace, creator, company, output string) error {
	workReportDir, err := localio.ResolveAbsPath(output)
	if err != nil {
		return err
	}
	reportFormats := []string{"reporting/csv", "reporting/html"}
	csvReportCategories := []string{"hosts", "ports", "contacts", "credentials"}
	timestamp := time.Now().Format("01-02-2006")

	if exists, err := localio.Exists(filepath.Dir(workReportDir)); err == nil && !exists {
		if err = os.MkdirAll(filepath.Dir(workReportDir), 0750); err != nil {
			return err
		}
	}
	for _, report := range reportFormats {
		ext := strings.Split(report, "/")[1]
		switch ext {
		case "csv":
			for _, category := range csvReportCategories {
				reportFilePath := fmt.Sprintf("%s/recon-ng-%s-%s-%s.%s", workReportDir, company, category, timestamp, ext)
				cmd := fmt.Sprintf("recon-cli -w %s -m %s -o \"HEADERS = True\" -o \"TABLE = %s \" -o FILENAME=%s -x", workspace, report, category, reportFilePath)
				if err = localio.RunCommandPipeOutput(cmd); err != nil {
					return err
				}
			}
		case "html":
			reportFilePath := fmt.Sprintf("-o FILENAME=%s/recon-ng-%s-%s.%s", workReportDir, company, timestamp, ext)
			command := fmt.Sprintf("recon-cli -w %s -m %s -o \"CREATOR = %s\" -o \"CUSTOMER = %s\" -o FILENAME=%s -x", workspace, report, creator, company, reportFilePath)
			if err = localio.RunCommandPipeOutput(command); err != nil {
				return err
			}

			if !localio.IsHeadless() {
				htmlReport := fmt.Sprintf("%s/recon-ng-%s-%s.%s", workReportDir, company, timestamp, ext)
				if err = localio.RunCommandPipeOutput(fmt.Sprintf("firefox %s", htmlReport)); err != nil {
					return err
				}
			}
		default:
			// Do Nothing
		}
	}
	return nil
}

// setupWorkspace configures the recon-ng workspace and installs all modules
func setupWorkspace(workspace, company string, domains, subs, netblocks []string) error {
	if err := insertCompany(workspace, company); err != nil {
		return err
	}

	if err := insertDomains(workspace, domains); err != nil {
		return err
	}

	if err := insertDomains(workspace, subs); err != nil {
		return err
	}

	if err := insertNetblocks(workspace, netblocks); err != nil {
		return err
	}

	if err := setUserAgent(workspace); err != nil {
		return err
	}

	// refresh install all modules
	marketPlaceRefreshAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace refresh\"", workspace)
	marketPlaceInstallAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace install all\"", workspace)
	cmds := []string{marketPlaceRefreshAllCMD, marketPlaceInstallAllCMD}
	if err := localio.RunCommandsPipeOutput(cmds); err != nil {
		return err
	}
	return nil
}

// RunReconNG runs all specified modules against the target domain
func (h *Hosts) RunReconNG(opts *Options) error {
	localio.PrintInfo("workspace", opts.Workspace, "Running Recon-ng")
	if err := setupWorkspace(opts.Workspace, opts.Company, h.Domains, h.SubDomains, h.CIDRs); err != nil {
		return err
	}

	rt := reflect.TypeOf(opts.Modules)
	switch rt.Kind() {
	case reflect.Slice:
		modules := opts.Modules.([]string)
		if err := installMarketPlaceModules(opts.Workspace, modules); err != nil {
			return err
		}

		// Ensure recon-ng deps and censysio modules are installed.
		if err := configureReconNGDependencies(); err != nil {
			return err
		}

		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return err
		}

		if err := runContactsModules(opts.Workspace); err != nil {
			return err
		}
	case reflect.String:
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

		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return err
		}

		if err := runContactsModules(opts.Workspace); err != nil {
			return err
		}
	}

	if err := generateReport(opts.Workspace, opts.Creator, opts.Company, opts.Output); err != nil {
		return err
	}

	return nil
}
