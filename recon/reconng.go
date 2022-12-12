package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/mr-pmillz/gorecon/v2/localio"
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
		"certifi",
		"pyyaml",
		"dnspython",
		"lxml",
		"mechanize",
		"requests",
		"flask",
		"flask-restful",
		"flasgger",
		"dicttoxml",
		"XlsxWriter",
		"unicodecsv",
		"rq",
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
		"recon/domains-contacts/hunter_io",
		"reporting/csv",
		"reporting/html",
		"reporting/list",
	}
	for _, module := range modules {
		if !localio.Contains(ignoreModules, module) && !isContactsModule(module) {
			if err := runModule(workspace, module, "default"); err != nil {
				return localio.LogError(err)
			}
		}
	}
	return nil
}

// isContactsModule ...
func isContactsModule(module string) bool {
	parts := strings.Split(module, "/")
	if len(parts) > 0 && len(parts) <= 2 {
		moduleType := parts[1]
		modParts := strings.Split(moduleType, "-")
		if localio.Contains(modParts, "contacts") {
			return true
		}
	}
	return false
}

// runContactsModules runs all contacts modules after gathering emails via hunterio
func runContactsModules(workspace string, modules []string) error {
	// first run hunterio to gather emails and populate the contacts db.
	hunterIO := "recon/domains-contacts/hunter_io"
	if localio.Contains(modules, hunterIO) {
		if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -m %s -o source=default -o count=100 -x", workspace, hunterIO)); err != nil {
			return localio.LogError(err)
		}
	}

	// now check for any other contacts modules and run them except for hunter_io
	var contactModules []string
	for _, module := range modules {
		if isContactsModule(module) && module != hunterIO {
			contactModules = append(contactModules, module)
		}
	}

	for _, contactModule := range contactModules {
		if err := runModule(workspace, contactModule, "default"); err != nil {
			return localio.LogError(err)
		}
	}

	return nil
}

func setUserAgent(workspace string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("recon-cli -w %s -C \"options set USER-AGENT Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0\"", workspace)); err != nil {
		return err
	}
	return nil
}

func installMarketPlaceModules(workspace string) error {
	// refresh install all modules
	marketPlaceRefreshAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace refresh\"", workspace)
	marketPlaceInstallAllCMD := fmt.Sprintf("recon-cli -w %s -C \"marketplace install all\"", workspace)
	cmds := []string{marketPlaceRefreshAllCMD, marketPlaceInstallAllCMD}
	if err := localio.RunCommandsPipeOutput(cmds); err != nil {
		return err
	}
	return nil
}

// insertCompany ...
func insertCompany(workspace, company string) error {
	command := fmt.Sprintf("recon-cli -w %s -C \"db query insert into companies (company) select '%s' where not exists (select 1 from companies where company='%s');\"", workspace, company, company)
	if err := localio.RunCommandPipeOutput(command); err != nil {
		return err
	}
	return nil
}

// insertDomains ...
func insertDomains(workspace string, domains []string, primaryDomainIsSubdomain bool) error {
	// keep count to prevent too many domains from being inserted into the recon-ng domains db table
	// TODO: improve reconng.go scope handling of *Hosts Structure.
	count := 0
	var insertedDomains []string
	for _, i := range domains {
		switch {
		case count >= 3:
			break
		case isBaseDomain(i) && !primaryDomainIsSubdomain && !localio.Contains(insertedDomains, i):
			count++
			command := fmt.Sprintf("recon-cli -w %s \"-C db query insert into domains (domain) select '%s' where not exists (select 1 from domains where domain='%s');\"", workspace, i, i)
			if err := localio.RunCommandPipeOutput(command); err != nil {
				return err
			}
			insertedDomains = append(insertedDomains, i)
		case !isBaseDomain(i) && primaryDomainIsSubdomain && !localio.Contains(insertedDomains, i):
			count++
			command := fmt.Sprintf("recon-cli -w %s \"-C db query insert into domains (domain) select '%s' where not exists (select 1 from domains where domain='%s');\"", workspace, i, i)
			if err := localio.RunCommandPipeOutput(command); err != nil {
				return err
			}
			insertedDomains = append(insertedDomains, i)
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
//
//nolint:gocognit
func generateReport(workspace, creator, company, output string) (*CsvReportFiles, error) {
	workReportDir, err := localio.ResolveAbsPath(output)
	if err != nil {
		return nil, err
	}
	reportFormats := []string{"reporting/csv", "reporting/html", "reporting/list"}
	csvReportCategories := []string{"hosts", "ports", "contacts", "credentials"}
	timestamp := time.Now().Format("01-02-2006")
	csvReportFiles := &CsvReportFiles{}

	if err = os.MkdirAll(filepath.Dir(workReportDir), 0750); err != nil {
		return nil, err
	}

	for _, report := range reportFormats {
		_company := strings.ReplaceAll(company, " ", "_")
		ext := strings.Split(report, "/")[1]
		switch ext {
		case "csv":
			for _, category := range csvReportCategories {
				reportFilePath := fmt.Sprintf("%s/recon-ng-%s-%s-%s.%s", workReportDir, _company, category, timestamp, ext)
				switch category {
				case "hosts":
					csvReportFiles.hosts = reportFilePath
				case "ports":
					csvReportFiles.ports = reportFilePath
				case "contacts":
					csvReportFiles.contacts = reportFilePath
				default:
					// Do Nothing
				}
				cmd := fmt.Sprintf("recon-cli -w %s -m %s -o \"HEADERS = True\" -o \"TABLE = %s \" -o \"FILENAME=%s\" -x", workspace, report, category, reportFilePath)
				if err = localio.RunCommandPipeOutput(cmd); err != nil {
					return nil, err
				}
			}
		case "html":
			reportFilePath := fmt.Sprintf("%s/recon-ng-%s-%s.%s", workReportDir, _company, timestamp, ext)
			command := fmt.Sprintf("recon-cli -w %s -m %s -o \"CREATOR = %s\" -o \"CUSTOMER = %s\" -o \"FILENAME=%s\" -x", workspace, report, creator, company, reportFilePath)
			if err = localio.RunCommandPipeOutput(command); err != nil {
				return nil, err
			}

			if !localio.IsHeadless() {
				htmlReport := fmt.Sprintf("%s/recon-ng-%s-%s.%s", workReportDir, _company, timestamp, ext)
				if err = localio.RunCommandPipeOutput(fmt.Sprintf("firefox %s", htmlReport)); err != nil {
					return nil, err
				}
			}
		case "list":
			hostIps := fmt.Sprintf("%s/recon-ng-%s-hosts-ip-addresses-%s.txt", workReportDir, _company, timestamp)
			hostDomains := fmt.Sprintf("%s/recon-ng-%s-hosts-hosts-%s.txt", workReportDir, _company, timestamp)
			portsIps := fmt.Sprintf("%s/recon-ng-%s-ports-ips-%s.txt", workReportDir, _company, timestamp)
			portsHost := fmt.Sprintf("%s/recon-ng-%s-ports-hosts-ip-%s.txt", workReportDir, _company, timestamp)
			portsPort := fmt.Sprintf("%s/recon-ng-%s-ports-ports-%s.txt", workReportDir, _company, timestamp)
			contactsEmails := fmt.Sprintf("%s/recon-ng-%s-emails-%s.txt", workReportDir, _company, timestamp)
			hostIPsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = hosts\" -o \"COLUMN = ip_address\" -x", workspace, report, hostIps)
			hostDomainsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = hosts\" -o \"COLUMN = host\" -x", workspace, report, hostDomains)
			portsIPsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = ports\" -o \"COLUMN = ip_address\" -x", workspace, report, portsIps)
			portsHostsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = ports\" -o \"COLUMN = host\" -x", workspace, report, portsHost)
			portsPortsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = ports\" -o \"COLUMN = port\" -x", workspace, report, portsPort)
			contactsEmailsCMD := fmt.Sprintf("recon-cli -w %s -m %s -o \"FILENAME=%s\" -o \"TABLE = contacts\" -o \"COLUMN = email\" -x", workspace, report, contactsEmails)
			if err = localio.RunCommandsPipeOutput([]string{
				hostIPsCMD,
				hostDomainsCMD,
				portsIPsCMD,
				portsHostsCMD,
				portsPortsCMD,
				contactsEmailsCMD,
			}); err != nil {
				return nil, err
			}
		default:
			// Do Nothing
		}
	}
	return csvReportFiles, nil
}

// setupWorkspace configures the recon-ng workspace and installs all modules.
func setupWorkspace(workspace, company string, domains, subs, netblocks []string, primaryDomainIsSubdomain bool) error {
	if err := insertCompany(workspace, company); err != nil {
		return err
	}

	if err := insertDomains(workspace, domains, primaryDomainIsSubdomain); err != nil {
		return err
	}

	if err := insertDomains(workspace, subs, primaryDomainIsSubdomain); err != nil {
		return err
	}

	if len(netblocks) >= 1 {
		if err := insertNetblocks(workspace, netblocks); err != nil {
			return err
		}
	}

	if err := setUserAgent(workspace); err != nil {
		return err
	}

	if err := installMarketPlaceModules(workspace); err != nil {
		return err
	}
	// Ensure recon-ng deps and censysio modules are installed.
	if err := configureReconNGDependencies(); err != nil {
		return err
	}
	return nil
}

// ThoroughReconNG Runs recon-ng a second time inserting any new base domains if found.
// If no new base domains were found. Skip.
func (h *Hosts) ThoroughReconNG(opts *Options) (*CsvReportFiles, error) {
	if err := insertDomains(opts.Workspace, h.Domains, opts.PrimaryDomainIsSubdomain); err != nil {
		return nil, err
	}

	rt := reflect.TypeOf(opts.Modules)
	switch rt.Kind() {
	case reflect.Slice:
		modules := opts.Modules.([]string)

		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}
	case reflect.String:
		modules, err := localio.ReadLines(opts.Modules.(string))
		if err != nil {
			return nil, err
		}

		if err = runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}
	}

	csvReports, err := generateReport(opts.Workspace, opts.Creator, opts.Company, opts.Output)
	if err != nil {
		return nil, err
	}

	return csvReports, nil
}

// RunReconNG runs all specified modules against the target domain
func (h *Hosts) RunReconNG(opts *Options) (*CsvReportFiles, error) {
	localio.PrintInfo("workspace", opts.Workspace, "Running Recon-ng")
	if err := setupWorkspace(opts.Workspace, opts.Company, h.Domains, h.SubDomains, h.CIDRs, opts.PrimaryDomainIsSubdomain); err != nil {
		return nil, err
	}

	rt := reflect.TypeOf(opts.Modules)
	switch rt.Kind() {
	case reflect.Slice:
		modules := opts.Modules.([]string)

		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}

		if err := runContactsModules(opts.Workspace, modules); err != nil {
			return nil, err
		}
		// run default modules a second time to ensure nothing was missed
		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}
	case reflect.String:
		var modules []string
		if exists, err := localio.Exists(opts.Modules.(string)); err == nil && exists {
			modules, err = localio.ReadLines(opts.Modules.(string))
			if err != nil {
				return nil, err
			}
		} else {
			modules = append(modules, opts.Modules.(string))
		}

		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}

		if err := runContactsModules(opts.Workspace, modules); err != nil {
			return nil, err
		}
		// run default modules a second time to ensure nothing was missed
		if err := runModulesDefault(opts.Workspace, modules); err != nil {
			return nil, err
		}
	}

	csvReports, err := generateReport(opts.Workspace, opts.Creator, opts.Company, opts.Output)
	if err != nil {
		return nil, err
	}

	return csvReports, nil
}
