package recon

import (
	"github.com/mr-pmillz/gorecon/localio"
)

func (h *Hosts) RunAllRecon(opts *Options) error {
	localio.PrintInfo("GoRecon", opts.Company, "Running All Recon Modules!")
	if err := localio.PrettyPrint(h); err != nil {
		return err
	}
	reports, err := h.RunReconNG(opts)
	if err != nil {
		return err
	}

	reconNGScope, err := ParseReconNGCSV(&CsvReportFiles{
		hosts:    reports.hosts,
		ports:    reports.ports,
		contacts: reports.contacts,
	})
	if err != nil {
		return err
	}

	subs, err := runSubfinder(reconNGScope.Domains, opts.Output)
	if err != nil {
		return err
	}

	var newBaseDomainsFound bool
	for _, domain := range reconNGScope.Domains {
		if !localio.Contains(h.Domains, domain) {
			newBaseDomainsFound = true
			h.Domains = append(h.Domains, domain)
		}
	}

	var urls []string
	if newBaseDomainsFound {
		localio.PrintInfo("Recon-ng", "Running Recon-ng", "New Base Domains found! Re-running recon-ng")
		thoroughReports, err := h.ThoroughReconNG(opts)
		if err != nil {
			return err
		}
		scope, err := ParseReconNGCSV(&CsvReportFiles{
			hosts:    thoroughReports.hosts,
			ports:    thoroughReports.ports,
			contacts: thoroughReports.contacts,
		})
		if err != nil {
			return err
		}
		urls, err = GenerateURLs(scope, h, subs)
		if err != nil {
			return err
		}
	} else {
		urls, err = GenerateURLs(reconNGScope, h, subs)
		if err != nil {
			return err
		}
	}

	if err = runHTTPX(urls, opts.Output); err != nil {
		return err
	}

	outputCSV, err := runHTTPXOutputCSV(urls, opts.Output)
	if err != nil {
		return err
	}

	if err = runGoWitness(outputCSV, opts.Output); err != nil {
		return err
	}

	// TODO: Run Nuclei with templates/* against all found responsive URLs from httpx output
	// TODO: incorporate URLCrazy, DNSRecon
	// TODO: run Naabu to find open ports. Feed open ports to Nmap to verify service versions
	return nil
}
