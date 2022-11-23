package recon

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
	"strconv"
)

// RunAllRecon ...
//nolint:gocognit
func (h *Hosts) RunAllRecon(opts *Options) error {
	localio.PrintInfo("GoRecon", opts.Company, "Running All Recon Modules!")
	if err := localio.PrettyPrint(h); err != nil {
		return localio.LogError(err)
	}

	if opts.RunAmass {
		asnInfo, err := getASNByDomain(opts, h.Domains)
		if err != nil {
			return localio.LogError(err)
		}
		amassData, err := runAmass(opts, h, asnInfo)
		if err != nil {
			return localio.LogError(err)
		}
		if amassData != nil {
			for _, i := range amassData.Data {
				if !localio.Contains(h.Domains, i.Name) {
					h.SubDomains = append(h.SubDomains, i.Name)
				}
				for _, j := range i.Addresses {
					if !localio.Contains(h.ASNs, strconv.Itoa(j.Asn)) {
						h.ASNs = append(h.ASNs, strconv.Itoa(j.Asn))
					}
				}
			}
		}
	}

	// run dnsrecon to start off with because hacking recon is fun :)
	if opts.RunDNSRecon {
		if err := runDNSRecon(h.Domains, opts.Output); err != nil {
			return localio.LogError(err)
		}
	}

	reports, err := h.RunReconNG(opts)
	if err != nil {
		return localio.LogError(err)
	}

	reconNGScope, err := ParseReconNGCSV(&CsvReportFiles{
		hosts:    reports.hosts,
		ports:    reports.ports,
		contacts: reports.contacts,
	}, h.OutOfScope)
	if err != nil {
		return localio.LogError(err)
	}

	var newBaseDomainsFound bool
	for _, domain := range reconNGScope.Domains {
		if !localio.Contains(h.Domains, domain) {
			if inScope := h.isDomainInScope(domain); inScope {
				newBaseDomainsFound = true
				h.Domains = append(h.Domains, domain)
			}
		}
	}

	subs, err := runSubfinder(h.Domains, opts)
	if err != nil {
		return localio.LogError(err)
	}

	var urls []string
	if newBaseDomainsFound {
		localio.PrintInfo("Recon-ng", "Running Recon-ng", "New Base Domains found! Re-running recon-ng")
		thoroughReports, err := h.ThoroughReconNG(opts)
		if err != nil {
			return localio.LogError(err)
		}
		scope, err := ParseReconNGCSV(&CsvReportFiles{
			hosts:    thoroughReports.hosts,
			ports:    thoroughReports.ports,
			contacts: thoroughReports.contacts,
		}, h.OutOfScope)
		if err != nil {
			return localio.LogError(err)
		}
		urls, err = GenerateURLs(scope, h, subs)
		if err != nil {
			return localio.LogError(err)
		}
	} else {
		urls, err = GenerateURLs(reconNGScope, h, subs)
		if err != nil {
			return localio.LogError(err)
		}
	}
	if err = localio.WriteStructToJSONFile(h, fmt.Sprintf("%s/gorecon-scope.json", opts.Output)); err != nil {
		return localio.LogError(err)
	}

	if err = runHTTPX(urls, opts.Output); err != nil {
		return localio.LogError(err)
	}

	outputCSV, err := runHTTPXOutputCSV(urls, opts.Output)
	if err != nil {
		return localio.LogError(err)
	}

	urlFile, err := WriteHttpxURLsToFile(outputCSV, opts.Output)
	if err != nil {
		return err
	}

	// fast content-discovery
	if err = runKatana(urlFile, opts); err != nil {
		return localio.LogError(err)
	}

	if err = runGoWitness(urlFile, opts.Output); err != nil {
		return localio.LogError(err)
	}

	return nil
}
