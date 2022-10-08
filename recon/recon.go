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

	subs, err := runSubfinder(h.Domains, opts.Output)
	if err != nil {
		return err
	}

	urls, err := GenerateURLs(reconNGScope, h, subs)
	if err != nil {
		return err
	}

	if err = runHTTPX(urls, opts.Output); err != nil {
		return err
	}

	// TODO: see if can hide STDOUT from csv file generation.
	if err = runHTTPXOutputCSV(urls, opts.Output); err != nil {
		return err
	}

	// TODO: Run Nuclei with templates/* against all found responsive URLs from httpx output
	// TODO: Run Eyewitness or GoWitness against responsive URLs from httpx output
	// TODO: Run Parsuite against Nessus file as an optional feature?
	// TODO: incorporate URLCrazy?, DNSRecon?
	// TODO: Automate Gather contacts with BurpSuite as an optional feature?
	// TODO: incorporate testssl.sh?
	// TODO: run Naabu to find open ports. Feed open ports to Nmap to verify service versions

	return nil
}
