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
	_ = reconNGScope

	return nil
}
