package recon

import (
	"gorecon/localio"
)

func (h *Hosts) RunAllRecon(opts *Options) error {
	localio.PrintInfo("GoRecon", opts.Company, "Running All Recon Modules!")
	if err := localio.PrettyPrint(h); err != nil {
		return err
	}
	if err := h.RunReconNG(opts); err != nil {
		return err
	}

	return nil
}
