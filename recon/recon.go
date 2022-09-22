package recon

import (
	"fmt"
	"gorecon/localio"
)

func (h *Hosts) RunAllRecon(opts *Options) error {
	fmt.Println("[+] Running All Recon Modules")
	if err := localio.PrettyPrint(h); err != nil {
		return err
	}
	if err := h.RunReconNG(opts); err != nil {
		return err
	}

	return nil
}
