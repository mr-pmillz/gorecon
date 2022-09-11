package recon

import (
	"fmt"
)

func RunAllRecon(hosts *Hosts, opts *Options) error {
	fmt.Println("[+] Running All Recon Modules")
	if err := RunReconNG(hosts, opts); err != nil {
		return err
	}

	return nil
}
