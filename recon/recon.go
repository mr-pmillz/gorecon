package recon

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gorecon/localio"
)

func (h *Hosts) RunAllRecon(opts *Options) error {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	gologger.Info().Str("GoRecon", opts.Company).Msg("Running All Recon Modules!")
	if err := localio.PrettyPrint(h); err != nil {
		return err
	}
	//if err := h.RunReconNG(opts); err != nil {
	//	return err
	//}

	return nil
}
