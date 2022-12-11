package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
)

// generateURLs ...
func generateURLs(n *Data) ([]string, error) {
	var allWebURLs []string
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if info.SvcName == "www" && info.RiskFactor != "none" {
				allWebURLs = append(allWebURLs, fmt.Sprintf("http://%s:%d", reportHost.Name, info.Port))
				allWebURLs = append(allWebURLs, fmt.Sprintf("https://%s:%d", reportHost.Name, info.Port))
			}
		}
	}

	return localio.RemoveDuplicateStr(allWebURLs), nil
}

// runNuclei runs nuclei against all www SvcName items from parsed Nessus data
// runs basic automatic scan
// TODO run scans based upon CVE findings from nessus etc...
func runNuclei(n *Data, opts *Options) error {
	urls, err := generateURLs(n)
	if err != nil {
		return localio.LogError(err)
	}

	if err = os.MkdirAll(fmt.Sprintf("%s/web", opts.Output), os.ModePerm); err != nil {
		return localio.LogError(err)
	}
	nessusURLs := fmt.Sprintf("%s/web/nessus_www_urls.txt", opts.Output)
	if err = localio.WriteLines(urls, nessusURLs); err != nil {
		return localio.LogError(err)
	}

	if err := localio.RunCommandPipeOutput("GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"); err != nil {
		return err
	}
	nucleiBin, err := exec.LookPath("nuclei")
	if err != nil {
		return localio.LogError(err)
	}

	nucleiOutput := fmt.Sprintf("%s/web/nuclei-output.txt", opts.Output)
	nucleiRawOutput := fmt.Sprintf("%s/web/nuclei-color-output.txt", opts.Output)
	nucleiAutoScanCMD := fmt.Sprintf("%s -l %s -as -no-interactsh -stats -o %s | tee %s", nucleiBin, nessusURLs, nucleiOutput, nucleiRawOutput)

	if err = localio.RunCommandPipeOutput(fmt.Sprintf("%s -update-templates", nucleiBin)); err != nil {
		return localio.LogError(err)
	}

	if err = localio.RunCommandPipeOutput(nucleiAutoScanCMD); err != nil {
		return localio.LogError(err)
	}

	return nil
}
