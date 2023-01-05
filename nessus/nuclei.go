package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
	"sort"
)

// generateURLs parses all web service URLs from a .nessus xml file and returns a sorted slice of unique URLs
func generateURLs(n *Data) ([]string, error) {
	var allWebURLs []string
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if info.SvcName == "www" {
				switch {
				case info.Port == 443:
					allWebURLs = append(allWebURLs, fmt.Sprintf("https://%s", reportHost.Name))
				case info.Port == 80:
					allWebURLs = append(allWebURLs, fmt.Sprintf("http://%s", reportHost.Name))
				case info.Port != 443 && info.Port != 80:
					allWebURLs = append(allWebURLs, fmt.Sprintf("http://%s:%d", reportHost.Name, info.Port))
					allWebURLs = append(allWebURLs, fmt.Sprintf("https://%s:%d", reportHost.Name, info.Port))
				}
			}
		}
	}

	sort.Sort(localio.StringSlice(allWebURLs))
	return localio.RemoveDuplicateStr(allWebURLs), nil
}

// runNuclei runs nuclei against all www SvcName items from parsed Nessus data
// runs all critical,high,medium severity templates
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

	nucleiOutput := fmt.Sprintf("%s/web/nuclei-severity-scan.txt", opts.Output)
	nucleiRawOutput := fmt.Sprintf("%s/web/nuclei-severity-scan-color.txt", opts.Output)
	homedir, err := os.UserHomeDir()
	if err != nil {
		return localio.LogError(err)
	}
	nucleiSeverityScanCMD := fmt.Sprintf("%s -l %s -no-interactsh -stats -t %s/nuclei-templates/ -severity critical,high,medium -o %s | tee %s", nucleiBin, nessusURLs, homedir, nucleiOutput, nucleiRawOutput)

	if err = localio.RunCommandPipeOutput(fmt.Sprintf("%s -update-templates", nucleiBin)); err != nil {
		return localio.LogError(err)
	}

	if err = localio.RunCommandPipeOutput(nucleiSeverityScanCMD); err != nil {
		return localio.LogError(err)
	}

	return nil
}
