package recon

import (
	"bufio"
	"bytes"
	_ "embed" // single file embed
	"encoding/json"
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/mr-pmillz/tail"
	"os"
	"strings"
	"text/template"
)

type AmassConfigOptions struct {
	OutputDirectory      string
	ScopeIP              string
	ScopeCIDR            string
	ScopeASN             string
	DomainScope          string
	OutOfScopeSubdomains string
	DataSources          string
}

// getASNs ...
func getASNs(asnInfo *ASNMapScope) []string {
	asnSlice := make([]string, 0, len(asnInfo.DomainASN))
	for _, i := range asnInfo.DomainASN {
		var asn string
		if strings.HasPrefix(i.AsNumber, "AS") {
			asn = strings.ReplaceAll(i.AsNumber, "AS", "")
		} else {
			asn = i.AsNumber
		}

		asnSlice = append(asnSlice, fmt.Sprintf("asn = %s\n", asn))
	}
	return asnSlice
}

type AmassResults struct {
	Data []AmassData
}

type AmassData struct {
	Name      string      `json:"name,omitempty"`
	Domain    string      `json:"domain,omitempty"`
	Addresses []Addresses `json:"addresses,omitempty"`
	Tag       string      `json:"tag,omitempty"`
	Sources   []string    `json:"sources,omitempty"`
}
type Addresses struct {
	IP   string `json:"ip,omitempty"`
	Cidr string `json:"cidr,omitempty"`
	Asn  int    `json:"asn,omitempty"`
	Desc string `json:"desc,omitempty"`
}

// parseAmassResults ...
func parseAmassResults(jsonFilePath string) (*AmassResults, error) {
	amassResults := AmassResults{}
	f, err := os.Open(jsonFilePath)
	if err != nil {
		return nil, localio.LogError(err)
	}
	defer f.Close()

	jsonData := bufio.NewScanner(f)

	var data AmassData
	for jsonData.Scan() {
		if err = json.Unmarshal(jsonData.Bytes(), &data); err != nil {
			return nil, localio.LogError(err)
		}
		amassResults.Data = append(amassResults.Data, data)
	}

	if jsonData.Err() != nil {
		return nil, localio.LogError(err)
	}
	return &amassResults, nil
}

// cleanupTail cleans up tail process.
func cleanupTail(t *tail.Tail) {
	_ = t.Stop()
	defer t.Cleanup()
}

// runAmass ...
func runAmass(opts *Options, scope *Hosts, asnInfo *ASNMapScope) (*AmassResults, error) {
	amassConfig, err := setupAmass(opts, scope, asnInfo)
	if err != nil {
		return nil, localio.LogError(err)
	}

	jsonOutput := fmt.Sprintf("%s/amass/enum.json", opts.Output)
	textOutput := fmt.Sprintf("%s/amass/enum.txt", opts.Output)
	amassTXT := fmt.Sprintf("%s/amass/amass.txt", opts.Output)
	// ensure output files are removed in case of re-running with same output dir.
	for _, f := range []string{jsonOutput, textOutput, amassTXT} {
		if exists, err := localio.Exists(f); err == nil && exists {
			if err = os.Remove(f); err != nil {
				localio.LogWarningf("couldn't remove file: %s\n%+v", f, err)
			}
		}
	}

	enumCMD := fmt.Sprintf("amass enum -config %s -ipv4 -noalts -norecursive -json %s &> %s", amassConfig, jsonOutput, textOutput)
	localio.Infof("Running Amass. This command takes a while, around 10 - 20 minutes depending on the size of the target network.\nBe patient. Tailing this funky file for you!")
	// tail amasses output for show while you report for dough!
	t, err := tail.TailFile(textOutput, tail.Config{
		MustExist: false,
		Follow:    true,
	})
	if err != nil {
		localio.LogWarningf("couldn't tail file: %s\n%+v", amassTXT, err)
	}
	go func() {
		for line := range t.Lines {
			fmt.Println(line.Text)
		}
	}()

	if err = localio.RunCommandPipeOutput(enumCMD); err != nil {
		// if amass fails, ignore error and continue reconnaissance
		localio.LogWarningf("problem running amass\n%s\n%+v\ncontinuing recon", enumCMD, err)
		return nil, nil
	}
	cleanupTail(t)
	// show the results
	if err = localio.RunCommandPipeOutput(fmt.Sprintf("amass db -config %s -show -ip", amassConfig)); err != nil {
		localio.LogWarningf("couldn't show amass db results:\n %+v", err)
		return nil, nil
	}

	amassData, err := parseAmassResults(jsonOutput)
	if err != nil {
		return nil, localio.LogError(err)
	}
	if err = localio.WriteStructToJSONFile(amassData, fmt.Sprintf("%s/amass/enum_formatted.json", opts.Output)); err != nil {
		return nil, localio.LogError(err)
	}

	return amassData, nil
}

// setupAmass ...
func setupAmass(opts *Options, scope *Hosts, asnInfo *ASNMapScope) (string, error) {
	// install amass
	if _, exists := localio.CommandExists("amass"); !exists {
		if err := localio.RunCommandPipeOutput("GO111MODULE=on go install -v github.com/OWASP/Amass/v3/...@master"); err != nil {
			return "", localio.LogError(err)
		}
	}

	amassConfigData, err := formatDataSources(opts, scope, asnInfo)
	if err != nil {
		return "", localio.LogError(err)
	}
	amassConfigINI, err := generateAmassConfig(amassConfigData)
	if err != nil {
		return "", localio.LogError(err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", localio.LogError(err)
	}
	amassConfigDir := fmt.Sprintf("%s/.config/amass", homeDir)
	if err = os.MkdirAll(amassConfigDir, os.ModePerm); err != nil {
		return "", localio.LogError(err)
	}
	amassConfigFilePath := fmt.Sprintf("%s/gorecon-amass-config.ini", amassConfigDir)
	if err = localio.CopyStringToFile(amassConfigINI, amassConfigFilePath); err != nil {
		return "", localio.LogError(err)
	}

	return amassConfigFilePath, nil
}

func formatConfigEntries(entries []string) string {
	if len(entries) == 0 {
		return "#\n"
	}
	return strings.Join(entries, "\n")
}

// formatDataSources ...
func formatDataSources(opts *Options, scope *Hosts, asnInfo *ASNMapScope) (*AmassConfigOptions, error) {
	a := &AmassConfigOptions{}
	amassOutputDir := fmt.Sprintf("%s/amass", opts.Output)
	if err := os.MkdirAll(amassOutputDir, os.ModePerm); err != nil {
		return nil, localio.LogError(err)
	}
	a.OutputDirectory = amassOutputDir

	var ips []string
	var cidrs []string
	domains := []string{"[scope.domains]"}
	outOfScopeSubdomains := []string{"[scope.blacklisted]"}
	for _, i := range scope.CIDRs {
		parts := strings.Split(i, "/")
		if localio.Contains(parts, "32") {
			ips = append(ips, fmt.Sprintf("address = %s", parts[0]))
		} else {
			cidrs = append(cidrs, fmt.Sprintf("cidr = %s", i))
		}
	}
	for _, cidr := range asnInfo.DomainASN {
		cidrs = append(cidrs, fmt.Sprintf("cidr = %s", cidr.AsRange))
	}

	a.ScopeIP = formatConfigEntries(ips)
	a.ScopeCIDR = formatConfigEntries(cidrs)
	a.ScopeASN = formatConfigEntries(getASNs(asnInfo))
	for _, i := range scope.Domains {
		domains = append(domains, fmt.Sprintf("domain = %s", i))
	}
	a.DomainScope = formatConfigEntries(domains)

	for _, i := range scope.OutOfScopeSubdomains {
		outOfScopeSubdomains = append(outOfScopeSubdomains, fmt.Sprintf("subdomain = %s", i))
	}
	a.OutOfScopeSubdomains = formatConfigEntries(outOfScopeSubdomains)

	dataSources, err := localio.ReadLines(opts.AmassDataSources)
	if err != nil {
		return nil, localio.LogError(err)
	}
	a.DataSources = strings.Join(dataSources, "\n")

	return a, nil
}

//go:embed templates/amass-config.ini
var amassConfigTemplate string

// generateAmassConfig generates an amass config.ini file with scope and all free api keys which are optional but recommended.
func generateAmassConfig(opts *AmassConfigOptions) (string, error) {
	amassConfig, err := template.New("amassConfig").Parse(amassConfigTemplate)
	if err != nil {
		return "", localio.LogError(err)
	}
	var amassConfigBuf bytes.Buffer
	if err = amassConfig.Execute(&amassConfigBuf, AmassConfigOptions{
		OutputDirectory:      opts.OutputDirectory,
		ScopeIP:              opts.ScopeIP,
		ScopeCIDR:            opts.ScopeCIDR,
		ScopeASN:             opts.ScopeASN,
		DomainScope:          opts.DomainScope,
		OutOfScopeSubdomains: opts.OutOfScopeSubdomains,
		DataSources:          opts.DataSources,
	}); err != nil {
		return "", localio.LogError(err)
	}

	return amassConfigBuf.String(), nil
}
