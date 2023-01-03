package nessus

import (
	"bytes"
	_ "embed" // single file embed
	"encoding/json"
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

// setup ...
func setup(outputDir string) ([]string, error) {
	hosts, err := writeAllSslTLSHostsToFile(outputDir)
	if err != nil {
		return nil, localio.LogError(err)
	}

	if err = localio.GitCloneDepthOne("https://github.com/drwetter/testssl.sh.git", "/tmp/testssl.sh"); err != nil {
		return nil, localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return nil, localio.LogError(err)
	}

	return hosts, nil
}

// runTestSSL runs Testssl.sh concurrently
func runTestSSL(outputDir string, verbose bool) error {
	hosts, err := setup(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	startTLSServices := map[int]string{
		25:   "smtp",
		563:  "nntp",
		587:  "smtp",
		636:  "ldap",
		993:  "imap",
		995:  "pop3",
		2000: "sieve",
		2525: "smtp",
		3268: "ldap",
		3269: "ldap",
		3306: "mysql",
		4190: "sieve",
		5432: "postgres",
	}

	localio.Infof("Running Testssl.sh against %d hosts\nBe patient, Testssl.sh is running in parallel. Stdout won't appear until after a scan is completed, approx. 60 seconds...\n %+v", len(hosts), hosts)
	// Common channel for the goroutines
	tasks := make(chan *exec.Cmd, len(hosts))

	var wg sync.WaitGroup

	// Spawn 5 goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(num int, w *sync.WaitGroup) {
			defer w.Done()
			var (
				out []byte
				err error
			)
			for cmd := range tasks {
				out, err = cmd.Output()
				if err != nil {
					localio.LogWarningf("can't get stdout: %+v", err)
				}
				if verbose {
					fmt.Println(string(out))
				}
			}
		}(i, &wg)
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		localio.LogWarningf("could not get bash path %+v", err)
	}
	for _, host := range hosts {
		port := strings.Split(host, ":")[1]
		portInt, err := strconv.Atoi(port)
		if err != nil {
			return localio.LogError(err)
		}
		var command string
		if startTLSService, ok := startTLSServices[portInt]; ok {
			command = fmt.Sprintf("cd /tmp/testssl.sh && ./testssl.sh --quiet --warnings batch -oA %s/ssl --starttls %s %s", outputDir, startTLSService, host)
		} else {
			command = fmt.Sprintf("cd /tmp/testssl.sh && ./testssl.sh --quiet --warnings batch -oA %s/ssl %s", outputDir, host)
		}

		localio.LogInfo("Command", command, "")
		tasks <- exec.Command(bashPath, "-c", command)
	}
	close(tasks)
	// wait for the workers to finish
	wg.Wait()

	return nil
}

// writeAllSslTlsHostsToFile writes all sorted unique ssl and tls hosts to a file
// returns a slice of sorted ssl and tls IPs.
// TODO don't generate TLS/SSL hosts from files, grab directly from parsed nessus. TODO
func writeAllSslTLSHostsToFile(outputDir string) ([]string, error) {
	files, err := localio.FilePathWalkDir(outputDir)
	if err != nil {
		return nil, localio.LogError(err)
	}

	var sslTLSHosts []string
	for _, f := range files {
		base := filepath.Base(f)
		parts := strings.Split(base, "-")
		if base != "all-tls-ssl-hosts.txt" && !strings.Contains(base, "no-ports") {
			if localio.Contains(parts, "ssl") || localio.Contains(parts, "tls") {
				if ips, err := localio.ReadLines(f); err == nil {
					sslTLSHosts = append(sslTLSHosts, ips...)
				}
			}
		}
	}

	sslTLSHosts = localio.RemoveDuplicateStr(sslTLSHosts)
	allSslTLSHosts := fmt.Sprintf("%s/all-tls-ssl-hosts.txt", outputDir)
	if err = localio.WriteLines(sslTLSHosts, allSslTLSHosts); err != nil {
		return nil, localio.LogError(err)
	}

	return sslTLSHosts, nil
}

// parseTestSSLResults ...
func parseTestSSLResults(outputDir string) (*TestSSLReports, error) {
	files, err := localio.FilePathWalkDir(fmt.Sprintf("%s/ssl", outputDir))
	if err != nil {
		return nil, localio.LogError(err)
	}
	var jsonFiles []string
	for _, f := range files {
		if strings.HasSuffix(f, ".json") {
			jsonFiles = append(jsonFiles, f)
		}
	}

	combinedReport := &TestSSLReports{}
	for _, j := range jsonFiles {
		var t TestSSLReport
		data, err := os.ReadFile(j)
		if err != nil {
			return nil, localio.LogError(err)
		}
		if err = json.Unmarshal(data, &t); err != nil {
			continue
		}
		combinedReport.Report = append(combinedReport.Report, t)
	}

	return combinedReport, nil
}

type TestSSLReports struct {
	Report []TestSSLReport
}

type TestSSLReport struct {
	Invocation string `json:"Invocation,omitempty"`
	At         string `json:"at,omitempty"`
	Version    string `json:"version,omitempty"`
	Openssl    string `json:"openssl,omitempty"`
	StartTime  string `json:"startTime,omitempty"`
	ScanResult []struct {
		TargetHost string `json:"targetHost,omitempty"`
		IP         string `json:"ip,omitempty"`
		Port       string `json:"port,omitempty"`
		RDNS       string `json:"rDNS,omitempty"`
		Service    string `json:"service,omitempty"`
		Pretest    []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"pretest,omitempty"`
		Protocols []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Cve      string `json:"cve,omitempty"`
			Cwe      string `json:"cwe,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"protocols,omitempty"`
		Grease  []interface{} `json:"grease,omitempty"`
		Ciphers []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Cwe      string `json:"cwe,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"ciphers,omitempty"`
		ServerPreferences []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"serverPreferences,omitempty"`
		Fs []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"fs,omitempty"`
		ServerDefaults []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"serverDefaults,omitempty"`
		HeaderResponse []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
			Cwe      string `json:"cwe,omitempty"`
		} `json:"headerResponse,omitempty"`
		Vulnerabilities []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Cve      string `json:"cve,omitempty"`
			Cwe      string `json:"cwe,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"vulnerabilities,omitempty"`
		CipherTests        []interface{} `json:"cipherTests,omitempty"`
		BrowserSimulations []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"browserSimulations,omitempty"`
		Rating []struct {
			ID       string `json:"id,omitempty"`
			Severity string `json:"severity,omitempty"`
			Finding  string `json:"finding,omitempty"`
		} `json:"rating,omitempty"`
	} `json:"scanResult,omitempty"`
	ScanTime int `json:"scanTime,omitempty"`
}

type TestSSLEntry struct {
	key   string
	value *Row
}

type testSSLFindings []TestSSLEntry

//go:embed templates/server-supports-weak-ssl-tls-protocols-or-ciphers.html
var testSSLReportTable string

type TestSSLHTMLReportRows struct {
	Key   string
	Hosts string
}

// generateWeakSSLTLSFindingsReportHTMLFile writes an HTML report file with all the Testssl.sh confirmed Findings.
//
//nolint:gocognit
func generateWeakSSLTLSFindingsReportHTMLFile(outputDir string) error {
	testSSLReports, err := parseTestSSLResults(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	affectedHosts := map[string][]string{}
	items := map[string][]string{}
	for _, report := range testSSLReports.Report {
		for _, info := range report.ScanResult {
			for _, protocol := range info.Protocols {
				switch {
				case protocol.ID == "SSLv2" && protocol.Severity != OK && protocol.Severity != INFO && protocol.Severity != LOW:
					affectedHosts[protocol.ID] = append(affectedHosts[protocol.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["SSL 2.0 Protocol Supported"] = []string{"SSL 2.0 Protocol Supported", protocol.ID, protocol.Finding, protocol.Severity}
				case protocol.ID == "SSLv3" && protocol.Severity != OK && protocol.Severity != INFO && protocol.Severity != LOW:
					affectedHosts[protocol.ID] = append(affectedHosts[protocol.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["SSL 3.0 Protocol Supported"] = []string{"SSL 3.0 Protocol Supported", protocol.ID, protocol.Finding, protocol.Severity}
				case protocol.ID == "TLS1" && protocol.Severity != OK && protocol.Severity != INFO:
					affectedHosts[protocol.ID] = append(affectedHosts[protocol.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["TLS 1.0 Protocol Supported"] = []string{"TLS 1.0 Protocol Supported", protocol.ID, protocol.Finding, protocol.Severity}
				case protocol.ID == "TLS1_1" && protocol.Severity != OK && protocol.Severity != INFO:
					affectedHosts[protocol.ID] = append(affectedHosts[protocol.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["TLS 1.1 Protocol Supported"] = []string{"TLS 1.1 Protocol Supported", protocol.ID, protocol.Finding, protocol.Severity}
				}
			}
			for _, cipher := range info.ServerPreferences {
				if cipher.Severity != OK && cipher.Severity != INFO {
					affectedHosts[cipher.ID] = append(affectedHosts[cipher.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Weak Ciphers"] = []string{"Weak Ciphers", cipher.ID, cipher.Finding, cipher.Severity}
				}
			}
			for _, cipher := range info.Ciphers {
				if cipher.Severity != OK && cipher.Severity != INFO {
					affectedHosts[cipher.ID] = append(affectedHosts[cipher.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Weak Ciphers"] = []string{"Weak Ciphers", cipher.ID, cipher.Finding, cipher.Severity}
				}
			}
		}
	}

	rows := make(testSSLFindings, 0, len(items))
	for finding, info := range items {
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		relativeOutputFilePathHosts := fmt.Sprintf("confirmed-%s-hosts.txt", outputFileName)
		absOutputFilePathHosts := fmt.Sprintf("%s/ssl/confirmed-%s-hosts.txt", outputDir, outputFileName)
		sort.Sort(localio.StringSlice(affectedHosts[info[1]]))
		sortedHosts := localio.RemoveDuplicateStr(affectedHosts[info[1]])
		rows = append(rows, TestSSLEntry{
			key: finding,
			value: &Row{
				Finding:  finding,
				Hosts:    strings.Join(sortedHosts, "<br>"),
				Count:    strconv.Itoa(len(sortedHosts)),
				FileName: relativeOutputFilePathHosts,
			},
		})
		if err := localio.WriteLines(sortedHosts, absOutputFilePathHosts); err != nil {
			return localio.LogError(err)
		}
	}

	var htmlRows []TestSSLHTMLReportRows
	for _, i := range rows {
		switch {
		case len(strings.Split(i.value.Hosts, "<br>")) > 50:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: fmt.Sprintf("<b>Count:</b> %s<br><b>Filename:</b> %s", i.value.Count, i.value.FileName),
			})
		default:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: i.value.Hosts,
			})
		}
	}
	sort.SliceStable(htmlRows, func(i, j int) bool {
		switch strings.Compare(htmlRows[i].Key, htmlRows[j].Key) {
		case -1:
			return true
		case 1:
			return false
		}
		return htmlRows[i].Key > htmlRows[j].Key
	})

	templateFuncs := template.FuncMap{"rangeStruct": RangeStructer}

	t := template.New("t").Funcs(templateFuncs)
	t, err = t.Parse(htmlTemplate)
	if err != nil {
		return localio.LogError(err)
	}

	var sslTemplateBuf bytes.Buffer
	if err = t.Execute(&sslTemplateBuf, htmlRows); err != nil {
		return localio.LogError(err)
	}

	reportTemplate, err := template.New("reportTemplate").Parse(testSSLReportTable)
	if err != nil {
		return localio.LogError(err)
	}

	var reportTemplateBuf bytes.Buffer
	if err = reportTemplate.Execute(&reportTemplateBuf, SSLTLSRows{
		Rows: sslTemplateBuf.String(),
	}); err != nil {
		return localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return localio.LogError(err)
	}

	if err = localio.CopyStringToFile(reportTemplateBuf.String(), fmt.Sprintf("%s/ssl/server-supports-weak-transport-layer-security-report.html", outputDir)); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// generateSSLTLSVulnerabilityFindingsReportHTMLFile writes an HTML report file with all the Testssl.sh confirmed Vulnerability findings.
// TODO: Rather than duplicating this function, re-write it in a re-usable universal way to prevent code duplication
// For now, duplicating code is faster and easier ¯\_(ツ)_/¯
//
//nolint:gocognit
func generateSSLTLSVulnerabilityFindingsReportHTMLFile(outputDir string) error {
	testSSLReports, err := parseTestSSLResults(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	affectedHosts := map[string][]string{}
	items := map[string][]string{}
	for _, report := range testSSLReports.Report {
		for _, info := range report.ScanResult {
			for _, vuln := range info.Vulnerabilities {
				switch {
				case vuln.ID == "heartbleed" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["heartbleed"] = []string{"heartbleed", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "CCS" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["CCS"] = []string{"CCS", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "ticketbleed" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["ticketbleed"] = []string{"ticketbleed", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "ROBOT" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["ROBOT"] = []string{"ROBOT", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "secure_renego" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["secure_renego"] = []string{"secure_renego", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "secure_client_renego" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["secure_client_renego"] = []string{"secure_client_renego", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "CRIME_TLS" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["CRIME_TLS"] = []string{"CRIME_TLS", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "BREACH" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["BREACH"] = []string{"BREACH", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "POODLE_SSL" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["POODLE_SSL"] = []string{"POODLE_SSL", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "fallback_SCSV" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["fallback_SCSV"] = []string{"fallback_SCSV", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "SWEET32" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["SWEET32"] = []string{"SWEET32", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "FREAK" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["FREAK"] = []string{"FREAK", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "DROWN" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["DROWN"] = []string{"DROWN", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "DROWN_hint" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["DROWN_hint"] = []string{"DROWN_hint", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "LOGJAM-common_primes" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["LOGJAM-common_primes"] = []string{"LOGJAM-common_primes", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "LOGJAM" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["LOGJAM"] = []string{"LOGJAM", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "BEAST" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["BEAST"] = []string{"BEAST", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "LUCKY13" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["LUCKY13"] = []string{"LUCKY13", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "winshock" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["winshock"] = []string{"winshock", vuln.ID, vuln.Finding, vuln.Severity}
				case vuln.ID == "RC4" && vuln.Severity != OK && vuln.Severity != INFO:
					affectedHosts[vuln.ID] = append(affectedHosts[vuln.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["RC4"] = []string{"RC4", vuln.ID, vuln.Finding, vuln.Severity}
				}
			}
		}
	}

	rows := make(testSSLFindings, 0, len(items))
	for finding, info := range items {
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		relativeOutputFilePathHosts := fmt.Sprintf("confirmed-%s-vulnerability-hosts.txt", outputFileName)
		absOutputFilePathHosts := fmt.Sprintf("%s/ssl/confirmed-%s-vulnerability-hosts.txt", outputDir, outputFileName)
		sort.Sort(localio.StringSlice(affectedHosts[info[1]]))
		sortedHosts := localio.RemoveDuplicateStr(affectedHosts[info[1]])
		rows = append(rows, TestSSLEntry{
			key: finding,
			value: &Row{
				Finding:  finding,
				Hosts:    strings.Join(sortedHosts, "<br>"),
				Count:    strconv.Itoa(len(sortedHosts)),
				FileName: relativeOutputFilePathHosts,
			},
		})
		if err := localio.WriteLines(sortedHosts, absOutputFilePathHosts); err != nil {
			return localio.LogError(err)
		}
	}

	var htmlRows []TestSSLHTMLReportRows
	for _, i := range rows {
		switch {
		case len(strings.Split(i.value.Hosts, "<br>")) > 50:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: fmt.Sprintf("<b>Count:</b> %s<br><b>Filename:</b> %s", i.value.Count, i.value.FileName),
			})
		default:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: i.value.Hosts,
			})
		}
	}
	sort.SliceStable(htmlRows, func(i, j int) bool {
		switch strings.Compare(htmlRows[i].Key, htmlRows[j].Key) {
		case -1:
			return true
		case 1:
			return false
		}
		return htmlRows[i].Key > htmlRows[j].Key
	})

	templateFuncs := template.FuncMap{"rangeStruct": RangeStructer}

	t := template.New("t").Funcs(templateFuncs)
	t, err = t.Parse(htmlTemplate)
	if err != nil {
		return localio.LogError(err)
	}

	var sslTemplateBuf bytes.Buffer
	if err = t.Execute(&sslTemplateBuf, htmlRows); err != nil {
		return localio.LogError(err)
	}

	reportTemplate, err := template.New("reportTemplate").Parse(testSSLReportTable)
	if err != nil {
		return localio.LogError(err)
	}

	var reportTemplateBuf bytes.Buffer
	if err = reportTemplate.Execute(&reportTemplateBuf, SSLTLSRows{
		Rows: sslTemplateBuf.String(),
	}); err != nil {
		return localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return localio.LogError(err)
	}

	if err = localio.CopyStringToFile(reportTemplateBuf.String(), fmt.Sprintf("%s/ssl/testssl-tls-ssl-vulnerabilities-report.html", outputDir)); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// generateWeakSSLTLSFindingsReportHTMLFile writes an HTML report file with all the Testssl.sh confirmed Findings.
// TODO: Rather than duplicating this function, re-write it in a re-usable universal way to prevent code duplication
// For now, duplicating code is faster and easier ¯\_(ツ)_/¯
//
//nolint:gocognit
func generateCertificateErrorsSSLTLSFindingsReportHTMLFile(outputDir string) error {
	testSSLReports, err := parseTestSSLResults(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	affectedHosts := map[string][]string{}
	items := map[string][]string{}
	for _, report := range testSSLReports.Report {
		for _, info := range report.ScanResult {
			for _, servDef := range info.ServerDefaults {
				switch {
				case servDef.ID == "cert_chain_of_trust" && servDef.Severity == CRITICAL:
					affectedHosts[servDef.ID] = append(affectedHosts[servDef.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Self-Signed Certificate"] = []string{"Self-Signed Certificate", servDef.ID, servDef.Finding, servDef.Severity}
				case servDef.ID == "cert_trust" && servDef.Severity == HIGH:
					affectedHosts[servDef.ID] = append(affectedHosts[servDef.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Certificate does not match supplied URI"] = []string{"Certificate does not match supplied URI", servDef.ID, servDef.Finding, servDef.Severity}
				case servDef.ID == "cert_subjectAltName" && servDef.Severity == MEDIUM:
					affectedHosts[servDef.ID] = append(affectedHosts[servDef.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Certificate does not match supplied URI"] = []string{"Certificate does not match supplied URI", servDef.ID, servDef.Finding, servDef.Severity}
				case servDef.ID == "cert_signatureAlgorithm" && servDef.Severity == MEDIUM:
					affectedHosts[servDef.ID] = append(affectedHosts[servDef.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Certificate signed using weak signature algorithm SHA1 with RSA"] = []string{"Certificate signed using weak signature algorithm SHA1 with RSA", servDef.ID, servDef.Finding, servDef.Severity}
				case servDef.ID == "cert_revocation" && servDef.Severity == HIGH:
					affectedHosts[servDef.ID] = append(affectedHosts[servDef.ID], fmt.Sprintf("%s:%s", info.TargetHost, info.Port))
					items["Neither CRL nor OCSP URI provided"] = []string{"Neither CRL nor OCSP URI provided", servDef.ID, servDef.Finding, servDef.Severity}
				}
			}
		}
	}

	rows := make(testSSLFindings, 0, len(items))
	for finding, info := range items {
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		relativeOutputFilePathHosts := fmt.Sprintf("confirmed-%s-hosts.txt", outputFileName)
		absOutputFilePathHosts := fmt.Sprintf("%s/ssl/confirmed-%s-hosts.txt", outputDir, outputFileName)
		sort.Sort(localio.StringSlice(affectedHosts[info[1]]))
		sortedHosts := localio.RemoveDuplicateStr(affectedHosts[info[1]])
		rows = append(rows, TestSSLEntry{
			key: finding,
			value: &Row{
				Finding:  finding,
				Hosts:    strings.Join(sortedHosts, "<br>"),
				Count:    strconv.Itoa(len(sortedHosts)),
				FileName: relativeOutputFilePathHosts,
			},
		})
		if err := localio.WriteLines(sortedHosts, absOutputFilePathHosts); err != nil {
			return localio.LogError(err)
		}
	}

	var htmlRows []TestSSLHTMLReportRows
	for _, i := range rows {
		switch {
		case len(strings.Split(i.value.Hosts, "<br>")) > 50:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: fmt.Sprintf("<b>Count:</b> %s<br><b>Filename:</b> %s", i.value.Count, i.value.FileName),
			})
		default:
			htmlRows = append(htmlRows, TestSSLHTMLReportRows{
				Key:   i.key,
				Hosts: i.value.Hosts,
			})
		}
	}
	sort.SliceStable(htmlRows, func(i, j int) bool {
		switch strings.Compare(htmlRows[i].Key, htmlRows[j].Key) {
		case -1:
			return true
		case 1:
			return false
		}
		return htmlRows[i].Key > htmlRows[j].Key
	})

	templateFuncs := template.FuncMap{"rangeStruct": RangeStructer}

	t := template.New("t").Funcs(templateFuncs)
	t, err = t.Parse(htmlTemplate)
	if err != nil {
		return localio.LogError(err)
	}

	var sslTemplateBuf bytes.Buffer
	if err = t.Execute(&sslTemplateBuf, htmlRows); err != nil {
		return localio.LogError(err)
	}

	reportTemplate, err := template.New("reportTemplate").Parse(testSSLReportTable)
	if err != nil {
		return localio.LogError(err)
	}

	var reportTemplateBuf bytes.Buffer
	if err = reportTemplate.Execute(&reportTemplateBuf, SSLTLSRows{
		Rows: sslTemplateBuf.String(),
	}); err != nil {
		return localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return localio.LogError(err)
	}

	if err = localio.CopyStringToFile(reportTemplateBuf.String(), fmt.Sprintf("%s/ssl/certificate-errors-report.html", outputDir)); err != nil {
		return localio.LogError(err)
	}

	return nil
}
