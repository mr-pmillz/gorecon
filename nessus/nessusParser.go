package nessus

import (
	"bytes"
	_ "embed" // single file embed
	"encoding/xml"
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/olekukonko/tablewriter"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

var nonAlphanumericRegex = regexp.MustCompile(`[^.a-zA-Z0-9 ]+`)

func clearString(str string) string {
	return nonAlphanumericRegex.ReplaceAllString(str, "")
}

// writeHostsToFile ...
func writeHostsToFile(pluginName, pluginID, severity, output string, hosts []string) error {
	outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(pluginName), " "), "-"))
	absOutputFilePath := fmt.Sprintf("%s/%s_%s-%s-hosts.txt", output, severity, pluginID, outputFileName)
	if err := localio.WriteLines(hosts, absOutputFilePath); err != nil {
		return localio.LogError(err)
	}
	return nil
}

// writeHostsToFileNoPorts ...
func writeHostsToFileNoPorts(pluginName, pluginID, severity, output string, hosts []string) error {
	outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(pluginName), " "), "-"))
	noPortsOutputDir := fmt.Sprintf("%s/findings_hosts_no_ports", output)
	if err := os.MkdirAll(noPortsOutputDir, os.ModePerm); err != nil {
		return localio.LogError(err)
	}
	absOutputFilePath := fmt.Sprintf("%s/findings_hosts_no_ports/%s_%s-%s-hosts-no-ports.txt", output, severity, pluginID, outputFileName)
	if err := localio.WriteLines(hosts, absOutputFilePath); err != nil {
		return localio.LogError(err)
	}
	return nil
}

type ScanStats struct {
	TotalCritical int
	TotalHigh     int
	TotalMedium   int
	TotalLow      int
}

type Row struct {
	Finding          string
	PluginID         string
	Severity         string
	CVSSBaseScore    float64
	ExploitAvailable string
	Count            string
	Hosts            string
	FileName         string
}

type Entry struct {
	key   string
	value *Row
}

type bySeverity []Entry

func (s bySeverity) Len() int           { return len(s) }
func (s bySeverity) Less(i, j int) bool { return s[i].value.CVSSBaseScore < s[j].value.CVSSBaseScore }
func (s bySeverity) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// printTable creates a formatted table containing findings sorted from Critical to Low
// writes table to file and to stdout
func printTable(n *Data, opts *Options) error {
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Finding", "Plugin ID", "Severity", "Exploit Available", "Count", "Hosts"})
	table.SetBorder(false)

	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor, tablewriter.BgBlackColor},
	)

	table.SetColumnColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.Normal},
	)

	affectedHostsPluginID := map[string][]string{}
	affectedHostsNoPortsPluginID := map[string][]string{}
	items := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if info.RiskFactor == "None" {
				continue
			}

			affectedHostsPluginID[info.PluginID] = append(affectedHostsPluginID[info.PluginID], fmt.Sprintf("%s:%d", reportHost.Name, info.Port))
			affectedHostsNoPortsPluginID[info.PluginID] = append(affectedHostsNoPortsPluginID[info.PluginID], reportHost.Name)
			items[info.PluginName] = []string{info.PluginName, info.PluginID, info.RiskFactor, strconv.FormatBool(info.ExploitAvailable), fmt.Sprintf("%f", info.CVSSBaseScore)}
		}
	}

	rows := make(bySeverity, 0, len(items))
	scanStats := &ScanStats{}
	for finding, info := range items {
		sort.Sort(localio.StringSlice(affectedHostsPluginID[info[1]]))
		sortedHosts := localio.RemoveDuplicateStr(affectedHostsPluginID[info[1]])
		sort.Strings(affectedHostsNoPortsPluginID[info[1]])
		sortedHostsNoPorts := localio.RemoveDuplicateStr(affectedHostsNoPortsPluginID[info[1]])
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		absOutputFilePathHosts := fmt.Sprintf("%s/%s_%s-%s-hosts.txt", opts.Output, info[2], info[1], outputFileName)
		CVSSFloat, _ := strconv.ParseFloat(info[4], 64)
		rows = append(rows, Entry{
			key: finding,
			value: &Row{
				Finding:          finding,
				PluginID:         info[1],
				Severity:         info[2],
				ExploitAvailable: info[3],
				CVSSBaseScore:    CVSSFloat,
				Count:            strconv.Itoa(len(sortedHosts)),
				Hosts:            absOutputFilePathHosts,
			},
		})
		scanStats = setStats(info[2], *scanStats)

		if err := writeHostsToFile(finding, info[1], info[2], opts.Output, sortedHosts); err != nil {
			return localio.LogError(err)
		}
		if err := writeHostsToFileNoPorts(finding, info[1], info[2], opts.Output, sortedHostsNoPorts); err != nil {
			return localio.LogError(err)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].value.CVSSBaseScore > rows[j].value.CVSSBaseScore
	})

	for _, i := range rows {
		colorData := []string{
			i.key,
			i.value.PluginID,
			i.value.Severity,
			i.value.ExploitAvailable,
			i.value.Count,
			i.value.Hosts,
		}
		table.Rich(colorData, []tablewriter.Colors{
			{tablewriter.Normal},
			{tablewriter.Normal},
			getSeverityColor(i.value.Severity),
			{tablewriter.Normal},
			{tablewriter.Normal},
			{tablewriter.Normal},
		})
	}

	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_LEFT,
	})

	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.SetFooter([]string{
		"VULNERABILITY STATS",
		fmt.Sprintf("Critical: %d", scanStats.TotalCritical),
		fmt.Sprintf("High: %d", scanStats.TotalHigh),
		fmt.Sprintf("Medium: %d", scanStats.TotalMedium),
		fmt.Sprintf("Low: %d", scanStats.TotalLow),
		fmt.Sprintf("TOTAL: %d", scanStats.TotalCritical+scanStats.TotalHigh+scanStats.TotalMedium+scanStats.TotalLow),
	})
	table.SetFooterAlignment(tablewriter.ALIGN_LEFT)
	table.Render()

	fmt.Println(tableString.String())
	if err := localio.WriteStringToFile(fmt.Sprintf("%s/nessus_table_output.txt", opts.Output), tableString.String()); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// getPriorityColor ...
func getSeverityColor(severity string) tablewriter.Colors {
	switch severity {
	case "Critical":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}
	case "High":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor}
	case "Medium":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor}
	case "Low":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor}
	default:
		return tablewriter.Colors{tablewriter.Bold, tablewriter.Normal}
	}
}

// setStats populates the ScanStats structure
func setStats(severity string, scanStats ScanStats) *ScanStats {
	switch severity {
	case "Critical":
		scanStats.TotalCritical++
	case "High":
		scanStats.TotalHigh++
	case "Medium":
		scanStats.TotalMedium++
	case "Low":
		scanStats.TotalLow++
	default:
		// Do Nothing
	}
	return &scanStats
}

// getNessusData Unmarshals nessus file to *NessusData struct
func getNessusData(nessusFile string) (*Data, error) {
	r := &Data{}
	nesFile, err := os.OpenFile(nessusFile, os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, localio.LogError(err)
	}
	defer nesFile.Close()

	data, err := io.ReadAll(nesFile)
	if err != nil {
		return nil, localio.LogError(err)
	}

	if err = xml.Unmarshal(data, r); err != nil {
		return nil, localio.LogError(err)
	}
	return r, nil
}

// getAllTargetsOpenPorts ...
func getAllTargetsOpenPorts(n *Data, protocol string) (map[string][]string, error) {
	allTargetsOpenPorts := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if info.Port != 0 && info.Protocol == protocol {
				if !localio.Contains(allTargetsOpenPorts[reportHost.Name], strconv.Itoa(info.Port)) {
					allTargetsOpenPorts[reportHost.Name] = append(allTargetsOpenPorts[reportHost.Name], strconv.Itoa(info.Port))
					allTargetsOpenPorts[reportHost.Name] = localio.RemoveDuplicateStr(allTargetsOpenPorts[reportHost.Name])
					sort.Sort(localio.StringSlice(allTargetsOpenPorts[reportHost.Name]))
				}
			}
		}
	}

	return allTargetsOpenPorts, nil
}

// getTargetsByPorts ...
func getTargetsByPorts(n *Data, ports []string, protocol string) (map[string][]string, error) {
	targets := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if localio.Contains(ports, strconv.Itoa(info.Port)) && info.Protocol == protocol {
				if !localio.Contains(targets[reportHost.Name], strconv.Itoa(info.Port)) {
					targets[reportHost.Name] = append(targets[reportHost.Name], strconv.Itoa(info.Port))
					targets[reportHost.Name] = localio.RemoveDuplicateStr(targets[reportHost.Name])
					sort.Sort(localio.StringSlice(targets[reportHost.Name]))
				}
			}
		}
	}

	return targets, nil
}

// getTargetsBySVCName ...
func getTargetsBySVCName(n *Data, svcKinds []string, protocol string) (map[string][]string, error) {
	targets := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if localio.Contains(svcKinds, info.SvcName) && info.Protocol == protocol {
				if !localio.Contains(targets[reportHost.Name], strconv.Itoa(info.Port)) {
					targets[reportHost.Name] = append(targets[reportHost.Name], strconv.Itoa(info.Port))
					targets[reportHost.Name] = localio.RemoveDuplicateStr(targets[reportHost.Name])
					sort.Sort(localio.StringSlice(targets[reportHost.Name]))
				}
			}
		}
	}

	return targets, nil
}

type NmapTargetInfo struct {
	Target   string
	TCPPorts []string
	UDPPorts []string
	Scripts  string
	SVCName  string
}

// newNmapTargetInfo ...
func newNmapTargetInfo(d *Data, svcKinds []string) ([]NmapTargetInfo, error) {
	var n []NmapTargetInfo
	for _, reportHost := range d.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			nt := &NmapTargetInfo{}
			switch {
			case localio.Contains(svcKinds, info.SvcName) && info.Protocol == "tcp":
				nt.Target = reportHost.Name
				nt.TCPPorts = append(nt.TCPPorts, strconv.Itoa(info.Port))
				nt.SVCName = info.SvcName
				if script, ok := ScriptMaps[info.SvcName]; ok {
					nt.Scripts = script
				}
				n = append(n, *nt)
			case localio.Contains(svcKinds, info.SvcName) && info.Protocol == "udp":
				nt.Target = reportHost.Name
				nt.UDPPorts = append(nt.UDPPorts, strconv.Itoa(info.Port))
				nt.SVCName = info.SvcName
				if script, ok := ScriptMaps[info.SvcName]; ok {
					nt.Scripts = script
				}
			}
		}
	}
	for _, target := range n {
		uniqueTCPPorts := localio.RemoveDuplicateStr(target.TCPPorts)
		uniqueUDPPorts := localio.RemoveDuplicateStr(target.UDPPorts)
		sort.Sort(localio.StringSlice(uniqueTCPPorts))
		sort.Sort(localio.StringSlice(uniqueUDPPorts))
		target.TCPPorts = uniqueTCPPorts
		target.UDPPorts = uniqueUDPPorts
	}

	return n, nil
}

//go:embed templates/sslReportTable.html
var sslReportTable string

type HTMLReportRows struct {
	Key      string
	PluginID string
	Hosts    string
}

// generateNessusSSLTLSReportHTMLFile writes an HTML report file with all the Nessus SSL & TLS Findings.
func generateNessusSSLTLSReportHTMLFile(n *Data, outputDir string) (*bySeverity, error) {
	tlsAndSSLPluginIDs := []string{"81606", "69551", "15901", "57582", "83738", "51192", "35291", "124410", "20007", "89058", "60108", "31705", "26928", "83875", "78479", "104743", "157288", "45411", "42873", "65821"}
	affectedHostsPluginID := map[string][]string{}
	items := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if localio.Contains(tlsAndSSLPluginIDs, info.PluginID) {
				affectedHostsPluginID[info.PluginID] = append(affectedHostsPluginID[info.PluginID], fmt.Sprintf("%s:%d", reportHost.Name, info.Port))
				items[info.PluginName] = []string{info.PluginName, info.PluginID, info.RiskFactor, strconv.FormatBool(info.ExploitAvailable), fmt.Sprintf("%f", info.CVSSBaseScore)}
			}
		}
	}

	rows := make(bySeverity, 0, len(items))
	for finding, info := range items {
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		relativeOutputFilePathHosts := fmt.Sprintf("%s_%s-%s-hosts.txt", info[2], info[1], outputFileName)
		sort.Sort(localio.StringSlice(affectedHostsPluginID[info[1]]))
		sortedHosts := localio.RemoveDuplicateStr(affectedHostsPluginID[info[1]])
		CVSSFloat, _ := strconv.ParseFloat(info[4], 64)
		rows = append(rows, Entry{
			key: finding,
			value: &Row{
				Finding:       finding,
				PluginID:      info[1],
				CVSSBaseScore: CVSSFloat,
				Hosts:         strings.Join(sortedHosts, "<br>"),
				Count:         strconv.Itoa(len(sortedHosts)),
				FileName:      relativeOutputFilePathHosts,
			},
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].value.CVSSBaseScore > rows[j].value.CVSSBaseScore
	})
	var htmlRows []HTMLReportRows
	for _, i := range rows {
		switch {
		case len(strings.Split(i.value.Hosts, "<br>")) > 50:
			htmlRows = append(htmlRows, HTMLReportRows{
				Key:      i.key,
				PluginID: i.value.PluginID,
				Hosts:    fmt.Sprintf("<b>Count:</b> %s<br><b>Filename:</b> %s", i.value.Count, i.value.FileName),
			})
		default:
			htmlRows = append(htmlRows, HTMLReportRows{
				Key:      i.key,
				PluginID: i.value.PluginID,
				Hosts:    i.value.Hosts,
			})
		}
	}

	templateFuncs := template.FuncMap{"rangeStruct": RangeStructer}

	t := template.New("t").Funcs(templateFuncs)
	t, err := t.Parse(htmlTemplate)
	if err != nil {
		return nil, localio.LogError(err)
	}

	var sslTemplateBuf bytes.Buffer
	if err = t.Execute(&sslTemplateBuf, htmlRows); err != nil {
		return nil, localio.LogError(err)
	}

	reportTemplate, err := template.New("reportTemplate").Parse(sslReportTable)
	if err != nil {
		return nil, localio.LogError(err)
	}

	var reportTemplateBuf bytes.Buffer
	if err = reportTemplate.Execute(&reportTemplateBuf, SSLTLSRows{
		Rows: sslTemplateBuf.String(),
	}); err != nil {
		return nil, localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return nil, localio.LogError(err)
	}

	if err = localio.CopyStringToFile(reportTemplateBuf.String(), fmt.Sprintf("%s/ssl/nessusSSLTLSReport.html", outputDir)); err != nil {
		return nil, localio.LogError(err)
	}

	return &rows, nil
}

type SSLTLSRows struct {
	Rows string
}

// RangeStructer takes the first argument, which must be a struct, and
// returns the value of each field in a slice. It will return nil
// if there are no arguments or first argument is not a struct
func RangeStructer(args ...interface{}) []interface{} {
	if len(args) == 0 {
		return nil
	}

	v := reflect.ValueOf(args[0])
	if v.Kind() != reflect.Struct {
		return nil
	}

	out := make([]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		out[i] = v.Field(i).Interface()
	}

	return out
}

// writeSMBHostsToFile ...
func writeSMBHostsToFile(data *Data, outputDir string) error {
	targets, err := getTargetsByPorts(data, []string{"139", "445"}, "tcp")
	if err != nil {
		return localio.LogError(err)
	}
	udpTargets, err := getTargetsByPorts(data, []string{"137"}, "udp")
	if err != nil {
		return localio.LogError(err)
	}

	var targetList []string //nolint:prealloc
	for target := range targets {
		targetList = append(targetList, target)
	}
	for udpTarget := range udpTargets {
		targetList = append(targetList, udpTarget)
	}

	uniqueTargets := localio.RemoveDuplicateStr(targetList)
	sort.Sort(localio.StringSlice(uniqueTargets))

	if len(uniqueTargets) != 0 {
		if err = os.MkdirAll(fmt.Sprintf("%s/smb", outputDir), os.ModePerm); err != nil {
			return localio.LogError(err)
		}
		if err = localio.WriteLines(uniqueTargets, fmt.Sprintf("%s/smb/nessus-smb-hosts.txt", outputDir)); err != nil {
			return localio.LogError(err)
		}
	}

	return nil
}

// Parse parses the nessus file and prints the results table
//
//nolint:gocognit
func Parse(opts *Options) error {
	data, err := getNessusData(opts.NessusFile)
	if err != nil {
		return localio.LogError(err)
	}
	absOutputPath, err := localio.ResolveAbsPath(opts.Output)
	if err != nil {
		return localio.LogError(err)
	}
	opts.Output = absOutputPath

	if err = printTable(data, opts); err != nil {
		return localio.LogError(err)
	}

	if err = writeSMBHostsToFile(data, opts.Output); err != nil {
		return localio.LogError(err)
	}

	switch {
	case opts.TestSSL:
		_, err = generateNessusSSLTLSReportHTMLFile(data, opts.Output)
		if err != nil {
			return localio.LogError(err)
		}
		if err = runTestSSL(opts.Output, true); err != nil {
			return localio.LogError(err)
		}
		if err = generateWeakSSLTLSFindingsReportHTMLFile(opts.Output); err != nil {
			return localio.LogError(err)
		}
		if err = generateSSLTLSVulnerabilityFindingsReportHTMLFile(opts.Output); err != nil {
			return localio.LogError(err)
		}
		if err = generateCertificateErrorsSSLTLSFindingsReportHTMLFile(opts.Output); err != nil {
			return localio.LogError(err)
		}
	case opts.StreamNmap:
		targets, err := getAllTargetsOpenPorts(data, "tcp")
		if err != nil {
			return localio.LogError(err)
		}
		if err = streamNmap(targets, opts.Output); err != nil {
			return localio.LogError(err)
		}
	case opts.AsyncNmap:
		targets, err := getAllTargetsOpenPorts(data, "tcp")
		if err != nil {
			return localio.LogError(err)
		}
		if err = runNmapAsync(opts.Output, targets); err != nil {
			return localio.LogError(err)
		}
	case opts.AsyncNmapSVCScripts:
		// runs nmap scripts based upon services
		if err = runNmapServiceScripts(opts.Output, data); err != nil {
			return localio.LogError(err)
		}
	case opts.Nuclei:
		if err = runNuclei(data, opts); err != nil {
			return localio.LogError(err)
		}
	case opts.Enum4LinuxNG:
		if err = runEnum4LinuxNG(data, opts.Output); err != nil {
			return localio.LogError(err)
		}
		if err = runCrackMapExecSMB(opts.Output); err != nil {
			return localio.LogError(err)
		}
	default:
		// Do Nothing.
	}

	return nil
}

// Data contains a nessus report.
type Data struct {
	Report Report `xml:"Report"`
}

// Report has a name and contains all the host details.
type Report struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}

// ReportHost containts the hostname or ip address for the host and
// all vulnerability and service information.
type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

// HostProperties are tags filled with likely useless information.
type HostProperties struct {
	Tags []Tag `xml:"tag"`
}

// Tag is used to split the tag into name and the tag content.
type Tag struct {
	Name string `xml:"name,attr"`
	Data string `xml:",chardata"`
}

// ReportItem is vulnerability plugin output.
//
//nolint:staticcheck
type ReportItem struct {
	Port                       int      `xml:"port,attr"`
	SvcName                    string   `xml:"svc_name,attr"`
	Protocol                   string   `xml:"protocol,attr"`
	Severity                   int      `xml:"severity,attr"`
	PluginID                   string   `xml:"pluginID,attr"`
	PluginName                 string   `xml:"pluginName,attr"`
	PluginFamily               string   `xml:"pluginFamily,attr"`
	PluginType                 string   `xml:"plugin_type,name"`
	PluginVersion              string   `xml:"plugin_version"`
	Fname                      string   `xml:"fname,name"`
	RiskFactor                 string   `xml:"risk_factor,name"`
	Synopsis                   string   `xml:"synopsis,name"`
	Description                string   `xml:"description,name"`
	Solution                   string   `xml:"solution,name"`
	PluginOutput               string   `xml:"plugin_output,name"`
	SeeAlso                    string   `xml:"see_also,name"`
	CVE                        []string `xml:"cve,name"`
	BID                        []string `xml:"bid,name"`
	XREF                       []string `xml:"xref,name"`
	PluginModificationDate     string   `xml:"plugin_modification_date,name"`
	PluginPublicationDate      string   `xml:"plugin_publication_date,name"`
	VulnPublicationDate        string   `xml:"vuln_publication_date,name"`
	ExploitabilityEase         string   `xml:"exploitability_ease,name"`
	ExploitAvailable           bool     `xml:"exploit_available,name"`
	ExploitFrameworkCanvas     bool     `xml:"exploit_framework_canvas,name"`
	ExploitFrameworkMetasploit bool     `xml:"exploit_framework_metasploit,name"`
	ExploitFrameworkCore       bool     `xml:"exploit_framework_core,name"`
	MetasploitName             string   `xml:"metasploit_name,name"`
	CanvasPackage              string   `xml:"canvas_package,name"`
	CoreName                   string   `xml:"core_name,name"`
	CVSSVector                 string   `xml:"cvss_vector,name"`
	CVSSBaseScore              float64  `xml:"cvss_base_score,name"`
	CVSSTemporalScore          string   `xml:"cvss_temporal_score,name"`
	ComplianceResult           string   `xml:"cm:compliance-result,name"`
	ComplianceActualValue      string   `xml:"cm:compliance-actual-value,name"`
	ComplianceCheckID          string   `xml:"cm:compliance-check-id,name"`
	ComplianceAuditFile        string   `xml:"cm:compliance-audit-file,name"`
	ComplianceCheckValue       string   `xml:"cm:compliance-check-name,name"`
}
