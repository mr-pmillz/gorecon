package nessus

import (
	"encoding/xml"
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
	"github.com/olekukonko/tablewriter"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
func printTable(n *DataNessus, opts *Options) error {
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
	items := map[string][]string{}
	for _, reportHost := range n.Report.ReportHosts {
		for _, info := range reportHost.ReportItems {
			if info.RiskFactor == "None" {
				continue
			}

			affectedHostsPluginID[info.PluginID] = append(affectedHostsPluginID[info.PluginID], fmt.Sprintf("%s:%d", reportHost.Name, info.Port))
			items[info.PluginName] = []string{info.PluginName, info.PluginID, info.RiskFactor, strconv.FormatBool(info.ExploitAvailable), fmt.Sprintf("%f", info.CVSSBaseScore)}
		}
	}

	row := make(bySeverity, 0, len(items))
	scanStats := &ScanStats{}
	for finding, info := range items {
		sortedHosts := localio.SortIPs(affectedHostsPluginID[info[1]])
		outputFileName := strings.ToLower(strings.Join(strings.Split(clearString(finding), " "), "-"))
		absOutputFilePathHosts := fmt.Sprintf("%s/%s_%s-%s-hosts.txt", opts.Output, info[2], info[1], outputFileName)
		CVSSFloat, _ := strconv.ParseFloat(info[4], 64)
		row = append(row, Entry{
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
	}
	sort.Sort(sort.Reverse(row))

	for _, i := range row {
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

// getNessusData Unmarshals nessus file to *DataNessus struct
func getNessusData(nessusFile string) (*DataNessus, error) {
	r := &DataNessus{}
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

// Parse parses the nessus file and prints the results table
func Parse(opts *Options) error {
	data, err := getNessusData(opts.NessusFile)
	if err != nil {
		return localio.LogError(err)
	}

	if err = printTable(data, opts); err != nil {
		return localio.LogError(err)
	}
	if opts.TestSSL {
		if err = runTestSSL(opts.Output, true); err != nil {
			return localio.LogError(err)
		}
	}

	return nil
}

// DataNessus contains a nessus report.
type DataNessus struct {
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
