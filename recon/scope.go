package recon

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/gocarina/gocsv"
	"github.com/jpillora/go-tld"
	"github.com/projectdiscovery/mapcidr"

	"github.com/mr-pmillz/gorecon/localio"
)

type Hosts struct {
	Domains    []string
	SubDomains []string
	CIDRs      []string
	IPv4s      []string
	IPv6s      []string
	OutOfScope []string
}

// getOutOfScope ...
//nolint:gocognit
func getOutOfScope(outtaScope interface{}) ([]string, error) {
	outOfScope := []string{"google", "amazon", "amazonaws", "googlemail", "*", "googlehosted", "cloudfront", "cloudflare", "fastly", "akamai", "sucuri", "microsoft"}
	outOfScopeType := reflect.TypeOf(outtaScope)
	switch outOfScopeType.Kind() {
	case reflect.Slice:
		for _, i := range outtaScope.([]string) {
			switch {
			case valid.IsCIDR(i):
				ips, err := mapcidr.IPAddresses(i)
				if err != nil {
					return nil, localio.LogError(err)
				}
				outOfScope = append(outOfScope, ips...)
			default:
				outOfScope = append(outOfScope, i)
			}
		}
	case reflect.String:
		if outtaScope.(string) != "" {
			if exists, err := localio.Exists(outtaScope.(string)); exists && err == nil {
				outOfScopes, err := localio.ReadLines(outtaScope.(string))
				if err != nil {
					return nil, err
				}
				for _, i := range outOfScopes {
					switch {
					case valid.IsCIDR(i):
						ips, err := mapcidr.IPAddresses(i)
						if err != nil {
							return nil, localio.LogError(err)
						}
						outOfScope = append(outOfScope, ips...)
					default:
						outOfScope = append(outOfScope, i)
					}
				}
			} else {
				outOfScope = append(outOfScope, outtaScope.(string))
			}
		}
	}

	return removeDuplicateStr(outOfScope), nil
}

//nolint:gocognit
//nolint:gocyclo
func NewScope(opts *Options) (*Hosts, error) {
	localio.PrintInfo("Company", opts.Company, "Generating External Scope Information")
	hosts := new(Hosts)
	outOfScopeType := reflect.TypeOf(opts.OutOfScope)
	switch outOfScopeType.Kind() {
	case reflect.Slice:
		hosts.OutOfScope = append(hosts.OutOfScope, opts.OutOfScope.([]string)...)
	case reflect.String:
		if opts.OutOfScope.(string) != "" {
			if exists, err := localio.Exists(opts.OutOfScope.(string)); exists && err == nil {
				outOfScopes, err := localio.ReadLines(opts.OutOfScope.(string))
				if err != nil {
					return nil, err
				}
				hosts.OutOfScope = append(hosts.OutOfScope, outOfScopes...)
			} else {
				hosts.OutOfScope = append(hosts.OutOfScope, opts.OutOfScope.(string))
			}
		}
	}

	// check if domain arg is file, string, or a slice
	rtd := reflect.TypeOf(opts.Domain)
	switch rtd.Kind() {
	case reflect.Slice:
		for _, domain := range opts.Domain.([]string) {
			// check if CIDR, IPv4, IPv6, Subdomain, or primary domain
			// this tld library expects http:// protocol | URL format so prepend it to domain
			d, _ := tld.Parse(fmt.Sprintf("https://%s", domain))
			if d.Subdomain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
				hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
			}
			if d.Domain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
				if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
					hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
				}
			}
		}
	case reflect.String:
		if isfile, err := localio.Exists(opts.Domain.(string)); isfile && err == nil {
			domainList, err := localio.ReadLines(opts.Domain.(string))
			if err != nil {
				return nil, err
			}

			// parse --domain file or string into scope object
			for _, domain := range domainList {
				// check if CIDR, IPv4, IPv6, Subdomain, or primary domain
				// this tld library expects http:// protocol | URL format so prepend it to domain
				d, _ := tld.Parse(fmt.Sprintf("https://%s", domain))
				if d.Subdomain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
					if !localio.Contains(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
						hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
					}
				}
				if d.Domain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
					if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
						hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
					}
				}
			}
		} else {
			d, _ := tld.Parse(fmt.Sprintf("https://%s", opts.Domain.(string)))
			if d.Subdomain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
				if !localio.Contains(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
					hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
				}
			}
			if d.Domain != "" && !localio.Contains(hosts.OutOfScope, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
				if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
					hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
				}
			}
		}
	}
	rtn := reflect.TypeOf(opts.NetBlock)
	switch rtn.Kind() {
	case reflect.Slice:
		for _, netblock := range opts.NetBlock.([]string) {
			if !localio.Contains(hosts.OutOfScope, netblock) {
				switch {
				case valid.IsCIDR(netblock):
					hosts.CIDRs = append(hosts.CIDRs, netblock)
				case valid.IsIPv4(netblock):
					hosts.IPv4s = append(hosts.IPv4s, netblock)
				case valid.IsIPv6(netblock):
					hosts.IPv6s = append(hosts.IPv6s, netblock)
				}
			}
		}
	case reflect.String:
		// parse --netblock file into scope object
		if opts.NetBlock.(string) != "" {
			if exists, err := localio.Exists(opts.NetBlock.(string)); exists && err == nil {
				netblocks, err := localio.ReadLines(opts.NetBlock.(string))
				if err != nil {
					return nil, err
				}
				for _, netblock := range netblocks {
					if !localio.Contains(hosts.OutOfScope, netblock) {
						switch {
						case valid.IsCIDR(netblock):
							hosts.CIDRs = append(hosts.CIDRs, netblock)
						case valid.IsIPv4(netblock):
							hosts.IPv4s = append(hosts.IPv4s, netblock)
						case valid.IsIPv6(netblock):
							hosts.IPv6s = append(hosts.IPv6s, netblock)
						}
					}
				}
			} else if !localio.Contains(hosts.OutOfScope, opts.NetBlock.(string)) {
				switch {
				case valid.IsCIDR(opts.NetBlock.(string)):
					hosts.CIDRs = append(hosts.CIDRs, opts.NetBlock.(string))
				case valid.IsIPv4(opts.NetBlock.(string)):
					hosts.IPv4s = append(hosts.IPv4s, opts.NetBlock.(string))
				case valid.IsIPv6(opts.NetBlock.(string)):
					hosts.IPv6s = append(hosts.IPv6s, opts.NetBlock.(string))
				}
			}
		}
	}

	return hosts, nil
}

// removeDuplicateStr removes duplicate strings from a slice of strings
func removeDuplicateStr(strSlice []string) []string { //nolint:typecheck
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// GenerateURLs creates a slice of http and https urls from recon-ng results scope.
func GenerateURLs(scope *NGScope, h *Hosts, subs []string) ([]string, error) { //nolint:typecheck
	var urls []string //nolint:prealloc
	ignoreDomains := []string{"google", "amazon", "amazonaws", "googlemail", "*", "googlehosted", "cloudfront", "cloudflare", "fastly", "akamai", "sucuri"}
	ignoreDomains = append(ignoreDomains, h.OutOfScope...)

	// create http and https urls from found hosts
	for _, host := range scope.Hosts {
		if !localio.ContainsChars(ignoreDomains, host.Host) && !localio.ContainsChars(ignoreDomains, host.IP) && host.Host != "" && host.IP != "" {
			urls = append(urls, fmt.Sprintf("http://%s", host.Host))
			urls = append(urls, fmt.Sprintf("https://%s", host.Host))
			urls = append(urls, fmt.Sprintf("http://%s", host.IP))
			urls = append(urls, fmt.Sprintf("https://%s", host.IP))
		}
	}
	for _, hostPort := range scope.Ports {
		if !localio.ContainsChars(ignoreDomains, hostPort.Host) && !localio.ContainsChars(ignoreDomains, hostPort.IP) && hostPort.Host != "" && hostPort.IP != "" {
			switch hostPort.Port {
			case "21", "22", "25", "53", "110", "119", "123", "135", "139", "143", "179", "194", "445", "500", "1433", "3389", "5985":
				// Do nothing
			case "80":
				urls = append(urls, fmt.Sprintf("http://%s", hostPort.Host))
				urls = append(urls, fmt.Sprintf("http://%s", hostPort.IP))
			case "443":
				urls = append(urls, fmt.Sprintf("https://%s", hostPort.Host))
				urls = append(urls, fmt.Sprintf("https://%s", hostPort.IP))
			default:
				urls = append(urls, fmt.Sprintf("http://%s:%s/", hostPort.Host, hostPort.Port))
				urls = append(urls, fmt.Sprintf("http://%s:%s/", hostPort.IP, hostPort.Port))
				urls = append(urls, fmt.Sprintf("https://%s:%s/", hostPort.Host, hostPort.Port))
				urls = append(urls, fmt.Sprintf("https://%s:%s/", hostPort.IP, hostPort.Port))
			}
		}
	}
	for _, sub := range subs {
		urls = append(urls, fmt.Sprintf("http://%s", sub))
		urls = append(urls, fmt.Sprintf("https://%s", sub))
	}

	return removeDuplicateStr(urls), nil
}

type HttpxOutputCSV struct {
	Timestamp        string `csv:"timestamp,omitempty"`
	Asn              string `csv:"asn,omitempty"`
	Csp              string `csv:"csp,omitempty"`
	TLSGrab          string `csv:"tls-grab,omitempty"`
	Hashes           string `csv:"hashes,omitempty"`
	Regex            string `csv:"regex,omitempty"`
	CdnName          string `csv:"cdn-name,omitempty"`
	Port             int    `csv:"port,omitempty"`
	URL              string `csv:"url,omitempty"`
	Input            string `csv:"input,omitempty"`
	Location         string `csv:"location,omitempty"`
	Title            string `csv:"title,omitempty"`
	Scheme           string `csv:"scheme,omitempty"`
	Error            string `csv:"error,omitempty"`
	Webserver        string `csv:"webserver,omitempty"`
	ResponseBody     string `csv:"response-body,omitempty"`
	ContentType      string `csv:"content-type,omitempty"`
	Method           string `csv:"method,omitempty"`
	Host             string `csv:"host,omitempty"`
	Path             string `csv:"path,omitempty"`
	FaviconMmh3      string `csv:"favicon-mmh3,omitempty"`
	FinalURL         string `csv:"final-url,omitempty"`
	ResponseHeader   string `csv:"response-header,omitempty"`
	Request          string `csv:"request,omitempty"`
	ResponseTime     string `csv:"response-time,omitempty"`
	Jarm             string `csv:"jarm,omitempty"`
	ChainStatusCodes string `csv:"chain-status-codes,omitempty"`
	A                string `csv:"a,omitempty"`
	Cnames           string `csv:"cnames,omitempty"`
	Technologies     string `csv:"technologies,omitempty"`
	Extracts         string `csv:"extracts,omitempty"`
	Chain            string `csv:"chain,omitempty"`
	Words            int    `csv:"words,omitempty"`
	Lines            int    `csv:"lines,omitempty"`
	StatusCode       int    `csv:"status-code,omitempty"`
	ContentLength    int    `csv:"content-length,omitempty"`
	Failed           bool   `csv:"failed,omitempty"`
	Vhost            bool   `csv:"vhost,omitempty"`
	Websocket        bool   `csv:"websocket,omitempty"`
	Cdn              bool   `csv:"cdn,omitempty"`
	HTTP2            bool   `csv:"http2,omitempty"`
	Pipeline         bool   `csv:"pipeline,omitempty"`
}

// recon-ng csv parser section

type NGScope struct {
	URLs          []string
	URLsWithPorts []string
	Domains       []string
	Hosts         []NGHostsCSV
	Contacts      []NGContactsCSV
	Ports         []NGPortsCSV
	HttpxData     []HttpxOutputCSV
}

type NGPortsCSV struct {
	IP       string `csv:"ip_address"`
	Host     string `csv:"host"`
	Port     string `csv:"port"`
	Protocol string `csv:"protocol"`
	Banner   string `csv:"banner"`
	Notes    string `csv:"notes"`
	Module   string `csv:"module"`
}

type NGContactsCSV struct {
	FirstName  string `csv:"first_name"`
	MiddleName string `csv:"middle_name"`
	LastName   string `csv:"last_name"`
	Email      string `csv:"email"`
	Title      string `csv:"title"`
	Region     string `csv:"region"`
	Country    string `csv:"country"`
	Phone      string `csv:"phone"`
	Notes      string `csv:"notes"`
	Module     string `csv:"module"`
}

type NGHostsCSV struct {
	Host    string `csv:"host"`
	IP      string `csv:"ip_address"`
	Region  string `csv:"region"`
	Country string `csv:"country"`
	Lat     string `csv:"latitude"`
	Long    string `csv:"longitude"`
	Notes   string `csv:"notes"`
	Module  string `csv:"module"`
}

type CsvReportFiles struct {
	hosts    string
	ports    string
	contacts string
}

// ParseHttpxCSV maps the httpx output csv results to a struct
func ParseHttpxCSV(csvFilePath string) (*NGScope, error) {
	scope := NGScope{}
	data, err := os.OpenFile(csvFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer data.Close()

	var httpx []*HttpxOutputCSV

	gocsv.SetCSVReader(gocsv.LazyCSVReader)

	if err = gocsv.UnmarshalFile(data, &httpx); err != nil {
		return nil, err
	}

	if _, err = data.Seek(0, 0); err != nil {
		return nil, err
	}

	for _, i := range httpx {
		scope.HttpxData = append(scope.HttpxData, HttpxOutputCSV{
			Timestamp:        i.Timestamp,
			Asn:              i.Asn,
			Csp:              i.Csp,
			TLSGrab:          i.TLSGrab,
			Hashes:           i.Hashes,
			Regex:            i.Regex,
			CdnName:          i.CdnName,
			Port:             i.Port,
			URL:              i.URL,
			Input:            i.Input,
			Location:         i.Location,
			Title:            i.Title,
			Scheme:           i.Scheme,
			Error:            i.Error,
			Webserver:        i.Webserver,
			ResponseBody:     i.ResponseBody,
			ContentType:      i.ContentType,
			Method:           i.Method,
			Host:             i.Host,
			Path:             i.Path,
			FaviconMmh3:      i.FaviconMmh3,
			FinalURL:         i.FinalURL,
			ResponseHeader:   i.ResponseHeader,
			Request:          i.Request,
			ResponseTime:     i.ResponseTime,
			Jarm:             i.Jarm,
			ChainStatusCodes: i.ChainStatusCodes,
			A:                i.A,
			Cnames:           i.Cnames,
			Technologies:     i.Technologies,
			Extracts:         i.Extracts,
			Chain:            i.Chain,
			Words:            i.Words,
			Lines:            i.Lines,
			StatusCode:       i.StatusCode,
			ContentLength:    i.ContentLength,
			Failed:           i.Failed,
			Vhost:            i.Vhost,
			Websocket:        i.Websocket,
			Cdn:              i.Cdn,
			HTTP2:            i.HTTP2,
			Pipeline:         i.Pipeline,
		})
	}

	return &scope, nil //nolint:typecheck
}

// WriteHttpxURLsToFile writes the httpx responsive urls to a file.
func WriteHttpxURLsToFile(csvFilePath, outputDir string) (string, error) {
	data, err := ParseHttpxCSV(csvFilePath)
	if err != nil {
		return "", err
	}

	var urls []string //nolint:prealloc

	for _, i := range data.HttpxData {
		if i.StatusCode >= 200 && i.StatusCode < 500 && i.StatusCode != 404 {
			urls = append(urls, i.URL)
		}
	}

	outputFilePath := fmt.Sprintf("%s/httpx-responsive-urls.txt", outputDir)

	if err = localio.WriteLines(urls, outputFilePath); err != nil {
		return "", err
	}

	return outputFilePath, nil
}

// ParseReconNGCSV ...
func ParseReconNGCSV(csvFiles *CsvReportFiles, outOfScope []string) (*NGScope, error) { //nolint:typecheck
	scope := NGScope{}
	ports, err := os.OpenFile(csvFiles.ports, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer ports.Close()

	var p []*NGPortsCSV

	gocsv.SetCSVReader(gocsv.LazyCSVReader)

	if err = gocsv.UnmarshalFile(ports, &p); err != nil {
		return nil, err
	}

	if _, err = ports.Seek(0, 0); err != nil {
		return nil, err
	}

	for _, i := range p {
		if isInScope(i.IP, outOfScope) && isInScope(i.Host, outOfScope) {
			scope.Ports = append(scope.Ports, NGPortsCSV{
				IP:       i.IP,
				Host:     i.Host,
				Port:     i.Port,
				Protocol: i.Protocol,
				Banner:   i.Banner,
				Notes:    i.Notes,
				Module:   i.Module,
			})
		}
	}

	reportHosts, err := os.OpenFile(csvFiles.hosts, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer reportHosts.Close()

	var h []*NGHostsCSV

	if err = gocsv.UnmarshalFile(reportHosts, &h); err != nil {
		return nil, err
	}

	if _, err = reportHosts.Seek(0, 0); err != nil {
		return nil, err
	}
	for _, i := range h {
		if isInScope(i.IP, outOfScope) && isInScope(i.Host, outOfScope) {
			scope.Hosts = append(scope.Hosts, NGHostsCSV{
				Host:    i.Host,
				IP:      i.IP,
				Region:  i.Region,
				Country: i.Country,
				Lat:     i.Lat,
				Long:    i.Long,
				Notes:   i.Notes,
				Module:  i.Module,
			})
			parts := strings.Split(i.Host, ".")
			if len(parts) == 2 {
				d := strings.Join(parts, ".")
				if !localio.Contains(scope.Domains, d) {
					scope.Domains = append(scope.Domains, d)
				}
			}
		}
	}

	contacts, err := os.OpenFile(csvFiles.contacts, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer contacts.Close()

	var c []*NGContactsCSV

	if err = gocsv.UnmarshalFile(contacts, &c); err != nil {
		return nil, err
	}

	if _, err = contacts.Seek(0, 0); err != nil {
		return nil, err
	}
	for _, i := range c {
		scope.Contacts = append(scope.Contacts, NGContactsCSV{
			FirstName:  i.FirstName,
			MiddleName: i.MiddleName,
			LastName:   i.LastName,
			Email:      i.Email,
			Title:      i.Title,
			Region:     i.Region,
			Country:    i.Country,
			Phone:      i.Phone,
			Notes:      i.Notes,
			Module:     i.Module,
		})
	}

	return &scope, nil
}

// isInScope ...
func isInScope(scopeKind string, outOfScope []string) bool {
	// check if any CIDRs in outOfScope slice
	for _, i := range outOfScope {
		if valid.IsCIDR(i) {
			ips, _ := mapcidr.IPAddresses(i)
			outOfScope = append(outOfScope, ips...)
		}
	}
	// remove any potential duplicates from outOfScope
	sortedOutOfScope := removeDuplicateStr(outOfScope)

	switch {
	case valid.IsCIDR(scopeKind):
		ips, _ := mapcidr.IPAddresses(scopeKind)
		for _, ip := range ips {
			if !localio.Contains(sortedOutOfScope, ip) {
				return true
			}
		}
	default:
		if !localio.Contains(sortedOutOfScope, scopeKind) {
			return true
		}
	}

	return false
}

func (h *Hosts) isDomainInScope(domain string) bool {
	// check that domain is in scope by resolving and checking against netblocks
	ipv4s, _ := resolveDomainToIP(domain)
	if len(ipv4s) > 0 && !localio.Contains(h.OutOfScope, domain) {
		for _, netblock := range h.CIDRs {
			ips, _ := mapcidr.IPAddresses(netblock)
			for _, ip := range ips {
				if localio.Contains(ipv4s, ip) {
					return true
				}
			}
		}
	}
	return false
}
