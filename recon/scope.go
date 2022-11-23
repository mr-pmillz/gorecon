package recon

import (
	"fmt"
	"net"
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
	Domains              []string
	SubDomains           []string
	CIDRs                []string
	IPv4s                []string
	IPv6s                []string
	OutOfScope           []string
	OutOfScopeSubdomains []string
	ASNs                 []string
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
		for _, i := range opts.OutOfScope.([]string) {
			if valid.IsDNSName(i) {
				d, _ := tld.Parse(fmt.Sprintf("https://%s", i))
				if d.Subdomain != "" && !localio.Contains(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
					hosts.OutOfScopeSubdomains = append(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
				}
			}
		}
	case reflect.String:
		if opts.OutOfScope.(string) != "" {
			if exists, err := localio.Exists(opts.OutOfScope.(string)); exists && err == nil {
				outOfScopes, err := localio.ReadLines(opts.OutOfScope.(string))
				if err != nil {
					return nil, err
				}
				hosts.OutOfScope = append(hosts.OutOfScope, outOfScopes...)
				for _, i := range outOfScopes {
					if valid.IsDNSName(i) {
						d, _ := tld.Parse(fmt.Sprintf("https://%s", i))
						if d.Subdomain != "" && !localio.Contains(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
							hosts.OutOfScopeSubdomains = append(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
						}
					}
				}
			} else {
				hosts.OutOfScope = append(hosts.OutOfScope, opts.OutOfScope.(string))
				if valid.IsDNSName(opts.OutOfScope.(string)) {
					d, _ := tld.Parse(fmt.Sprintf("https://%s", opts.OutOfScope.(string)))
					if d.Subdomain != "" && !localio.Contains(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
						hosts.OutOfScopeSubdomains = append(hosts.OutOfScopeSubdomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
					}
				}
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
//nolint:gocognit
func GenerateURLs(scope *NGScope, h *Hosts, subs []string) ([]string, error) { //nolint:typecheck
	var urls []string //nolint:prealloc
	ignoreHosts := []string{"google", "amazon", "amazonaws", "googlemail", "*", "googlehosted", "cloudfront", "cloudflare", "fastly", "akamai", "sucuri"}
	ignoreHosts = append(ignoreHosts, h.OutOfScope...)

	// create http and https urls from found hosts
	for _, host := range scope.Hosts {
		if !localio.ContainsChars(ignoreHosts, host.Host) && !localio.ContainsChars(ignoreHosts, host.IP) && host.Host != "" && host.IP != "" {
			urls = append(urls, fmt.Sprintf("http://%s", host.Host))
			urls = append(urls, fmt.Sprintf("https://%s", host.Host))
			// ensure that private IP addresses are ignored
			if !net.IP.IsPrivate(net.IP(host.IP)) {
				urls = append(urls, fmt.Sprintf("http://%s", host.IP))
				urls = append(urls, fmt.Sprintf("https://%s", host.IP))
			}
		}
	}
	for _, hostPort := range scope.Ports {
		if !localio.ContainsChars(ignoreHosts, hostPort.Host) && !localio.ContainsChars(ignoreHosts, hostPort.IP) && hostPort.Host != "" && hostPort.IP != "" {
			switch hostPort.Port {
			case "21", "22", "25", "53", "110", "119", "123", "135", "139", "143", "179", "194", "445", "500", "1433", "3389", "5985":
				// Do nothing
			case "80":
				urls = append(urls, fmt.Sprintf("http://%s", hostPort.Host))
				if !net.IP.IsPrivate(net.IP(hostPort.IP)) {
					urls = append(urls, fmt.Sprintf("http://%s", hostPort.IP))
				}
			case "443":
				urls = append(urls, fmt.Sprintf("https://%s", hostPort.Host))
				if !net.IP.IsPrivate(net.IP(hostPort.IP)) {
					urls = append(urls, fmt.Sprintf("https://%s", hostPort.IP))
				}
			default:
				urls = append(urls, fmt.Sprintf("http://%s:%s/", hostPort.Host, hostPort.Port))
				urls = append(urls, fmt.Sprintf("https://%s:%s/", hostPort.Host, hostPort.Port))
				if !net.IP.IsPrivate(net.IP(hostPort.IP)) {
					urls = append(urls, fmt.Sprintf("http://%s:%s/", hostPort.IP, hostPort.Port))
					urls = append(urls, fmt.Sprintf("https://%s:%s/", hostPort.IP, hostPort.Port))
				}
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
	Asn                string `csv:"asn,omitempty"`
	A                  string `csv:"a,omitempty"`
	Body               string `csv:"body,omitempty"`
	Cdn                bool   `csv:"cdn,omitempty"`
	CdnName            string `csv:"cdn_name,omitempty"`
	ChainStatusCodes   string `csv:"chain_status_codes,omitempty"`
	Chain              string `csv:"chain,omitempty"`
	Cname              string `csv:"cname,omitempty"`
	ContentLength      int    `csv:"content_length,omitempty"`
	ContentType        string `csv:"content_type,omitempty"`
	Csp                string `csv:"csp,omitempty"`
	Error              string `csv:"error,omitempty"`
	ExtractRegex       string `csv:"extract_regex,omitempty"`
	Extracts           string `csv:"extracts,omitempty"`
	Failed             bool   `csv:"failed,omitempty"`
	Favicon            string `csv:"favicon,omitempty"`
	FinalURL           string `csv:"final_url,omitempty"`
	Hash               string `csv:"hash,omitempty"`
	Header             string `csv:"header,omitempty"`
	Host               string `csv:"host,omitempty"`
	HTTP2              bool   `csv:"http2,omitempty"`
	Input              string `csv:"input,omitempty"`
	Jarm               string `csv:"jarm,omitempty"`
	Lines              int    `csv:"lines,omitempty"`
	Location           string `csv:"location,omitempty"`
	Method             string `csv:"method,omitempty"`
	Path               string `csv:"path,omitempty"`
	Pipeline           bool   `csv:"pipeline,omitempty"`
	Port               int    `csv:"port,omitempty"`
	RawHeader          string `csv:"raw_header,omitempty"`
	Request            string `csv:"request,omitempty"`
	Scheme             string `csv:"scheme,omitempty"`
	StatusCode         int    `csv:"status_code,omitempty"`
	StoredResponsePath string `csv:"stored_response_path,omitempty"`
	Tech               string `csv:"tech,omitempty"`
	Timestamp          string `csv:"timestamp,omitempty"`
	Time               string `csv:"time,omitempty"`
	Title              string `csv:"title,omitempty"`
	TLS                string `csv:"tls,omitempty"`
	URL                string `csv:"url,omitempty"`
	Vhost              bool   `csv:"vhost,omitempty"`
	Webserver          string `csv:"webserver,omitempty"`
	Websocket          bool   `csv:"websocket,omitempty"`
	Words              int    `csv:"words,omitempty"`
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
			Asn:                i.Asn,
			A:                  i.A,
			Body:               i.Body,
			Cdn:                i.Cdn,
			CdnName:            i.CdnName,
			ChainStatusCodes:   i.ChainStatusCodes,
			Chain:              i.Chain,
			Cname:              i.Cname,
			ContentLength:      i.ContentLength,
			ContentType:        i.ContentType,
			Csp:                i.Csp,
			Error:              i.Error,
			ExtractRegex:       i.ExtractRegex,
			Extracts:           i.Extracts,
			Failed:             i.Failed,
			Favicon:            i.Favicon,
			FinalURL:           i.FinalURL,
			Hash:               i.Hash,
			Header:             i.Header,
			Host:               i.Host,
			HTTP2:              i.HTTP2,
			Input:              i.Input,
			Jarm:               i.Jarm,
			Lines:              i.Lines,
			Location:           i.Location,
			Method:             i.Method,
			Path:               i.Path,
			Pipeline:           i.Pipeline,
			Port:               i.Port,
			RawHeader:          i.RawHeader,
			Request:            i.Request,
			Scheme:             i.Scheme,
			StatusCode:         i.StatusCode,
			StoredResponsePath: i.StoredResponsePath,
			Tech:               i.Tech,
			Timestamp:          i.Timestamp,
			Time:               i.Time,
			Title:              i.Title,
			TLS:                i.TLS,
			URL:                i.URL,
			Vhost:              i.Vhost,
			Webserver:          i.Webserver,
			Websocket:          i.Websocket,
			Words:              i.Words,
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
