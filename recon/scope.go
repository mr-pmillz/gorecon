package recon

import (
	"fmt"
	"os"
	"reflect"

	"github.com/mr-pmillz/gorecon/localio"

	valid "github.com/asaskevich/govalidator"
	"github.com/gocarina/gocsv"
	tld "github.com/jpillora/go-tld"
)

type Hosts struct {
	Domains    []string
	SubDomains []string
	CIDRs      []string
	IPv4s      []string
	IPv6s      []string
}

//nolint:gocognit
//nolint:gocyclo
//nolint:gocyclo
func NewScope(opts *Options) (*Hosts, error) {
	fmt.Println("[+] Generating Scope Information")
	hosts := new(Hosts)
	// check if domain arg is file, string, or a slice
	rtd := reflect.TypeOf(opts.Domain)
	switch rtd.Kind() {
	case reflect.Slice:
		for _, domain := range opts.Domain.([]string) {
			// check if CIDR, IPv4, IPv6, Subdomain, or primary domain
			// this tld library expects http:// protocol | URL format so prepend it to domain
			d, _ := tld.Parse(fmt.Sprintf("https://%s", domain))
			if d.Subdomain != "" {
				hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
			}
			if d.Domain != "" {
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
				if d.Subdomain != "" {
					if !localio.Contains(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD)) {
						hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
					}
				}
				if d.Domain != "" {
					if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
						hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
					}
				}
			}
		} else {
			d, _ := tld.Parse(fmt.Sprintf("https://%s", opts.Domain.(string)))
			if d.Subdomain != "" {
				hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
				if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
					hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
				}
			}
			if d.Domain != "" {
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
			switch {
			case valid.IsCIDR(netblock):
				hosts.CIDRs = append(hosts.CIDRs, netblock)
			case valid.IsIPv4(netblock):
				hosts.IPv4s = append(hosts.IPv4s, netblock)
			case valid.IsIPv6(netblock):
				hosts.IPv6s = append(hosts.IPv6s, netblock)
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
					switch {
					case valid.IsCIDR(netblock):
						hosts.CIDRs = append(hosts.CIDRs, netblock)
					case valid.IsIPv4(netblock):
						hosts.IPv4s = append(hosts.IPv4s, netblock)
					case valid.IsIPv6(netblock):
						hosts.IPv6s = append(hosts.IPv6s, netblock)
					}
				}
			} else {
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

// recon-ng csv parser section

type NGScope struct {
	URLs          []string
	URLsWithPorts []string
	Hosts         []NGHostsCSV
	Contacts      []NGContactsCSV
	Ports         []NGPortsCSV
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

func ParseReconNGCSV(csvFiles *CsvReportFiles) (*NGScope, error) {
	scope := NGScope{}
	ports, err := os.OpenFile(csvFiles.ports, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer ports.Close()

	var p []*NGPortsCSV

	gocsv.SetCSVReader(gocsv.LazyCSVReader)

	if err := gocsv.UnmarshalFile(ports, &p); err != nil {
		return nil, err
	}

	if _, err := ports.Seek(0, 0); err != nil {
		return nil, err
	}

	for _, i := range p {
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

	reportHosts, err := os.OpenFile(csvFiles.hosts, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer reportHosts.Close()

	var h []*NGHostsCSV

	if err := gocsv.UnmarshalFile(reportHosts, &h); err != nil {
		return nil, err
	}

	if _, err := reportHosts.Seek(0, 0); err != nil {
		return nil, err
	}
	for _, i := range h {
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
	}

	contacts, err := os.OpenFile(csvFiles.contacts, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer contacts.Close()

	var c []*NGContactsCSV

	if err := gocsv.UnmarshalFile(contacts, &c); err != nil {
		return nil, err
	}

	if _, err := contacts.Seek(0, 0); err != nil {
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
