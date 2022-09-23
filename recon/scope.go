package recon

import (
	"fmt"
	valid "github.com/asaskevich/govalidator"
	tld "github.com/jpillora/go-tld"
	"github.com/mr-pmilz/gorecon/localio"
	"reflect"
)

type Hosts struct {
	Domains    []string
	SubDomains []string
	CIDRs      []string
	IPv4s      []string
	IPv6s      []string
}

func NewScope(opts *Options) (*Hosts, error) {
	fmt.Println("[+] Generating Scope Information")
	hosts := new(Hosts)
	//check if domain arg is file, string, or a slice
	rtd := reflect.TypeOf(opts.Domain)
	switch rtd.Kind() {
	case reflect.Slice:
		for _, domain := range opts.Domain.([]string) {
			//check if CIDR, IPv4, IPv6, Subdomain, or primary domain
			//this tld library expects http:// protocol | URL format so prepend it to domain
			d, _ := tld.Parse(fmt.Sprintf("https://%s", domain))
			if d.Subdomain != "" {
				hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
			} else {
				hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
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
				//check if CIDR, IPv4, IPv6, Subdomain, or primary domain
				//this tld library expects http:// protocol | URL format so prepend it to domain
				d, _ := tld.Parse(fmt.Sprintf("https://%s", domain))
				if d.Subdomain != "" {
					hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
				} else {
					hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
				}
			}
		} else {
			d, _ := tld.Parse(fmt.Sprintf("https://%s", opts.Domain))
			if d.Subdomain != "" {
				hosts.SubDomains = append(hosts.SubDomains, fmt.Sprintf("%s.%s.%s", d.Subdomain, d.Domain, d.TLD))
				if !localio.Contains(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD)) {
					hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
				}
			} else {
				hosts.Domains = append(hosts.Domains, fmt.Sprintf("%s.%s", d.Domain, d.TLD))
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
