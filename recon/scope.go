package recon

import (
	"fmt"
	valid "github.com/asaskevich/govalidator"
	tld "github.com/jpillora/go-tld"
	"gorecon/localio"
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

	//check if domain arg is file or string
	if isfile, err := localio.Exists(opts.Domain); isfile && err == nil {
		domainList, err := localio.ReadLines(opts.Domain)
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

	// parse --netblock file into scope object
	if opts.NetBlock != "" {
		if exists, err := localio.Exists(opts.NetBlock); exists && err == nil {
			netblocks, err := localio.ReadLines(opts.NetBlock)
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
		}
	}

	return hosts, nil
}
