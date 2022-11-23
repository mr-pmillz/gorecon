package recon

import (
	"fmt"
	"net"

	"github.com/mr-pmillz/gorecon/v2/localio"
)

// resolveDomainToIP resolves a domain to IPv4 addresses
func resolveDomainToIP(domain string) ([]string, error) {
	var ipv4s []string
	ips, err := net.LookupIP(domain)
	if err != nil {
		localio.PrintInfo("resolveDomainToIP", "warning", fmt.Sprintf("Could not resolve %s to IPv4", domain))
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4s = append(ipv4s, ipv4.String())
		}
	}
	return ipv4s, nil
}
