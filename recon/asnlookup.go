package recon

import (
	"fmt"
	"github.com/gocarina/gocsv"
	"github.com/jpillora/go-tld"
	"github.com/mr-pmillz/gorecon/localio"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"os"
	"reflect"
)

type ASNMapScope struct {
	DomainASN []ASNMapDomainQueryCSV
}

type ASNMapDomainQueryCSV struct {
	Timestamp string `csv:"timestamp,omitempty"`
	Input     string `csv:"input,omitempty"`
	AsNumber  string `csv:"as_number,omitempty"`
	AsName    string `csv:"as_name,omitempty"`
	AsCountry string `csv:"as_country,omitempty"`
	AsRange   string `csv:"as_range,omitempty"`
}

func newASNClient() *asnmap.Client {
	return asnmap.NewClient()
}

// getDomains ...
func getDomains(optsDomain interface{}) ([]string, error) {
	var domains []string
	domainsType := reflect.TypeOf(optsDomain)
	switch domainsType.Kind() {
	case reflect.Slice:
		for _, d := range optsDomain.([]string) {
			parsed, _ := tld.Parse(fmt.Sprintf("https://%s", d))
			domains = append(domains, fmt.Sprintf("%s.%s", parsed.Domain, parsed.TLD))
		}
	case reflect.String:
		if isfile, err := localio.Exists(optsDomain.(string)); isfile && err == nil {
			domainList, err := localio.ReadLines(optsDomain.(string))
			if err != nil {
				return nil, localio.LogError(err)
			}
			for _, d := range domainList {
				parsed, _ := tld.Parse(fmt.Sprintf("https://%s", d))
				domains = append(domains, fmt.Sprintf("%s.%s", parsed.Domain, parsed.TLD))
			}
		} else {
			parsed, _ := tld.Parse(fmt.Sprintf("https://%s", optsDomain.(string)))
			domains = append(domains, fmt.Sprintf("%s.%s", parsed.Domain, parsed.TLD))
		}
	}
	return removeDuplicateStr(domains), nil
}

func getASNByDomain(opts *Options) (*ASNMapScope, error) {
	domains, err := getDomains(opts.Domain)
	if err != nil {
		return nil, localio.LogError(err)
	}
	asnmapScope := ASNMapScope{}
	client := newASNClient()
	resolvers := []string{
		"1.1.1.1",     // Cloudflare
		"1.0.0.1",     // Cloudflare Secondary
		"8.8.8.8",     // Google
		"8.8.4.4",     // Google Secondary
		"64.6.64.6",   // Verisign
		"64.6.65.6",   // Verisign Secondary
		"77.88.8.1",   // Yandex.DNS Secondary
		"74.82.42.42", // Hurricane Electric
	}

	asnOutputCSVFile, err := os.OpenFile(fmt.Sprintf("%s/ASN-data.csv", opts.Output), os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, localio.LogError(err)
	}
	defer asnOutputCSVFile.Close()

	for _, domain := range domains {
		localio.Infof("Looking up ASN for: %s", domain)
		resolvedIPs := asnmap.ResolveDomain(domain, resolvers...)
		for _, ip := range resolvedIPs {
			results := asnmap.GetFormattedDataInCSV(client.GetData(asnmap.IP(ip), asnmap.Domain(domain)))
			for _, result := range results {
				asnmapScope.DomainASN = append(asnmapScope.DomainASN, ASNMapDomainQueryCSV{
					Timestamp: result[0],
					Input:     result[1],
					AsNumber:  result[2],
					AsName:    result[3],
					AsCountry: result[4],
					AsRange:   result[len(result)-1],
				})
			}
		}
	}
	if err = localio.PrettyPrint(asnmapScope.DomainASN); err != nil {
		return nil, localio.LogError(err)
	}

	if err = gocsv.Marshal(asnmapScope.DomainASN, asnOutputCSVFile); err != nil {
		return nil, localio.LogError(err)
	}

	return &asnmapScope, nil
}
