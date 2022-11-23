package recon

import (
	"fmt"
	"github.com/gocarina/gocsv"
	"github.com/mr-pmillz/gorecon/v2/localio"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/mapcidr"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

// hackerTargetASN workaround to get ASN number since api.asnmap.sh API is down
func hackerTargetASN(ip string) ([]string, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", ip), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resBody, _ := io.ReadAll(resp.Body)
	return strings.Split(strings.ReplaceAll(string(resBody), "\"", ""), ","), nil
}

type ASNData struct {
	AsnHandle  int      `json:"asnHandle,omitempty"`
	AsnName    string   `json:"asnName,omitempty"`
	OrgID      string   `json:"orgID,omitempty"`
	OrgName    string   `json:"orgName,omitempty"`
	OrgCountry string   `json:"orgCountry,omitempty"`
	Ipv4Prefix []string `json:"ipv4_prefix,omitempty"`
	Ipv6Prefix []string `json:"ipv6_prefix,omitempty"`
}

// getASNByDomain ...
// This method is unreliable. api.asnmap.sh/api/v1/asnmap?ip=X.X.X.X is unstable.
func getASNByDomain(opts *Options, domains []string) (*ASNMapScope, error) {
	asnmapScope := ASNMapScope{}
	// client := asnmap.NewClient()
	resolvers := []string{
		"1.1.1.1:53", // Cloudflare
		"8.8.8.8:53", // Google
	}
	// use file cache in case data already exists
	if exists, err := localio.Exists(fmt.Sprintf("%s/%s-ASN-data.csv", opts.Output, opts.Company)); err == nil && exists {
		f, err := os.OpenFile(fmt.Sprintf("%s/%s-ASN-data.csv", opts.Output, opts.Company), os.O_RDWR, os.ModePerm)
		if err != nil {
			return nil, localio.LogError(err)
		}
		defer f.Close()
		if err = gocsv.Unmarshal(f, &asnmapScope); err != nil {
			return &asnmapScope, nil
		}
	}

	asnOutputCSVFile, err := os.OpenFile(fmt.Sprintf("%s/%s-ASN-data.csv", opts.Output, opts.Company), os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, localio.LogError(err)
	}
	defer asnOutputCSVFile.Close()

	c := localio.NewHTTPClient()
	for _, domain := range domains {
		localio.Infof("Looking up ASN for: %s", domain)
		resolvedIPs := asnmap.ResolveDomain(domain, resolvers...)
		for _, ip := range resolvedIPs {
			// results := asnmap.GetFormattedDataInCSV(client.GetData(asnmap.IP(ip), asnmap.Domain(domain)))
			if opts.ASNLookupAPI != "" {
				var asnData []*ASNData
				headers := map[string]string{
					"X-RapidAPI-Host": "asn-lookup.p.rapidapi.com",
					"X-RapidAPI-Key":  opts.ASNLookupAPI,
				}
				params := map[string]string{
					"ip": ip,
				}
				if err = c.DoReq("https://asn-lookup.p.rapidapi.com/api", "GET", &asnData, headers, params); err != nil {
					return nil, localio.LogError(err)
				}

				asnmapScope.DomainASN = append(asnmapScope.DomainASN, ASNMapDomainQueryCSV{
					Timestamp: time.Now().String(),
					Input:     ip,
					AsNumber:  strconv.Itoa(asnData[0].AsnHandle),
					AsName:    asnData[0].AsnName,
					AsCountry: asnData[0].OrgCountry,
					AsRange:   matchCIDR(asnData[0].Ipv4Prefix, ip),
				})
			} else {
				// fall back to free hackertarget api with no keys
				results, err := hackerTargetASN(ip)
				if err != nil {
					return nil, localio.LogError(err)
				}
				if localio.Contains(results, "API count exceeded - Increase Quota with Membership") {
					localio.LogWarningf("%+v", strings.Join(results, " "))

					return &asnmapScope, nil
				}
				asnmapScope.DomainASN = append(asnmapScope.DomainASN, ASNMapDomainQueryCSV{
					Timestamp: time.Now().String(),
					Input:     results[0],
					AsNumber:  results[1],
					AsRange:   results[2],
					AsName:    results[3],
					AsCountry: strings.TrimSpace(results[4]),
				})
			}
		}
	}
	if len(asnmapScope.DomainASN) != 0 {
		if err = localio.PrettyPrint(asnmapScope.DomainASN); err != nil {
			return nil, localio.LogError(err)
		}
	}

	if err = gocsv.Marshal(asnmapScope.DomainASN, asnOutputCSVFile); err != nil {
		return nil, localio.LogError(err)
	}

	return &asnmapScope, nil
}

// matchCIDR ...
func matchCIDR(cidrSlice []string, ip string) string {
	var matchedCIDR string
	var wg sync.WaitGroup
	wg.Add(len(cidrSlice))
	for i := 0; i < len(cidrSlice); i++ {
		go func(i int) {
			defer wg.Done()
			ips, _ := mapcidr.IPAddresses(cidrSlice[i])
			if localio.Contains(ips, ip) {
				matchedCIDR = cidrSlice[i]
				return
			}
		}(i)
	}
	wg.Wait()

	return matchedCIDR
}
