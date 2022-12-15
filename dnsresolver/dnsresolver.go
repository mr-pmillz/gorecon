package dnsresolver

import (
	"bufio"
	"fmt"
	valid "github.com/asaskevich/govalidator"
	"github.com/miekg/unbound"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/projectdiscovery/mapcidr"
	"reflect"
	"strings"
	"sync"
)

// getSliceFromOptInterface given an interface option from *Options struct
// returns a slice of all the supplied opt args value
func getSliceFromOptInterface(opt interface{}) ([]string, error) {
	var slice []string
	targetsType := reflect.TypeOf(opt)
	switch targetsType.Kind() {
	case reflect.Slice:
		slice = append(slice, opt.([]string)...)
	case reflect.String:
		if exists, err := localio.Exists(opt.(string)); exists && err == nil {
			targetList, err := localio.ReadLines(opt.(string))
			if err != nil {
				return nil, localio.LogError(err)
			}
			slice = append(slice, targetList...)
		} else {
			slice = append(slice, strings.Split(opt.(string), ",")...)
		}
	}

	return slice, nil
}

var (
	resolveData []string
)

// RunResolver ...
func RunResolver(opts *Options) error {
	targets, err := getSliceFromOptInterface(opts.Targets)
	if err != nil {
		return localio.LogError(err)
	}

	work := make(chan string)
	go func() {
		s := bufio.NewScanner(strings.NewReader(strings.Join(targets, "\n")))
		for s.Scan() {
			work <- s.Text()
		}
		close(work)
	}()
	wg := &sync.WaitGroup{}
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go doQueries(work, wg)
	}
	wg.Wait()
	uniqueResolveData := localio.RemoveDuplicateStr(resolveData)
	if err = localio.WriteLines(uniqueResolveData, fmt.Sprintf("%s/resolved-hosts.txt", opts.Output)); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// doQueries ...
func doQueries(work chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	u := unbound.New()
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		localio.LogWarningf("couldn't parse /etc/resolv.conf Error: %+v\n", err)
	}

	for target := range work {
		switch {
		case valid.IsCIDR(target):
			ips, _ := mapcidr.IPAddresses(target)
			for _, ip := range ips {
				addr, err := u.LookupAddr(ip)
				if err != nil {
					continue
				}

				for _, a := range addr {
					fmt.Println(ip, "\t", strings.TrimRight(a, "."))
					resolveData = append(resolveData, fmt.Sprintf("%s[%s]", strings.TrimRight(a, "."), ip))
				}
			}
		case valid.IsIPv4(target):
			addr, err := u.LookupAddr(target)
			if err != nil {
				continue
			}

			for _, a := range addr {
				fmt.Println(target, "\t", strings.TrimRight(a, "."))
				resolveData = append(resolveData, fmt.Sprintf("%s[%s]", strings.TrimRight(a, "."), target))
			}
		case valid.IsDNSName(target):
			ips, err := u.LookupIP(target)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				fmt.Println(ip.String(), "\t", target)
				resolveData = append(resolveData, fmt.Sprintf("%s[%s]", target, ip.String()))
			}
		default:
			// DoNothing
		}
	}
}
