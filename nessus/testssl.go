package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// setup ...
func setup(outputDir string) ([]string, error) {
	hosts, err := writeAllSslTLSHostsToFile(outputDir)
	if err != nil {
		return nil, localio.LogError(err)
	}

	if err = localio.GitCloneDepthOne("https://github.com/drwetter/testssl.sh.git", "/tmp/testssl.sh"); err != nil {
		return nil, localio.LogError(err)
	}

	sslDir := fmt.Sprintf("%s/ssl", outputDir)
	if err = os.MkdirAll(sslDir, os.ModePerm); err != nil {
		return nil, localio.LogError(err)
	}

	return hosts, nil
}

// runTestSSL runs Testssl.sh concurrently
func runTestSSL(outputDir string, verbose bool) error {
	hosts, err := setup(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	startTLSServices := map[int]string{
		21:   "ftp",
		23:   "telnet",
		24:   "lmtp",
		25:   "smtp",
		110:  "pop3",
		119:  "nntp",
		143:  "imap",
		389:  "ldap",
		465:  "smtp",
		563:  "nntp",
		587:  "smtp",
		636:  "ldap",
		993:  "imap",
		995:  "pop3",
		2000: "sieve",
		3268: "ldap",
		3269: "ldap",
		3306: "mysql",
		4190: "sieve",
		5432: "postgres",
	}

	localio.Infof("Running Testssl.sh against %d hosts\nBe patient, Testssl.sh is running in parallel. Stdout won't appear until after a scan is completed, approx. 60 seconds...\n %+v", len(hosts), hosts)
	// Common channel for the goroutines
	tasks := make(chan *exec.Cmd, len(hosts))

	var wg sync.WaitGroup

	// Spawn 5 goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(num int, w *sync.WaitGroup) {
			defer w.Done()
			var (
				out []byte
				err error
			)
			for cmd := range tasks {
				out, err = cmd.Output()
				if err != nil {
					localio.LogWarningf("can't get stdout: %+v", err)
				}
				if verbose {
					fmt.Println(string(out))
				}
			}
		}(i, &wg)
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		localio.LogWarningf("could not get bash path %+v", err)
	}
	for _, host := range hosts {
		port := strings.Split(host, ":")[1]
		portInt, err := strconv.Atoi(port)
		if err != nil {
			return localio.LogError(err)
		}
		var command string
		if startTLSService, ok := startTLSServices[portInt]; ok {
			command = fmt.Sprintf("cd /tmp/testssl.sh && ./testssl.sh --quiet --warnings batch -oA %s/ssl --starttls %s %s", outputDir, startTLSService, host)
		} else {
			command = fmt.Sprintf("cd /tmp/testssl.sh && ./testssl.sh --quiet --warnings batch -oA %s/ssl %s", outputDir, host)
		}

		localio.LogInfo("Command", command, "")
		tasks <- exec.Command(bashPath, "-c", command)
	}
	close(tasks)
	// wait for the workers to finish
	wg.Wait()

	return nil
}

// writeAllSslTlsHostsToFile writes all sorted unique ssl and tls hosts to a file
// returns a slice of sorted ssl and tls IPs.
func writeAllSslTLSHostsToFile(outputDir string) ([]string, error) {
	files, err := localio.FilePathWalkDir(outputDir)
	if err != nil {
		return nil, localio.LogError(err)
	}

	var sslTLSHosts []string
	for _, f := range files {
		base := filepath.Base(f)
		parts := strings.Split(base, "-")
		if base != "all-tls-ssl-hosts.txt" {
			if localio.Contains(parts, "ssl") || localio.Contains(parts, "tls") {
				if ips, err := localio.ReadLines(f); err == nil {
					sslTLSHosts = append(sslTLSHosts, ips...)
				}
			}
		}
	}

	sslTLSHosts = localio.RemoveDuplicateStr(sslTLSHosts)
	allSslTLSHosts := fmt.Sprintf("%s/all-tls-ssl-hosts.txt", outputDir)
	if err = localio.WriteLines(sslTLSHosts, allSslTLSHosts); err != nil {
		return nil, localio.LogError(err)
	}

	return sslTLSHosts, nil
}
