package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// runNmapServiceScripts ...
func runNmapServiceScripts(outputDir string, data *Data) error {
	targets, err := newNmapTargetInfo(data, ServiceKinds)
	if err != nil {
		return localio.LogError(err)
	}

	if err = os.MkdirAll(fmt.Sprintf("%s/nmap", outputDir), os.ModePerm); err != nil {
		return localio.LogError(err)
	}
	if err = nmapServiceRunner(outputDir, targets); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// nmapServiceRunner ...
func nmapServiceRunner(outputDir string, targets []NmapTargetInfo) error {
	localio.Infof("Running nmap against %d hosts", len(targets))
	// Common channel for the goroutines
	tasks := make(chan *exec.Cmd, len(targets))

	var wg sync.WaitGroup

	// Spawn 30 goroutines
	for i := 0; i < 30; i++ {
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
				fmt.Println(string(out))
			}
		}(i, &wg)
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		localio.LogFatal(err, "could not get bash path")
	}
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		localio.LogFatal(err, "could not get nmap path")
	}
	for _, target := range targets {
		switch {
		case len(target.TCPPorts) >= 1 && len(target.UDPPorts) >= 1:
			udpPorts := localio.PrependString(target.UDPPorts, "U:")
			tcpPorts := localio.PrependString(target.TCPPorts, "T:")
			command := fmt.Sprintf("sudo %s -vvv -Pn -sU -sT -p %s,%s -sV --script %s -oA %s/nmap/%s-%s %s", nmapPath, strings.Join(udpPorts, ","), strings.Join(tcpPorts, ","), target.Scripts, outputDir, target.Target, target.SVCName, target.Target)
			localio.LogInfo("Command", command, "")
			tasks <- exec.Command(bashPath, "-c", command)
		case len(target.TCPPorts) >= 1 && len(target.UDPPorts) == 0:
			command := fmt.Sprintf("sudo %s -vvv -Pn -sU -sT -p %s -sV --script %s -oA %s/nmap/%s-%s %s", nmapPath, strings.Join(target.TCPPorts, ","), target.Scripts, outputDir, target.Target, target.SVCName, target.Target)
			localio.LogInfo("Command", command, "")
			tasks <- exec.Command(bashPath, "-c", command)
		case len(target.TCPPorts) == 0 && len(target.UDPPorts) >= 1:
			command := fmt.Sprintf("sudo %s -vvv -Pn -sU -sT -p %s -sV --script %s -oA %s/nmap/%s-%s %s", nmapPath, strings.Join(target.UDPPorts, ","), target.Scripts, outputDir, target.Target, target.SVCName, target.Target)
			localio.LogInfo("Command", command, "")
			tasks <- exec.Command(bashPath, "-c", command)
		}
	}
	close(tasks)
	// wait for the workers to finish
	wg.Wait()

	return nil
}
