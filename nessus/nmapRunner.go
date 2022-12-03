package nessus

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// NmapStdoutStreamer is your custom type in code.
// You just have to make it a Streamer.
type NmapStdoutStreamer struct {
	nmap.Streamer
	File string
}

// Write is a function that handles the normal nmap stdout.
func (c *NmapStdoutStreamer) Write(d []byte) (int, error) {
	lines := string(d)

	if strings.Contains(lines, "Stats: ") {
		fmt.Print(lines)
	}
	return len(d), nil
}

// Bytes returns scan result bytes.
func (c *NmapStdoutStreamer) Bytes() []byte {
	data, err := os.ReadFile(c.File)
	if err != nil {
		data = append(data, "\ncould not read File"...)
	}
	return data
}

// streamNmap streams nmap output 1 host at a time.
// ToDo: stream nmap concurrently
func streamNmap(targets map[string][]string, outputDir string) error {
	if err := os.MkdirAll(fmt.Sprintf("%s/nmap", outputDir), os.ModePerm); err != nil {
		return localio.LogError(err)
	}
	tasks := make(chan *nmap.Run, len(targets))
	var wg sync.WaitGroup

	// Spawn 5 goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(num int, wg *sync.WaitGroup) {
			printNmapResults(tasks, wg)
		}(i, &wg)
	}

	for target, ports := range targets {
		localio.Infof("Running nmap against %s\t%+v", target, ports)
		tasks <- runNmap(target, outputDir, ports)
	}

	close(tasks)
	wg.Wait()
	return nil
}

// printNmapResults ...
func printNmapResults(ch <-chan *nmap.Run, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range ch {
		// use result to format custom output
		for _, host := range task.Hosts {
			if len(host.Ports) == 0 || len(host.Addresses) == 0 {
				continue
			}

			fmt.Printf("Host %q:\n", host.Addresses[0])
			for _, port := range host.Ports {
				fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
				for _, script := range port.Scripts {
					fmt.Printf("%s\n", script.Output)
				}
			}
		}
	}
}

// runNmap runs StreamNmap against a target and slice of ports
func runNmap(target, outputDir string, ports []string) *nmap.Run {
	// limit each scan to maximum of 10 minutes in case something gets stuck..
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	xmlOutput := fmt.Sprintf("%s/nmap/%s.xml", outputDir, target)
	nmapOutput := fmt.Sprintf("%s/nmap/%s.nmap", outputDir, target)
	cType := &NmapStdoutStreamer{
		File: xmlOutput,
	}

	s, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts(strings.Join(ports, ",")),
		nmap.WithNmapOutput(nmapOutput),
		nmap.WithAggressiveScan(),
		nmap.WithVerbosity(3),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		// Filter out hosts that don't have any open ports
		nmap.WithFilterHost(func(h nmap.Host) bool {
			// Filter out hosts with no open ports.
			for i := range h.Ports {
				if h.Ports[i].Status() == "open" {
					return true
				}
			}

			return false
		}),
		nmap.WithContext(ctx),
	)
	if err != nil {
		localio.LogFatal(err, "unable to create nmap scanner")
	}

	warnings, err := s.RunWithStreamer(cType, cType.File)
	if err != nil {
		localio.LogFatal(err, "unable to run nmap scan")
	}

	fmt.Printf("StreamNmap warnings: %v\n", warnings)

	result, err := nmap.Parse(cType.Bytes())
	if err != nil {
		localio.LogFatal(err, "unable to parse nmap output")
	}
	return result
}

// runNmapAsync runs nmap concurrently with 5 goroutines in parallel.
func runNmapAsync(outputDir string, targets map[string][]string) error {
	if err := os.MkdirAll(fmt.Sprintf("%s/nmap", outputDir), os.ModePerm); err != nil {
		return localio.LogError(err)
	}
	localio.Infof("Running nmap against %d hosts", len(targets))
	// Common channel for the goroutines
	tasks := make(chan *exec.Cmd, len(targets))

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
	for target, ports := range targets {
		command := fmt.Sprintf("sudo %s -vvv -A -T4 -p %s -oA %s/nmap/%s-open-ports %s", nmapPath, strings.Join(ports, ","), outputDir, target, target)
		localio.LogInfo("Command", command, "")
		tasks <- exec.Command(bashPath, "-c", command)
	}
	close(tasks)
	// wait for the workers to finish
	wg.Wait()
	return nil
}
