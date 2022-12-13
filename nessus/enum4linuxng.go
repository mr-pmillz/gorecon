package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"github.com/tidwall/gjson"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Enum4LinuxInfo struct {
	RepoPath       string
	VirtualENVPath string
	OutputDir      string
}

// setupEnum4Linux sets up enum4linux-ng requirements and virtualenv
// assumes you have virtualenv installed already...
func setupEnum4Linux(outputDir string) (*Enum4LinuxInfo, error) {
	var repoPath string

	// clone enum4linux-ng repo
	if localio.IsRoot() {
		if err := localio.GitCloneDepthOne("https://github.com/cddmp/enum4linux-ng.git", "/opt/enum4linux-ng"); err != nil {
			return nil, localio.LogError(err)
		}
		repoPath = "/opt/enum4linux-ng"
	} else {
		if err := localio.GitCloneDepthOne("https://github.com/cddmp/enum4linux-ng.git", "/tmp/enum4linux-ng"); err != nil {
			return nil, localio.LogError(err)
		}
		repoPath = "/tmp/enum4linux-ng"
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, localio.LogError(err)
	}

	pyenvDir := fmt.Sprintf("%s/pyenv", homeDir)
	exists, _ := localio.Exists(pyenvDir)
	if !exists {
		if err = os.MkdirAll(pyenvDir, os.ModePerm); err != nil {
			return nil, localio.LogError(err)
		}
	}

	// install deps and setup virtualenv
	enum4linuxNGVirtualenvPath := fmt.Sprintf("%s/enum4linux-ng", pyenvDir)
	setupCMDs := []string{
		fmt.Sprintf("virtualenv -p python3 %s", enum4linuxNGVirtualenvPath),
		fmt.Sprintf("source %s/bin/activate ; cd %s && python3 -m pip install -r requirements.txt ; python3 setup.py install", enum4linuxNGVirtualenvPath, repoPath),
	}

	if err = localio.RunCommandsPipeOutput(setupCMDs); err != nil {
		return nil, localio.LogError(err)
	}

	// create enum4linux output dir
	enum4LinuxDir := fmt.Sprintf("%s/enum4linux-ng", outputDir)
	if err := os.MkdirAll(enum4LinuxDir, os.ModePerm); err != nil {
		return nil, localio.LogError(err)
	}

	return &Enum4LinuxInfo{
		RepoPath:       repoPath,
		VirtualENVPath: enum4linuxNGVirtualenvPath,
		OutputDir:      fmt.Sprintf("%s/enum4linux-ng", outputDir),
	}, nil
}

// runEnum4LinuxNG runs enum4Linux-NG concurrently with 5 goroutines in parallel.
func runEnum4LinuxNG(data *Data, outputDir string) error {
	targets, err := getTCPTargetsBySVCName(data, []string{"cifs", "smb", "epmap", "ldap"})
	if err != nil {
		return localio.LogError(err)
	}

	e, err := setupEnum4Linux(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	localio.Infof("Running enum4linux-ng against %v hosts", len(targets))
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

	for target := range targets {
		command := fmt.Sprintf("source %s/bin/activate && enum4linux-ng -A -C -R -v %s -oA %s/%s-enum4linuxng | tee %s/%s-enum4linuxng-raw-output.log", e.VirtualENVPath, target, e.OutputDir, target, e.OutputDir, target)
		localio.LogInfo("Command", command, "")
		tasks <- exec.Command(bashPath, "-c", command)
	}
	close(tasks)
	// wait for the workers to finish
	wg.Wait()

	if err = parseEnum4LinuxOutput(e.OutputDir); err != nil {
		return localio.LogError(err)
	}

	return nil
}

// parseEnum4LinuxOutput ...
func parseEnum4LinuxOutput(outputDir string) error {
	files, err := localio.FilePathWalkDir(outputDir)
	if err != nil {
		return localio.LogError(err)
	}

	var enum4LinuxJSONFiles []string
	for _, f := range files {
		base := filepath.Base(f)
		parts := strings.Split(base, "-")
		if localio.Contains(parts, "enum4linuxng.json") {
			enum4LinuxJSONFiles = append(enum4LinuxJSONFiles, f)
		}
	}
	enum4LinuxUniqueJSONFiles := localio.RemoveDuplicateStr(enum4LinuxJSONFiles)

	var users []string
	for _, jsonFile := range enum4LinuxUniqueJSONFiles {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			return localio.LogError(err)
		}
		parsed := gjson.ParseBytes(data)
		result := parsed.Get("users")
		for _, user := range result.Map() {
			parsedRaw := gjson.Parse(user.Raw)
			if parsedRaw.Get("username").Exists() {
				users = append(users, parsedRaw.Get("username").String())
			}
		}
	}
	uniqueUsers := localio.RemoveDuplicateStr(users)
	if len(uniqueUsers) >= 1 {
		localio.Infof("Found %d users! Writing valid usernames to: %s", len(uniqueUsers), fmt.Sprintf("%s/valid-users.txt", outputDir))
		if err = localio.WriteLines(uniqueUsers, fmt.Sprintf("%s/valid-users.txt", outputDir)); err != nil {
			return localio.LogError(err)
		}
	}

	return nil
}
