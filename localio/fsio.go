package localio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/projectdiscovery/gologger/formatter"

	valid "github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/spf13/cobra"

	gogitex "github.com/go-git/go-git/v5/_examples"
	"github.com/spf13/viper"
)

// CommandExists ...
func CommandExists(cmd string) (string, bool) {
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		return "", false
	}
	return cmdPath, true
}

// Contains checks if a string is present in a slice
func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// ContainsChars checks if string chars are present in a slice
// for checking domains existing in other subdomains.
// Also checks exact matches
func ContainsChars(s []string, str string) bool {
	for _, v := range s {
		if !valid.IsCIDR(str) && !valid.IsIPv4(str) {
			parts := strings.Split(str, ".")
			if Contains(parts, v) {
				return true
			}
		}
	}

	return Contains(s, str)
}

// EmbedFileCopy ...
func EmbedFileCopy(src fs.File, dst string) error {
	destFilePath, err := ResolveAbsPath(dst)
	if err != nil {
		return LogError(err)
	}

	if err = os.MkdirAll(filepath.Dir(destFilePath), 0750); err != nil {
		return LogError(err)
	}

	destFile, err := os.Create(destFilePath)
	if err != nil {
		return LogError(err)
	}

	if _, err := io.Copy(destFile, src); err != nil {
		return LogError(err)
	}

	return nil
}

// Exists returns whether the given file or directory exists
func Exists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	absPath, err := ResolveAbsPath(path)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(absPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CopyFile ...
func CopyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return LogError(err)
	}
	defer srcFile.Close()

	if err = os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
		return LogError(err)
	}

	destFile, err := os.Create(dest)
	if err != nil {
		return LogError(err)
	}
	defer destFile.Close()

	buf := make([]byte, 1024*1024*4)
	_, err = io.CopyBuffer(destFile, srcFile, buf)
	return LogError(err)
}

// TimeTrack ...
func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	Infof("%s \ntook: %s\n", name, elapsed)
}

// RunCommandPipeOutput runs a bash command and pipes the output to stdout in realtime
// also has a built-in timer that tracks execution duration
// it returns an error
func RunCommandPipeOutput(command string) error {
	defer TimeTrack(time.Now(), command)
	LogInfo("Command", command, "")
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		return LogError(err)
	}

	// Increase timeout to 24 hours for long-running recon-ng process
	timeout := 1440

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, bashPath, "-c", command)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return LogError(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return LogError(err)
	}

	errScanner := bufio.NewScanner(stderr)
	go func() {
		for errScanner.Scan() {
			fmt.Printf("%s\n", errScanner.Text())
		}
	}()

	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			fmt.Printf("%s\n", scanner.Text())
		}
	}()

	cmd.Env = os.Environ()
	if err = cmd.Start(); err != nil {
		return LogError(err)
	}

	if err = cmd.Wait(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error waiting for Cmd %s\n", err)
		return LogError(err)
	}

	return nil
}

// RunCommandsPipeOutput ...
func RunCommandsPipeOutput(commands []string) error {
	for _, c := range commands {
		if err := RunCommandPipeOutput(c); err != nil {
			return LogError(err)
		}
	}
	return nil
}

// WriteStructToJSONFile ...
func WriteStructToJSONFile(data interface{}, outputFile string) error {
	outputFileDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputFileDir, 0750); err != nil {
		return LogError(err)
	}

	f, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return LogError(err)
	}

	if err = os.WriteFile(outputFile, f, 0600); err != nil {
		return LogError(err)
	}
	return nil
}

// LogInfo logs to a json file
func LogInfo(key, val, msg string) {
	timestamp := time.Now().Format("01-02-2006")
	fname := fmt.Sprintf("gorecon-command-log-%s.json", timestamp)

	f, err := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	teeformatter := formatter.NewTee(formatter.NewCLI(false), f)
	gologger.DefaultLogger.SetFormatter(teeformatter)
	gologger.Info().Str(key, val).Msg(msg)
}

// LogWarningf logs a warning to stdout
func LogWarningf(format string, args ...interface{}) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	gologger.Warning().Msgf(format, args...)
}

// PrintInfo is a wrapper around gologger Info method
func PrintInfo(key, val, msg string) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.Info().Str(key, val).Msg(msg)
}

// Infof ...
func Infof(format string, args ...interface{}) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.Info().Msgf(format, args...)
}

func LogError(err error) error {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelError)
	gologger.Error()
	return err
}

// LogFatal is a wrapper around gologger Info method
func LogFatal(err error, msg string) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	gologger.Debug().Str("Error", err.Error()).Msg(msg)
	gologger.Fatal()
}

// ExecCMD Execute a command
func ExecCMD(command string, verbose bool) (string, error) {
	if verbose {
		fmt.Printf("[+] %s\n", command)
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		return "", err
	}

	cmd := exec.Command(bashPath, "-c", command)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func PrettyPrint(v interface{}) (err error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		fmt.Println(string(b))
	}
	return
}

// ResolveAbsPath ...
func ResolveAbsPath(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return path, err
	}

	dir := usr.HomeDir
	if path == "~" {
		path = dir
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(dir, path[2:])
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return path, err
	}

	return path, nil
}

type LoadFromCommandOpts struct {
	DefaultFlagVal string
	Flag           string
	IsFilePath     bool
	Prefix         string
	Opts           interface{}
}

// ConfigureFlagOpts sets the cobra flag option to the LoadFromCommandOpts.Opts key
// it returns the parsed value of the cobra flag from LoadFromCommandOpts.Flag
//nolint:gocognit
func ConfigureFlagOpts(cmd *cobra.Command, lfcOpts *LoadFromCommandOpts) (interface{}, error) {
	cmdFlag, err := cmd.Flags().GetString(fmt.Sprintf("%s%s", lfcOpts.Prefix, lfcOpts.Flag))
	if err != nil {
		return nil, err
	}

	switch cmdFlag {
	case "":
		flagToUpperConfig := strings.ToUpper(strings.ReplaceAll(fmt.Sprintf("%s%s", lfcOpts.Prefix, lfcOpts.Flag), "-", "_"))
		configVal := viper.GetString(flagToUpperConfig)
		envVal, ok := os.LookupEnv(configVal)
		configSliceVal := viper.GetStringSlice(flagToUpperConfig)
		if ok {
			if lfcOpts.IsFilePath {
				fileExists, err := Exists(envVal)
				if err != nil {
					return nil, err
				}
				if fileExists {
					absVal, err := ResolveAbsPath(envVal)
					if err != nil {
						return nil, err
					}
					lfcOpts.Opts = absVal
				} else {
					lfcOpts.Opts = envVal
				}
			} else {
				lfcOpts.Opts = envVal
			}
		} else {
			switch {
			case len(configSliceVal) > 1 && strings.Contains(configVal, "\n"):
				lfcOpts.Opts = configSliceVal
			case configVal != "":
				if lfcOpts.IsFilePath {
					if exists, err := Exists(configVal); exists && err == nil {
						absConfigVal, err := ResolveAbsPath(configVal)
						if err != nil {
							return nil, err
						}
						lfcOpts.Opts = absConfigVal
					} else {
						lfcOpts.Opts = configVal
					}
				} else {
					lfcOpts.Opts = configVal
				}
			default:
				switch {
				case lfcOpts.DefaultFlagVal != "" && lfcOpts.IsFilePath:
					absDefaultVal, err := ResolveAbsPath(lfcOpts.DefaultFlagVal)
					if err != nil {
						return nil, err
					}
					_, err = os.Stat(absDefaultVal)
					if os.IsNotExist(err) {
						lfcOpts.Opts = cmdFlag
					} else {
						lfcOpts.Opts = absDefaultVal
					}
				case lfcOpts.DefaultFlagVal != "" && !lfcOpts.IsFilePath:
					lfcOpts.Opts = lfcOpts.DefaultFlagVal
				default:
					lfcOpts.Opts = cmdFlag
				}
			}
		}
	default:
		envValue, ok := os.LookupEnv(strings.ToUpper(strings.ReplaceAll(fmt.Sprintf("%s%s", lfcOpts.Prefix, lfcOpts.Flag), "-", "_")))
		if ok {
			lfcOpts.Opts = envValue
		} else {
			if lfcOpts.IsFilePath {
				fileExists, err := Exists(cmdFlag)
				if err != nil {
					return nil, err
				}
				if fileExists {
					absCmdFlag, err := ResolveAbsPath(cmdFlag)
					if err != nil {
						return nil, err
					}
					lfcOpts.Opts = absCmdFlag
				} else {
					lfcOpts.Opts = cmdFlag
				}
			} else {
				lfcOpts.Opts = cmdFlag
			}
		}
	}
	return lfcOpts.Opts, nil
}

// IsHeadless checks the DISPLAY env var to check if
// the server you're running this program on has a GUI / Desktop Environment
func IsHeadless() bool {
	return len(os.Getenv("DISPLAY")) == 0
}

// IsRoot checks if the current user is root or not
func IsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

type PipInstalled struct {
	Name []string
}

// NewPipInstalled returns a slice of all the installed python3 pip packages
func NewPipInstalled() (*PipInstalled, error) {
	pip := &PipInstalled{}
	cmd := "python3 -m pip list | awk '{print $1}'"
	pipPackages, err := ExecCMD(cmd, false)
	if err != nil {
		return nil, err
	}
	installedList := strings.Split(pipPackages, "\n")
	pip.Name = append(pip.Name, installedList...)

	return pip, nil
}

// InstallPython3VirtualEnv installs virtualenv via apt
func InstallPython3VirtualEnv() error {
	// ridonkulous bug https://askubuntu.com/questions/1406304/virtualenv-installs-envs-into-local-bin-instead-of-bin
	// virtualenv < 20.16.5 installs envs into local/bin instead of bin... :|
	// to work around this, just always update and install virtualenv + deps as opposed to checking semantic versioning
	// and adding another module like https://github.com/Masterminds/semver
	if err := RunCommandPipeOutput("sudo apt-get update -y && sudo apt-get -q install virtualenv python3-distutils python3-virtualenv -y"); err != nil {
		return LogError(err)
	}
	return nil
}

// GitClone clones a public git repo url to directory
func GitClone(url, directory string) error {
	if exists, err := Exists(directory); err == nil && !exists {
		gogitex.Info("git clone %s %s", url, directory)
		_, err := git.PlainClone(directory, false, &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
		})
		gogitex.CheckIfError(err)
	} else {
		fmt.Printf("[+] Repo: %s already exists at %s, skipping... \n", url, directory)
	}

	return nil
}

// GitCloneDepthOne clones a public git repo url to directory
func GitCloneDepthOne(url, directory string) error {
	if exists, err := Exists(directory); err == nil && !exists {
		gogitex.Info("git clone %s %s", url, directory)
		_, err := git.PlainClone(directory, false, &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
			Depth:    1,
		})
		gogitex.CheckIfError(err)
	} else {
		fmt.Printf("[+] Repo: %s already exists at %s, skipping... \n", url, directory)
	}

	return nil
}

// ReadLines reads a whole file into memory
// and returns a slice of its lines.
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// WriteLines writes the lines to the given file.
func WriteLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return LogError(err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		if len(line) > 0 {
			_, _ = fmt.Fprintln(w, line)
		}
	}
	return w.Flush()
}

func OrderIPPair(firstIP string, secondIP string) [2]string {
	// extract numbers out of IP strings
	firstIPPortArr := strings.Split(firstIP, ":")
	firstIPArr := strings.Split(firstIPPortArr[0], ".")
	secondIPPortArr := strings.Split(secondIP, ":")
	secondIPArr := strings.Split(secondIPPortArr[0], ".")

	// compare and return ordered string literal array
	for index, num := range firstIPArr {
		switch {
		case num == secondIPArr[index]:
			continue
		case num > secondIPArr[index]:
			return [2]string{secondIP, firstIP}
		default:
			return [2]string{firstIP, secondIP}
		}
	} // now check ports if nums were the same and return ordered IP:Ports
	if firstIPPortArr[1] < secondIPPortArr[1] {
		return [2]string{firstIP, secondIP}
	}
	return [2]string{secondIP, firstIP}
}

// SortIPs sorts IP addresses of an array in asc. order (quicksort)
func SortIPs(addrs []string) []string {
	// recursion base case
	if len(addrs) < 2 {
		return addrs
	}
	// random ip in addrs as pivot
	pivot := addrs[rand.Intn(len(addrs))] //nolint:gosec

	var left []string   // for IPs<pivot
	var middle []string // for IPs=pivot
	var right []string  // for IPs>pivot

	for _, ip := range addrs {
		switch {
		case OrderIPPair(ip, pivot)[0] == ip:
			left = append(left, ip)
		case ip == pivot:
			middle = append(middle, ip)
		default:
			right = append(right, ip)
		}
	}

	// combine and return
	left, right = SortIPs(left), SortIPs(right)
	var sortedIPs []string
	sortedIPs = append(sortedIPs, left...)
	sortedIPs = append(sortedIPs, middle...)
	sortedIPs = append(sortedIPs, right...)
	return RemoveDuplicateStr(sortedIPs)
}

// WriteStringToFile writes a string to a file
func WriteStringToFile(outputFile, data string) error {
	out, err := os.Create(outputFile)
	if err != nil {
		return LogError(err)
	}
	defer out.Close()
	if _, err = out.WriteString(data); err != nil {
		return LogError(err)
	}

	return nil
}

// FilePathWalkDir ...
func FilePathWalkDir(dirPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// RemoveDuplicateStr removes duplicate strings from a slice of strings
func RemoveDuplicateStr(strSlice []string) []string { //nolint:typecheck
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
