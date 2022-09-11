package localio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

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

// Exists returns whether the given file or directory exists
func Exists(path string) (bool, error) {
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

// DownloadFile ...
func DownloadFile(dest, url string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		fmt.Sprintf("Downloading %s", filepath.Base(url)),
	)
	_, err = io.Copy(io.MultiWriter(f, bar), resp.Body)
	return err
}

// CopyFile ...
func CopyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	if exists, err := Exists(filepath.Dir(dest)); err == nil && !exists {
		if err = os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
			return err
		}
	}

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	buf := make([]byte, 1024*1024*4)
	_, err = io.CopyBuffer(destFile, srcFile, buf)
	return err
}

// TimeTrack ...
func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s \ntook: %s\n", name, elapsed)
}

// RunCommandPipeOutput runs a bash command and pipes the output to stdout in realtime
// also has a built-in timer that tracks execution duration
// it returns an error
func RunCommandPipeOutput(command string) error {
	defer TimeTrack(time.Now(), command)
	fmt.Printf("[+] %s\n", command)
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		return err
	}

	timeout := 60

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, bashPath, "-c", command)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
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
		return err
	}

	if err = cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Error waiting for Cmd %s\n", err)
		return err
	}

	return nil
}

// RunCommandsPipeOutput ...
func RunCommandsPipeOutput(commands []string) error {
	for _, c := range commands {
		if err := RunCommandPipeOutput(c); err != nil {
			return err
		}
	}
	return nil
}

// ExecCMD Execute a command
func ExecCMD(command string) (string, error) {
	fmt.Printf("[+] %s\n", command)
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

// CopyStringToFile ...
func CopyStringToFile(data, dest string) error {
	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = destFile.WriteString(data)
	return err
}

// EmbedFileCopy ...
func EmbedFileCopy(dst string, src fs.File) error {
	destFilePath, err := ResolveAbsPath(dst)
	if err != nil {
		return err
	}

	if exists, err := Exists(filepath.Dir(destFilePath)); err == nil && !exists {
		if err = os.MkdirAll(filepath.Dir(destFilePath), 0750); err != nil {
			return err
		}
	}

	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(destFile, src); err != nil {
		return err
	}

	return nil
}

func PrettyPrint(v interface{}) (err error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		fmt.Println(string(b))
	}
	return
}

func FilePathWalkDir(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
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
func ConfigureFlagOpts(cmd *cobra.Command, LCMOpts *LoadFromCommandOpts) (interface{}, error) {
	cmdFlag, err := cmd.Flags().GetString(fmt.Sprintf("%s%s", LCMOpts.Prefix, LCMOpts.Flag))
	if err != nil {
		return nil, err
	}

	switch cmdFlag {
	case "":
		flagToUpperConfig := strings.ToUpper(strings.ReplaceAll(fmt.Sprintf("%s%s", LCMOpts.Prefix, LCMOpts.Flag), "-", "_"))
		configVal := viper.GetString(flagToUpperConfig)
		envVal, ok := os.LookupEnv(configVal)
		if ok {
			if LCMOpts.IsFilePath {
				fileExists, err := Exists(envVal)
				if err != nil {
					return nil, err
				}
				if fileExists {
					absVal, err := ResolveAbsPath(envVal)
					if err != nil {
						return nil, err
					}
					LCMOpts.Opts = absVal
				} else {
					LCMOpts.Opts = envVal
				}
			} else {
				LCMOpts.Opts = envVal
			}
		} else {
			if configVal != "" {
				if LCMOpts.IsFilePath {
					absConfigVal, err := ResolveAbsPath(configVal)
					if err != nil {
						return nil, err
					}
					LCMOpts.Opts = absConfigVal
				} else {
					LCMOpts.Opts = configVal
				}
			} else {
				if LCMOpts.DefaultFlagVal != "" && LCMOpts.IsFilePath {
					absDefaultVal, err := ResolveAbsPath(LCMOpts.DefaultFlagVal)
					if err != nil {
						return nil, err
					}
					_, err = os.Stat(absDefaultVal)
					if os.IsNotExist(err) {
						LCMOpts.Opts = cmdFlag
					} else {
						LCMOpts.Opts = absDefaultVal
					}
				} else if LCMOpts.DefaultFlagVal != "" && !LCMOpts.IsFilePath {
					LCMOpts.Opts = LCMOpts.DefaultFlagVal
				} else {
					LCMOpts.Opts = cmdFlag
				}
			}
		}
	default:
		envValue, ok := os.LookupEnv(strings.ToUpper(strings.ReplaceAll(fmt.Sprintf("%s%s", LCMOpts.Prefix, LCMOpts.Flag), "-", "_")))
		if ok {
			LCMOpts.Opts = envValue
		} else {
			if LCMOpts.IsFilePath {
				fileExists, err := Exists(cmdFlag)
				if err != nil {
					return nil, err
				}
				if fileExists {
					absCmdFlag, err := ResolveAbsPath(cmdFlag)
					if err != nil {
						return nil, err
					}
					LCMOpts.Opts = absCmdFlag
				} else {
					LCMOpts.Opts = cmdFlag
				}

			} else {
				LCMOpts.Opts = cmdFlag
			}
		}
	}

	return LCMOpts.Opts, nil
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
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
