package srctleaks

import (
	"embed"
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/cmd"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"os"
	"strings"
	"time"
)

//go:embed gitleaksconfig/*
var gitLeaksConfigDir embed.FS

// runGitLeaks clones discovered organization repos and runs gitleaks against them.
// runGitLeaks will remove any repos which do not contain secrets.
func runGitLeaks(repos []string, opts *Options) error {
	cloneDir := fmt.Sprintf("%s/company-repos", opts.Output)
	if exists, err := localio.Exists(cloneDir); err == nil && !exists {
		if err = os.MkdirAll(cloneDir, 0750); err != nil {
			gologger.Fatal().Msgf("Could not mkdir %s\n", err)
		}
	}
	gitLeaksConfig, err := gitLeaksConfigDir.Open("gitleaksconfig/.gitleaks.toml")
	if err != nil {
		return localio.LogError(err)
	}
	if err = localio.EmbedFileCopy(gitLeaksConfig, "/tmp/.gitleaks.toml"); err != nil {
		return localio.LogError(err)
	}

	var (
		vc       config.ViperConfig
		findings []report.Finding
	)

	// Load config
	if err = viper.Unmarshal(&vc); err != nil {
		localio.LogFatal(err, "Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		localio.LogFatal(err, "Failed to load config")
	}
	cfg.Path = "/tmp/.gitleaks.toml"
	start := time.Now()

	detector := detect.NewDetector(cfg)
	detector.Verbose = true

	for _, repo := range repos {
		repoName := strings.ReplaceAll(strings.Split(repo, "/")[len(strings.Split(repo, "/"))-1], ".git", "")
		// clone organization repo to cloneDir
		repoPath := fmt.Sprintf("%s/%s", cloneDir, repoName)
		if err = localio.GitClone(repo, repoPath); err != nil {
			return localio.LogError(err)
		}
		findings, err = detector.DetectGit(repoPath, "", detect.DetectType)
		if err != nil {
			return localio.LogError(err)
		}
		// log info about the scan
		localio.LogInfo("Gitleaks", repoName, fmt.Sprintf("scan completed in %s", cmd.FormatDuration(time.Since(start))))
		if len(findings) != 0 {
			localio.LogWarning("Gitleaks Findings", repoName, fmt.Sprintf("leaks found: %d", len(findings)))
			// write report output json
			if err = report.Write(findings, cfg, "json", fmt.Sprintf("%s/%s.json", cloneDir, repoName)); err != nil {
				return localio.LogError(err)
			}
			// write report output csv
			if err = report.Write(findings, cfg, "csv", fmt.Sprintf("%s/%s.csv", cloneDir, repoName)); err != nil {
				return localio.LogError(err)
			}
		} else {
			localio.LogInfo("Gitleaks Findings", repoName, "no leaks found, removing repository")
			if err = os.RemoveAll(repoPath); err != nil {
				return localio.LogError(err)
			}
		}

	}

	return nil
}
