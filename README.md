# Gorecon

[![Go Report Card](https://goreportcard.com/badge/github.com/mr-pmillz/gorecon)](https://goreportcard.com/report/github.com/mr-pmillz/gorecon)
![GitHub all releases](https://img.shields.io/github/downloads/mr-pmillz/gorecon/total?style=social)
![GitHub repo size](https://img.shields.io/github/repo-size/mr-pmillz/gorecon?style=plastic)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/mr-pmillz/gorecon?style=plastic)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/mr-pmillz/gorecon?style=plastic)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/mr-pmillz/gorecon?style=plastic)
[![CI](https://github.com/mr-pmillz/gorecon/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-pmillz/gorecon/actions/workflows/ci.yml)

Table of Contents
=================

* [Gorecon](#gorecon)
* [Table of Contents](#table-of-contents)
  * [About](#about)
  * [Future Feature Presentation](#future-feature-presentation)
  * [Docs](#docs)
  * [Installation](#installation)
  * [Usage](#usage)
  * [srctleaks](#srctleaks)
  * [Nessus Parser](#nessus-parser)

## About

This project was built to automate various repetitive tasks for external recon gathering.
Currently, the recon sub command runs the following tools in this order
1. [recon-ng](https://github.com/lanmaster53/recon-ng)
2. [subfinder](https://github.com/projectdiscovery/subfinder)
3. [httpx](https://github.com/projectdiscovery/httpx)
4. [katana](https://github.com/projectdiscovery/katana)
5. [gowitness](https://github.com/sensepost/gowitness)

Optional recon
1. [dnsrecon](https://github.com/darkoperator/dnsrecon)
2. [asnmap](https://github.com/projectdiscovery/asnmap)

- The srctleaks sub command discovers public organization repositories and users.
  - Then [GitLeaks](https://github.com/zricethezav/gitleaks) is run against all found public repositories.

- The nessus sub command parses a .nessus file, prints a nice table
  - and writes corresponding host:port to individual findings files

## Future Feature Presentation

As an optional feature ToDo:
- Add a docker-compose.yml to spin up a local elasticsearch and kibana instance
- Then push results to elastic and create nice reports  ¯\_(ツ)_/¯ :man_shrugging:

## Docs

  * [gorecon](docs/gorecon.md)                         - Automate external recon.
  * [gorecon recon](docs/gorecon_recon.md)             - Run all gorecon recon modules.
  * [gorecon srctleaks](docs/gorecon_srctleaks.md)     - Run Gitleaks against discovered public organization repositories.
  * [gorecon nessus](docs/gorecon_nessus.md)           - Parses a .nessus file, prints nice table and writes relevant hosts:ports to corresponding findings files

## Installation

Download the compiled binary from [releases](https://github.com/mr-pmillz/gorecon/releases)
Or download the program directly with go

```shell
go install github.com/mr-pmillz/gorecon@latest
```

create your [config.yaml](config/config.yaml.dist) file
ensure netblock ips are in IPv4 CIDR range formats. For a single ip, you would use 10.10.10.111/32
**DO NOT PUT COMMENTS in your config.yaml file.** This will break vipers parsing of the configuration.

```shell
cp config/config.yaml.dist config.yaml
```

For best results, ensure you add your api keys to recon-ng.
Can also add api keys file path to subfinder via config.yaml.
For example
```yaml
SUBFINDER_KEYS_FILE: "/home/YOURUSERNAME/.config/subfinder/provider-config.yaml"
```
- See [Subfinder-Post-Installation-Instructions](https://github.com/projectdiscovery/subfinder#post-installation-instructions)

Missing provider keys will just be skipped and free ones will be used.

## Usage

Gorecon supports yaml configuration files along with cli arguments. Cli args should override values in the configuration file.

```shell
Automates recon-ng based upon cli args or yaml configuration file. More features coming soon!

Usage:
  gorecon [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  nessus      parses nessus file
  recon       Run recon enumeration
  srctleaks   GitHub Public Repo OSINT

Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
  -h, --help            help for gorecon

Use "gorecon [command] --help" for more information about a command.
```

Run gorecon from a yaml configuration file.
See [config.yaml](config/config.yaml.dist)

## recon

```shell
Run recon enumeration

Example Commands:
        gorecon recon --config config.yaml

Usage:
  gorecon recon [--domain|-d example.com] [flags]

Flags:
      --asn                          if this flag is set, will query primary domain for ASN data via asnmap package
  -c, --company string               company name that your testing
      --creator string               report creator
  -d, --domain string                domain string or file containing domains ex. domains.txt
  -h, --help                         help for recon
  -m, --modules string               list of recon-ng modules you want to run for domains and hosts
  -n, --netblock string              CIDRs you wish to scan
      --out-of-scope string          out of scope domains, IPs, or CIDRs
  -o, --output string                report output dir
      --run-dnsrecon                 if this flag is specified, dnsrecon will be ran in addition to default enumeration
      --subfinder-keys-file string   file path to subfinder provider config containing api keys
  -w, --workspace string             workspace name, use one word

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```

## srctleaks

Find Public GitHub Organization for the Company specified in your config.yaml.
Runs [GitLeaks](https://github.com/zricethezav/gitleaks) natively in golang against all identified Public Repos
Also logs Repos and Organization Users to a file and removes repos with no found secrets.

**TL:DR**
If you're not finding an orgs public GitHub account, you may want to search GitHub manually for the org and then specify the -c flag accordingly

```shell
Checks for a public organization based upon company name arg and clones all repos then runs gitleaks on them to check for secrets.

Example Commands:
        gorecon srctleaks -c SpyVsSpyEnterprises -d made-up-spy-domain.com --github-token ${GITHUB_TOKEN} -o path/to/output/dir
        gorecon srctleaks -c SpyVsSpyEnterprises -d made-up-spy-domain.com --github-token ${GITHUB_TOKEN} -o path/to/output/dir --check-all-org-users
        gorecon srctleaks --config config.yaml
        gorecon srctleaks --config config.yaml --check-all-org-users

Usage:
  gorecon srctleaks [flags]

Flags:
      --check-all-org-users   runs gitleaks against all GitHub organization users public repos. Be cautious, this can take a while. Currently ignores Forked Repos
  -c, --company string        company name that your testing
      --debug                 Prints verbose debugging information
  -d, --domain string         domain string or file containing domains ex. domains.txt
      --github-token string   github personal access token for github API interaction
  -h, --help                  help for srctleaks
  -o, --output string         report output dir

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```

## Nessus Parser

```shell
parses nessus file, prints and logs hosts and plugin id data etc.

Example Commands:
        gorecon nessus -n path/to/scan-results.nessus -o path/to/output-dir
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --testssl

Usage:
  gorecon nessus [flags]

Flags:
  -h, --help                 help for nessus
  -n, --nessus-file string   full or relative path to nessus file.nessus
  -o, --output string        report output dir
      --testssl              runs Testssl.sh against all tls and ssl nessus findings hosts

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```