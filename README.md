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

## About

This project was built to automate various repetitive tasks for external recon gathering.
Currently, the recon sub command runs the following tools in this order
1. [dnsrecon](https://github.com/darkoperator/dnsrecon)
2. [recon-ng](https://github.com/lanmaster53/recon-ng)
3. [subfinder](https://github.com/projectdiscovery/subfinder)
4. [httpx](https://github.com/projectdiscovery/httpx)
5. [gowitness](https://github.com/sensepost/gowitness)

The srctleaks sub command discovers public organization repositories and users.
Then [GitLeaks](https://github.com/zricethezav/gitleaks) is run against all found public repositories.

## Future Feature Presentation

As an optional feature ToDo:
- Add terraform and ansible to set up elasticsearch & kibana (ELK)
- Then push results to elastic and create nice reports  ¯\_(ツ)_/¯ :man_shrugging:

## Docs

  * [gorecon](docs/gorecon.md)                         - Automate external recon.
  * [gorecon recon](docs/gorecon_recon.md)             - Run all gorecon recon modules.
  * [gorecon srctleaks](docs/gorecon_srctleaks.md)     - Run Gitleaks against discovered public organization repositories.

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

By default, gorecon will specify all providers to subfinder, ones with missing keys will just be skipped and free ones will be used.

## Usage

Gorecon supports yaml configuration files along with cli arguments. Cli args should override values in the configuration file.

```shell
Automates recon-ng based upon cli args or yaml configuration file. More features coming soon!

Usage:
  gorecon [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  recon       Run recon enumeration
  srctleaks   GitHub Public Repo OSINT

Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
  -h, --help            help for gorecon

Use "gorecon [command] --help" for more information about a command.
```

Run gorecon from a yaml configuration file.
See [config.yaml](config/config.yaml.dist)

```shell
./gorecon recon --config config.yaml
```
## srctleaks

Find Public GitHub Organization for the Company specified in your config.yaml.
Runs [GitLeaks](https://github.com/zricethezav/gitleaks) natively in golang against all identified Public Repos
Also logs Repos and Organization Users to a file and removes repos with no found secrets.
Initial proof of concept. checks for GitHub Organization based upon COMPANY arg / config.yaml key

- Checks against primary base domain without .tld to match GitHub Organization name. Works for some companies but not a catch all.
  - Example, Company name = Example & Domain = example.com this would match as company name is transformed to lowercase.
- **TL:DR**
You might want to search GitHub manually for the org and then specify -c and -d flags accordingly

```shell
Checks for a public organization based upon company name arg and clones all repos then runs gitleaks on them to check for secrets

Usage:
  gorecon srctleaks [flags]

Flags:
  -c, --company string        company name that your testing
  -d, --domain string         domain string or file containing domains ex. domains.txt
      --github-token string   github personal access token for github API interaction
  -h, --help                  help for srctleaks
  -o, --output string         report output dir

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```
