# GoRecon

[![Go Report Card](https://goreportcard.com/badge/github.com/mr-pmillz/gorecon)](https://goreportcard.com/report/github.com/mr-pmillz/gorecon)
![GitHub all releases](https://img.shields.io/github/downloads/mr-pmillz/gorecon/total?style=social)
![GitHub repo size](https://img.shields.io/github/repo-size/mr-pmillz/gorecon?style=plastic)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/mr-pmillz/gorecon?style=plastic)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/mr-pmillz/gorecon?style=plastic)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/mr-pmillz/gorecon?style=plastic)
[![CI](https://github.com/mr-pmillz/gorecon/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-pmillz/gorecon/actions/workflows/ci.yml)

Table of Contents
=================

* [GoRecon](#gorecon)
* [Table of Contents](#table-of-contents)
  * [About](#about)
  * [Future Feature Presentation](#future-feature-presentation)
  * [Docs](#docs)
  * [Installation](#installation)
    * [Amass](#amass)
  * [Usage](#usage)
  * [recon](#recon)
  * [srctleaks](#srctleaks)
  * [Nessus Parser](#nessus-parser)
  * [Screenshots](#screenshots)

## About

This project was built to automate various penetration testing tasks such as reconnaissance, parsing nessus scan results and running additional tools, results analysis for reporting, and more.

**Brought to you by:**

![Black Hills Information Security](https://www.blackhillsinfosec.com/wp-content/uploads/2016/03/BHIS-logo-L-300x300.png "Black Hills Information Security")

## Future Feature Presentation

As an optional feature ToDo:
- Add a docker-compose.yml to spin up a local elasticsearch and kibana instance
- Then push results to elastic and create nice reports  ¯\\_(ツ)_/¯

## Docs

* [gorecon](docs/gorecon.md)                         - Automate external recon.
* [gorecon recon](docs/gorecon_recon.md)             - Run all gorecon recon modules.
* [gorecon srctleaks](docs/gorecon_srctleaks.md)     - Run Gitleaks against discovered public organization repositories.
* [gorecon nessus](docs/gorecon_nessus.md)           - Parses a .nessus file, prints nice table and writes relevant hosts:ports to corresponding findings files

## Installation

Download the compiled binary from [releases](https://github.com/mr-pmillz/gorecon/releases)
Or download the program directly with go

```shell
go install github.com/mr-pmillz/gorecon/v2@latest
```

some golang tools in this project that don't have a pkg available to implement natively rely on go module installation, make sure "HOME/go/bin" is in your PATH env var.
ex. if not already configured, add the following to your .bash_profile or ~/.zshrc or ~/.bashrc etc..
```bash
[[ ":$PATH:" != *":${HOME}/go/bin:"* ]] && export PATH="${PATH}:${HOME}/go/bin"
# Set GOPATH
if [[ -z "${GOPATH}" ]]; then export GOPATH="${HOME}/go"; fi
```

create your [config.yaml](config/config.yaml.dist) file
ensure netblock ips are in IPv4 CIDR range formats. For a single ip, you would use 10.10.10.111/32
**DO NOT PUT COMMENTS in your config.yaml file.** This will break vipers parsing of the configuration.
It is okay to leave NETBLOCK and/or OUT_OF_SCOPE empty if using the config.yaml file

```shell
wget https://raw.githubusercontent.com/mr-pmillz/gorecon/master/config/config.yaml.dist -O config.yaml
```

For best results, add your api keys to recon-ng.
Can also add api keys file path to subfinder via config.yaml.
For example
```yaml
SUBFINDER_KEYS_FILE: "/home/YOURUSERNAME/.config/subfinder/provider-config.yaml"
```
- See [Subfinder-Post-Installation-Instructions](https://github.com/projectdiscovery/subfinder#post-installation-instructions)

Missing provider keys will just be skipped and free ones will be used.

### Amass
For Amass, GoRecon will generate the scope portions of the config.ini for you
- you can provide your own data sources file containing api keys which will be combined into the [base-template](recon/templates/amass-config.ini)
  - see [Amass-Config](https://github.com/OWASP/Amass/blob/master/examples/config.ini) for all the available options
  - The base-template config.ini is embedded into the gorecon binary using the embed pkg
  - if you want to make a change open up an issue or make a pull request.
  - put your Amass data-sources in a file and point to it with either an env variable, GoRecon's config.yaml, or the --amass-data-sources argument.
    - You can also add data_sources to ignore such as CommonCrawl which can cause amass to timeout/hang
    - the contents of the AMASS_DATA_SOURCES|--amass-data-sources file should be like the following example:

```ini
# Are there any data sources that should be disabled?
[data_sources.disabled]
data_source = CommonCrawl

# https://passivedns.cn (Contact)
[data_sources.360PassiveDNS]
[data_sources.360PassiveDNS.Credentials]
apikey = API-KEY-HERE

# https://asnlookup.com (Free)
[data_sources.ASNLookup]
[data_sources.ASNLookup.Credentials]
apikey = API-KEY-HERE
...snippet...
```

## Usage

GoRecon supports yaml configuration files along with cli arguments. Cli args should override values in the configuration file.
The optional config.yaml file is only geared towards the recon and srctleaks sub commands. It is recommended to use it with the recon sub command.

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
  -v, --version         version for gorecon

Use "gorecon [command] --help" for more information about a command.
```

Run GoRecon from a yaml configuration file.
See [config.yaml](config/config.yaml.dist)

## recon

The recon sub command runs the following tools in this order
1. [recon-ng](https://github.com/lanmaster53/recon-ng)
2. [subfinder](https://github.com/projectdiscovery/subfinder)
3. [httpx](https://github.com/projectdiscovery/httpx)
4. [gowitness](https://github.com/sensepost/gowitness)
5. [katana](https://github.com/projectdiscovery/katana)

Optional recon
- [dnsrecon](https://github.com/darkoperator/dnsrecon)
- [Amass](https://github.com/OWASP/Amass)

```shell
Run recon enumeration

Example Commands:
        gorecon recon --config config.yaml

Usage:
  gorecon recon [--domain|-d example.com] [flags]

Flags:
      --amass-data-sources string     path to a file containing amass data sources you want to use
      --asnlookup-api string          optional api key for ASN lookups, is free. see https://docs.rapidapi.com/docs/keys
  -c, --company string                company name that your testing
      --creator string                report creator
  -d, --domain string                 domain string or file containing domains ex. domains.txt
  -h, --help                          help for recon
  -m, --modules string                list of recon-ng modules you want to run for domains and hosts
  -n, --netblock string               CIDRs you wish to scan
      --out-of-scope string           out of scope domains, IPs, or CIDRs
  -o, --output string                 report output dir
      --primary-domain-is-subdomain   if this flag is set, recon-ng will accept subdomains for the primary domain database
      --run-amass                     if this flag is set, will run amass active enumeration
      --run-dnsrecon                  if this flag is specified, dnsrecon will be ran in addition to default enumeration
      --subfinder-keys-file string    file path to subfinder provider config containing api keys
  -w, --workspace string              workspace name, use one word

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```

## srctleaks

Find Public GitHub Organization for the Company specified in your config.yaml.
Runs [GitLeaks](https://github.com/zricethezav/gitleaks) natively in golang against all identified Public Repos
Also logs Repos and Organization Users to a file and removes repos with no found secrets.
Currently, if the main organization is not of the "organization" metadata type, the user will be ignored even if it matches the target org name specified.

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

In addition to parsing a nessus file, additional enumeration can be performed with optional flags

```shell
parses nessus file, prints and logs hosts and plugin id data etc.

Example Commands:
        gorecon nessus -n path/to/scan-results.nessus -o path/to/output-dir
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --testssl
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --async-nmap
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --async-nmap-svc-scripts
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --stream-nmap
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --nuclei
        gorecon nessus --nessus-file path/to/scan-results.nessus --output path/to/output-dir --enum4linux-ng

Usage:
  gorecon nessus [flags]

Flags:
      --async-nmap               runs nmap asynchronously in 10 parallel goroutines with default scripts against all open ports for low through critical severity findings hosts
      --async-nmap-svc-scripts   runs nmap asynchronously in 30 parallel goroutines with scripts fine tuned per service
      --enum4linux-ng            runs enum4linux-ng against all hosts parsed from nessus within svc_name attribute slice []string{"cifs", "smb", "epmap", "ldap"} also runs initial crackmapexec smb against just port 445 hosts
  -h, --help                     help for nessus
  -n, --nessus-file string       full or relative path to nessus file.nessus
      --nuclei                   runs nuclei automatic templates against all web services
  -o, --output string            report output dir
      --stream-nmap              streams nmap synchronously with default scripts against all open ports for low through critical severity findings hosts
      --testssl                  runs Testssl.sh against all tls and ssl nessus findings hosts

Global Flags:
      --config string   config file (default is APP_ROOT/config/config.yaml
```

## Screenshots

![Nessus Parser](https://github.com/mr-pmillz/gorecon/blob/master/docs/img/nessus-parser-example.png "Nessus Parser")
