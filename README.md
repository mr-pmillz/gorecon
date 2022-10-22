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

## About

This project was built to automate various repetitive tasks for external recon gathering.
Currently, runs the following tools in this order
1. dnsrecon
2. recon-ng
3. subfinder
4. httpx
5. gowitness

## Future Feature Presentation

As an optional feature ToDo:
- Add terraform and ansible to set up elasticsearch & kibana (ELK)
- Then push results to elastic and create nice reports  ¯\_(ツ)_/¯ :man_shrugging:

## Docs

  * [gorecon](docs/gorecon.md)                         - Automate external recon.
  * [gorecon recon](docs/gorecon_recon.md)             - Run all gorecon recon modules.

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

For best results, ensure you add your api keys to recon-ng, at the very least, the free ones.
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
External recon automation tool

Usage:
  gorecon [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  recon       Run recon enumeration

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

- Run gorecon with cli args

```shell
  -c, --company string        company name that your testing
      --creator string        report creator
  -d, --domain string         domain string or file containing domains ex. domains.txt
  -h, --help                  help for recon
  -m, --modules string        list of recon-ng modules you want to run for domains and hosts
  -n, --netblock string       CIDRs you wish to scan
      --out-of-scope string   out of scope domains, IPs, or CIDRs
  -o, --output string         output dir, defaults to ~/work
  -w, --workspace string      workspace name, use one word
```

examples
```shell
./gorecon recon -c COMPANY-NAME -d BASE-DOMAIN -m modules.txt -w WORKSPACE-NAME -n netblocks.txt -o ~/target-output
./gorecon recon -c COMPANY-NAME -d domains.txt -m modules.txt -w WORKSPACE-NAME -n netblocks.txt -o ~/target-output
```