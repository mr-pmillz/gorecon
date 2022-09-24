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
  * [Docs](#docs)
  * [Installation](#installation)
  * [Usage](#usage)

## About

This project was built to automate various repetitive tasks for external recon gathering.

## Docs

  * [gorecon](docs/gorecon.md)                         - Automate external recon.
  * [gorecon recon](docs/gorecon_recon.md)             - Run all gorecon recon modules. So far just recon-ng is completed.

## Installation

Download the compiled binary from [releases](https://github.com/mr-pmillz/gorecon/releases)
Or download the program directly with go

```shell
go install github.com/mr-pmillz/gorecon@latest
```

create your [config.yaml](config/config.yaml.dist) file
ensure netblock ips are in IPv4 CIDR range formats. For a single ip, you would use 10.10.10.111/32

```shell
cp config/config.yaml.dist config.yaml
```

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
# -c is the company name 
# -d is the base domain such as foo.bar or a file containing a list of domains.
# -m is a file containing recon-ng modules you want to run
# -n is a file containing CIDRs or IPs 
# -o is the output directory you want the generated reports to go.
./gorecon recon -c COMPANY-NAME -d BASE-DOMAIN -m modules.txt -w WORKSPACE-NAME -n netblocks.txt -o ~/work
./gorecon recon -c COMPANY-NAME -d domains.txt -m modules.txt -w WORKSPACE-NAME -n netblocks.txt -o ~/work
```