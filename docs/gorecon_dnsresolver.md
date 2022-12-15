## gorecon dnsresolver

Attempts to resolve all hosts, CIDRs, and/or IPs from a provided file

### Synopsis

Attempts to resolve all hosts, CIDRs, and/or IPs from a provided file. 
The dnsresolver subcommand will automatically parse the nameservers in /etc/resolv.conf using the "github.com/miekg/unbound" library's ResolvConf() method

Example Commands:
	gorecon dnsresolver -t path/to/target-list.txt -o path/to/output-dir
	gorecon dnsresolver -t path/to/target-list.txt -o path/to/output-dir -w 30


```
gorecon dnsresolver [flags]
```

### Options

```
  -h, --help             help for dnsresolver
  -o, --output string    directory where results will be written to. if dir not exist is created.
  -t, --targets string   full or relative path to a file containing a list of targets, CIDRs, hostnames, IPs
  -w, --workers int      number of goroutines to use. default is 10 (default 10)
```

### Options inherited from parent commands

```
      --config string   config file (default is APP_ROOT/config/config.yaml
```

### SEE ALSO

* [gorecon](gorecon.md)	 - External recon automation tool

###### Auto generated by spf13/cobra on 14-Dec-2022