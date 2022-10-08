## gorecon recon

Run recon enumeration

### Synopsis

Run recon enumeration

```
gorecon recon [--domain|-d example.com] [flags]
```

### Options

```
  -c, --company string        company name that your testing
      --creator string        report creator (default "BHIS")
  -d, --domain string         domain string or file containing domains ex. domains.txt
  -h, --help                  help for recon
  -m, --modules string        list of recon-ng modules you want to run for domains and hosts
  -n, --netblock string       CIDRs you wish to scan
      --out-of-scope string   out of scope domains, IPs, or CIDRs
  -o, --output string         output dir, defaults to ~/work (default "~/work")
  -w, --workspace string      workspace name, use one word
```

### Options inherited from parent commands

```
      --config string   config file (default is APP_ROOT/config/config.yaml
```

### SEE ALSO

* [gorecon](gorecon.md)	 - A brief description of your application

###### Auto generated by spf13/cobra on 22-Sep-2022