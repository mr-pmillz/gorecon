package nessus

const (
	INFO     = "INFO"
	OK       = "OK"
	LOW      = "LOW"
	MEDIUM   = "MEDIUM"
	HIGH     = "HIGH"
	CRITICAL = "CRITICAL"
	// In the template, we use rangeStruct to turn our struct values
	// into a slice we can iterate over
	htmlTemplate = `{{range .}}<tr>
{{range rangeStruct .}} <td>{{.}}</td>
{{end}}</tr>
{{end}}`
)

var ScriptMaps = map[string]string{
	"amqp":      "amqp-info.nse",
	"ajp13":     "ajp-headers.nse,ajp-methods.nse,ajp-request.nse",
	"ftp":       "ftp-anon.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,ftp-syst.nse",
	"ssh":       "ssh-auth-methods.nse,ssh-hostkey.nse,ssh-publickey-acceptance.nse,ssh-run.nse,ssh2-enum-algos.nse,sshv1.nse",
	"telnet":    "banner.nse,telnet-encryption.nse,telnet-ntlm-info.nse",
	"smtp":      "smtp-commands.nse,smtp-enum-users.nse,smtp-ntlm-info.nse,smtp-open-relay.nse",
	"smb":       "smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse",
	"tftp":      "tftp-enum.nse", // UDP
	"vnc":       "realvnc-auth-bypass.nse,vnc-info.nse,vnc-title.nse",
	"oracle":    "oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse",
	"ldap":      "ldap-novell-getpass.nse,ldap-rootdse.nse,ldap-search.nse",
	"rpc-nfs":   "nfs-ls.nse,nfs-statfs.nse,nfs-showmount.nse", // TCP ~ 111/2049 UDP ~ 2049
	"mssql":     "ms-sql-info.nse,ms-sql-config.nse,broadcast-ms-sql-discover.nse,ms-sql-ntlm-info.nse,ms-sql-empty-password.nse",
	"mysql":     "mysql-variables.nse,mysql-users.nse,mysql-query.nse,mysql-enum.nse,mysql-empty-password.nse,mysql-databases.nse",
	"mongodb":   "mongodb-databases.nse,mongodb-info.nse",
	"kerberos":  "banner.nse,krb5-enum-users.nse",
	"ike":       "ike-version.nse",
	"sip":       "banner.nse,sip-enum-users.nse,sip-methods.nse",
	"javarmi":   "rmi-dumpregistry.nse,rmi-vuln-classloader.nse",
	"cups":      "cups-info.nse,cups-queue-info.nse",
	"cassandra": "cassandra-info.nse",
	"webdav":    "http-iis-webdav-vuln.nse",
	"pop3":      "pop3-capabilities.nse,pop3-ntlm-info.nse",
	"snmp":      "snmp-info.nse,snmp-interfaces.nse,snmp-netstat.nse,snmp-processes.nse,snmp-sysdescr.nse,snmp-win32-services.nse,snmp-win32-shares.nse,snmp-win32-software.nse,snmp-win32-users.nse", // UDP
	"stun":      "stun-info.nse,stun-version.nse",
}

var ServiceKinds = []string{
	// "activemq",
	"ajp13",
	"amqp",
	// "asf-rmcp",
	// "as-signon",
	// "cifs",
	// "cim_listener",
	// "dce-rpc",
	// "dns",
	// "elasticsearch",
	// "epmap",
	"ftp",
	// "general",
	// "http-rpc-epmap",
	// "ibm-iseries-portmapper",
	"ldap",
	// "mdns",
	"mssql",
	"mysql",
	// "ncacn_http",
	// "netbios-ns",
	// "ntp",
	// "onvif",
	"ike",
	// "rpc-mountd",
	"rpc-nfs",
	// "rpc-nfs_acl",
	// "rpc-nlockmgr",
	// "rpc-portmapper",
	"sip",
	// "slp",
	"smb",
	"snmp",
	"ssh",
	"stun",
	"telnet",
	"tftp",
	// "unknown",
	// "vmware_auth",
	"vnc",
	// "vxworks_wdb",
	// "www",
}
