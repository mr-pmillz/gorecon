package nessus

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
)

// runCrackMapExecSMB runs crackmapexec against smb hosts found from nessus
func runCrackMapExecSMB(outputDir string) error {
	if err := localio.RunCommandPipeOutput(fmt.Sprintf("crackmapexec smb %s/smb/nessus-smb-hosts.txt | tee %s/smb/cme-smb-hosts.txt", outputDir, outputDir)); err != nil {
		return localio.LogError(err)
	}

	if err := localio.RunCommandPipeOutput(fmt.Sprintf("crackmapexec smb %s/smb/nessus-smb-hosts.txt --shares -u 'guest' -p '' | tee %s/smb/cme-smb-nopass-shares-hosts.txt", outputDir, outputDir)); err != nil {
		return localio.LogError(err)
	}

	return nil
}
