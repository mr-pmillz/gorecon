package nessus

import (
	"github.com/mr-pmillz/gorecon/v2/localio"
	"os"
	"testing"
)

func Test_parseEnum4LinuxOutput(t *testing.T) {
	enum4linuxNGTestDir, err := localio.ResolveAbsPath("test/enum4linux-ng-test")
	if err != nil {
		t.Errorf("couldn't resolve abs path")
	}
	type args struct {
		outputDir string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Test parseEnum4LinuxOutput", args: args{outputDir: enum4linuxNGTestDir}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseEnum4LinuxOutput(tt.args.outputDir); (err != nil) != tt.wantErr {
				t.Errorf("parseEnum4LinuxOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	t.Cleanup(func() {
		if exists, err := localio.Exists("test/enum4linux-ng-test/valid-users.txt"); err == nil && exists {
			if err = os.Remove("test/enum4linux-ng-test/valid-users.txt"); err != nil {
				t.Errorf("couldnt remove test file: %v", err)
			}
		}
		if exists, err := localio.Exists("test/enum4linux-ng-test/fqdns-and-ips.txt"); err == nil && exists {
			if err = os.Remove("test/enum4linux-ng-test/fqdns-and-ips.txt"); err != nil {
				t.Errorf("couldnt remove test file: %v", err)
			}
		}
	})
}
