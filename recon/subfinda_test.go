package recon

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_runSubfinder(t *testing.T) {
	type args struct {
		domains []string
		opts    *Options
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{name: "Testing Subfinder", args: args{
			domains: []string{"hackerone.com"},
			opts: &Options{
				Company:                 "Hackerone",
				Creator:                 "Mr-PMillz",
				Domain:                  []string{"hackerone.com"},
				Modules:                 nil,
				NetBlock:                nil,
				OutOfScope:              nil,
				Output:                  "test",
				Workspace:               "hackerone",
				SubFinderProviderConfig: "",
			},
		}, want: []string{}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runSubfinder(tt.args.domains, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("runSubfinder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if ok := assert.IsType(t, []string{}, got); !ok {
				t.Errorf("runSubfinder() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseOutputFiles(t *testing.T) {
	type args struct {
		domains   []string
		outputDir string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr assert.ErrorAssertionFunc
	}{
		{name: "Test parseOutputFiles", args: args{
			domains:   []string{"hackerone.com"},
			outputDir: "test",
		}, want: []string{}, wantErr: assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOutputFiles(tt.args.domains, tt.args.outputDir)
			if !tt.wantErr(t, err, fmt.Sprintf("parseOutputFiles(%v, %v)", tt.args.domains, tt.args.outputDir)) {
				return
			}
			if ok := assert.IsType(t, []string{}, got); !ok {
				t.Errorf("parseOutputFiles() got = %v, want %v", got, tt.want)
			}
		})
	}
}
