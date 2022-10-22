package recon

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_resolveDomainToIP(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr assert.ErrorAssertionFunc
	}{
		{name: "resolveDomainToIP() test", args: args{domain: "hackerone.com"}, want: []string{}, wantErr: assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDomainToIP(tt.args.domain)
			if !tt.wantErr(t, err, fmt.Sprintf("resolveDomainToIP(%v)", tt.args.domain)) {
				return
			}
			if ok := assert.IsType(t, []string{}, got); !ok {
				t.Errorf("parseOutputFiles() got = %v, want %v", got, tt.want)
			}
		})
	}
}
