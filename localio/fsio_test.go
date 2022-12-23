package localio

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestExists(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"Dir test", args{path: "/etc"}, true, false},
		{"File test", args{path: "/bin/bash"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Exists(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Exists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Exists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveAbsPath(t *testing.T) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("cant get homedir: %v", err)
	}
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"Tilda Test", args{path: "~/.bash_history"}, fmt.Sprintf("%s/.bash_history", homedir), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveAbsPath(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveAbsPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ResolveAbsPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSortHosts(t *testing.T) {
	type args struct {
		addrs []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{name: "Sort IPv4s and Hostnames", args: args{addrs: []string{
			"10.10.10.12:9001",
			"10.10.10.10:80",
			"10.10.10.10:80",
			"10.10.10.11:443",
			"10.10.10.11:22",
			"blackhillsinfosec.com:443",
			"10.10.10.11:80",
			"blackhillsinfosec.com:80",
			"10.10.10.11:9001",
			"hackerone.com:443",
		}}, want: []string{
			"10.10.10.10:80",
			"10.10.10.11:22",
			"10.10.10.11:80",
			"10.10.10.11:443",
			"10.10.10.11:9001",
			"10.10.10.12:9001",
			"blackhillsinfosec.com:80",
			"blackhillsinfosec.com:443",
			"hackerone.com:443",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Sort(StringSlice(tt.args.addrs))
			fmt.Println(tt.args.addrs)
			if got := RemoveDuplicateStr(tt.args.addrs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SortHosts() = %v\n, want %v\n", got, tt.want)
			}
		})
	}
}
