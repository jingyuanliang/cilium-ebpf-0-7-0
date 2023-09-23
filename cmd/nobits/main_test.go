package main

import (
	"bytes"
	"embed"
	"testing"

	"github.com/cilium/ebpf"
)

//go:embed bpf_host.o
var bpf_host embed.FS

//go:embed bpf_lxc.o
var bpf_lxc embed.FS

func TestNobits(t *testing.T) {
	for _, tc := range []struct {
		name string
		data *embed.FS
	}{
		{
			name: "bpf_host.o",
			data: &bpf_host,
		},
		{
			name: "bpf_lxc.o",
			data: &bpf_lxc,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.data.ReadFile(tc.name)
			if err != nil {
				t.Fatalf("data.ReadFile: %v", err)
			}

			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ebpf.LoadCollectionSpec: %v", err)
			}

			if spec == nil {
				t.Errorf("ebpf.LoadCollectionSpec returns nil")
			}
		})
	}
}
