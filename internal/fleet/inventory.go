// Package fleet runs hostwarden across many hosts over SSH: it uploads the
// static binary to a private temp dir, runs a JSON scan, removes the binary,
// and aggregates the reports. Host keys are always verified against
// known_hosts; there is no trust-on-first-use mode.
package fleet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// HostSpec describes how to reach one host. Zero fields inherit from the
// inventory defaults.
type HostSpec struct {
	Name         string   `yaml:"name"`
	Address      string   `yaml:"address"`
	Port         int      `yaml:"port"`
	User         string   `yaml:"user"`
	IdentityFile string   `yaml:"identity_file"`
	KnownHosts   string   `yaml:"known_hosts"`
	Sudo         *bool    `yaml:"sudo"`
	Args         []string `yaml:"args"`
}

// Inventory is the fleet inventory file.
type Inventory struct {
	Defaults HostSpec   `yaml:"defaults"`
	Hosts    []HostSpec `yaml:"hosts"`
}

// LoadInventory parses an inventory and resolves defaults into each host.
func LoadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}
	return ParseInventory(b)
}

// ParseInventory parses inventory YAML.
func ParseInventory(b []byte) (*Inventory, error) {
	var inv Inventory
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if len(inv.Hosts) == 0 {
		return nil, errors.New("inventory has no hosts")
	}
	names := map[string]bool{}
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		h.applyDefaults(inv.Defaults)
		if h.Address == "" {
			return nil, fmt.Errorf("host %d (%q): address is required", i, h.Name)
		}
		if h.Name == "" {
			h.Name = h.Address
		}
		if names[h.Name] {
			return nil, fmt.Errorf("duplicate host name %q", h.Name)
		}
		names[h.Name] = true
		if h.User == "" {
			return nil, fmt.Errorf("host %q: user is required (set it per host or in defaults)", h.Name)
		}
	}
	return &inv, nil
}

func (h *HostSpec) applyDefaults(d HostSpec) {
	if h.Port == 0 {
		h.Port = d.Port
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.User == "" {
		h.User = d.User
	}
	if h.IdentityFile == "" {
		h.IdentityFile = d.IdentityFile
	}
	if h.KnownHosts == "" {
		h.KnownHosts = d.KnownHosts
	}
	if h.KnownHosts == "" {
		h.KnownHosts = "~/.ssh/known_hosts"
	}
	if h.Sudo == nil {
		h.Sudo = d.Sudo
	}
	if h.Args == nil {
		h.Args = d.Args
	}
	h.IdentityFile = expandHome(h.IdentityFile)
	h.KnownHosts = expandHome(h.KnownHosts)
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// UseSudo reports whether the scan runs under `sudo -n`.
func (h HostSpec) UseSudo() bool { return h.Sudo != nil && *h.Sudo }
