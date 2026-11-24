package ssh

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// setting is the effective value of one sshd keyword and where it came from.
type setting struct {
	Value  string
	Source string // "file:line", or "default"
}

// sshdConfig is the effective global sshd configuration. Like sshd itself,
// the first occurrence of a keyword wins, Include directives are expanded in
// place, and Match blocks are ignored because they only apply conditionally.
type sshdConfig struct {
	settings map[string]setting
}

const sshdConfigPath = "/etc/ssh/sshd_config"

// OpenSSH defaults for the keywords hostwarden evaluates.
var sshdDefaults = map[string]string{
	"passwordauthentication": "yes",
	"permitrootlogin":        "prohibit-password",
	"maxauthtries":           "6",
	"permitemptypasswords":   "no",
	"x11forwarding":          "no",
}

func loadSSHDConfig(h *host.Host) (*sshdConfig, error) {
	cfg := &sshdConfig{settings: map[string]setting{}}
	if err := cfg.parse(h, sshdConfigPath, 0); err != nil && !errors.Is(err, errStopMatch) {
		return nil, err
	}
	return cfg, nil
}

func (c *sshdConfig) parse(h *host.Host, file string, depth int) error {
	if depth > 8 {
		return fmt.Errorf("sshd_config: Include nesting too deep at %s", file)
	}
	lines, err := h.Lines(file)
	if err != nil {
		return err
	}
	for _, l := range lines {
		key, value := splitDirective(l.Text)
		if key == "" {
			continue
		}
		if key == "match" {
			// Everything after the first Match belongs to conditional blocks.
			return errStopMatch
		}
		if key == "include" {
			for _, pattern := range strings.Fields(value) {
				if !path.IsAbs(pattern) {
					pattern = path.Join("/etc/ssh", pattern)
				}
				for _, inc := range h.Glob(pattern) {
					if err := c.parse(h, inc, depth+1); err != nil {
						if errors.Is(err, errStopMatch) || !host.IsNotExist(err) {
							return err
						}
					}
				}
			}
			continue
		}
		if _, seen := c.settings[key]; !seen {
			c.settings[key] = setting{Value: value, Source: fmt.Sprintf("%s:%d", file, l.N)}
		}
	}
	return nil
}

// errStopMatch unwinds nested Includes once a Match block starts.
var errStopMatch = errors.New("match block reached")

// splitDirective splits "Keyword value" or "Keyword=value" into a lower-cased
// keyword and its value, ignoring comments and blank lines.
func splitDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key := strings.ToLower(line[:i])
	value := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	value = strings.Trim(value, `"`)
	return key, value
}

// get returns the effective value for keyword, falling back to defaults.
func (c *sshdConfig) get(keyword string) setting {
	if s, ok := c.settings[keyword]; ok {
		return s
	}
	return setting{Value: sshdDefaults[keyword], Source: "default"}
}

// explicit reports whether keyword was set in a config file.
func (c *sshdConfig) explicit(keyword string) (setting, bool) {
	s, ok := c.settings[keyword]
	return s, ok
}
