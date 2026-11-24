// Package dockerapi is a minimal, read-only Docker Engine API client over a
// unix socket. It issues GET requests only.
package dockerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Client talks to the Docker Engine API.
type Client struct {
	http *http.Client
	base string
}

// New returns a client for the unix socket at socketPath.
func New(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 10 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: 20 * time.Second}, base: "http://docker"}
}

// NewWithHTTP returns a client using a custom HTTP client and base URL (tests).
func NewWithHTTP(c *http.Client, base string) *Client {
	return &Client{http: c, base: strings.TrimRight(base, "/")}
}

type listEntry struct {
	ID string `json:"Id"`
}

type inspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		User  string `json:"User"`
		Image string `json:"Image"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		CapAdd      []string `json:"CapAdd"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// Containers lists running containers with their security-relevant config.
func (c *Client) Containers(ctx context.Context) ([]host.Container, error) {
	var list []listEntry
	if err := c.get(ctx, "/containers/json", &list); err != nil {
		return nil, err
	}
	out := make([]host.Container, 0, len(list))
	for _, e := range list {
		var in inspect
		if err := c.get(ctx, "/containers/"+e.ID+"/json", &in); err != nil {
			return nil, err
		}
		ct := host.Container{
			ID:          shortID(in.ID),
			Name:        strings.TrimPrefix(in.Name, "/"),
			Image:       in.Config.Image,
			User:        in.Config.User,
			Privileged:  in.HostConfig.Privileged,
			NetworkMode: in.HostConfig.NetworkMode,
			PidMode:     in.HostConfig.PidMode,
			CapAdd:      in.HostConfig.CapAdd,
		}
		for _, m := range in.Mounts {
			ct.Mounts = append(ct.Mounts, host.Mount{Source: m.Source, Destination: m.Destination, ReadWrite: m.RW})
		}
		out = append(out, ct)
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("docker api %s: %w", path, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker api %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker api %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("docker api %s: decode: %w", path, err)
	}
	return nil
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
