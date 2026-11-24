package container

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

type fakeDocker struct {
	cts []host.Container
	err error
}

func (f fakeDocker) Containers(context.Context) ([]host.Container, error) { return f.cts, f.err }

func TestContainerAPIChecks(t *testing.T) {
	t.Parallel()
	cts := []host.Container{
		{Name: "app", Image: "app:1", User: "10001"},
		{Name: "ci-runner", Image: "gitlab-runner", Privileged: true, Mounts: []host.Mount{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", ReadWrite: true}}},
		{Name: "agent", Image: "monitor", User: "root", PidMode: "host", NetworkMode: "host", CapAdd: []string{"SYS_ADMIN"}, Mounts: []host.Mount{{Source: "/", Destination: "/host", ReadWrite: false}}},
		{Name: "web", Image: "nginx", User: "0:0", NetworkMode: "bridge", Mounts: []host.Mount{{Source: "/srv/www", Destination: "/usr/share/nginx/html"}}},
	}
	tests := []struct {
		check string
		want  []string
	}{
		{"HW-CTR-004", []string{"container:ci-runner", "container:agent"}},
		{"HW-CTR-005", []string{"container:ci-runner:/var/run/docker.sock", "container:agent:/host"}},
		{"HW-CTR-006", []string{"container:ci-runner", "container:agent", "container:web"}},
		{"HW-CTR-007", []string{"container:agent"}},
	}
	h := host.New(host.Config{Root: t.TempDir(), Docker: fakeDocker{cts: cts}})
	for _, tc := range tests {
		t.Run(tc.check, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, h)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(testutil.Targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
		})
	}
	t.Run("read-only root mount is high", func(t *testing.T) {
		t.Parallel()
		got, _ := testutil.RunCheck(t, Checks(), "HW-CTR-005", h)
		if got[1].Severity != audit.High {
			t.Errorf("severity = %v, want high", got[1].Severity)
		}
	})
}

func TestContainerAPISkips(t *testing.T) {
	t.Parallel()
	for name, d := range map[string]host.ContainerLister{
		"no client":   nil,
		"unreachable": fakeDocker{err: errors.New("permission denied")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := host.New(host.Config{Root: t.TempDir(), Docker: d})
			_, err := testutil.RunCheck(t, Checks(), "HW-CTR-004", h)
			if _, ok := audit.IsSkip(err); !ok {
				t.Errorf("err = %v, want skip", err)
			}
		})
	}
}

func TestDaemonAndSocket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		check string
		tree  testutil.Tree
		want  []string
	}{
		{"socket 660", "HW-CTR-001", testutil.Tree{"run/docker.sock": {Mode: 0o660}}, nil},
		{"socket 666", "HW-CTR-001", testutil.Tree{"run/docker.sock": {Mode: 0o666}}, []string{"/run/docker.sock"}},
		{"daemon unix only", "HW-CTR-002", testutil.Tree{"etc/docker/daemon.json": {Content: `{"hosts":["unix:///run/docker.sock"]}`}}, nil},
		{"daemon tcp with tls", "HW-CTR-002", testutil.Tree{"etc/docker/daemon.json": {Content: `{"hosts":["tcp://0.0.0.0:2376"],"tlsverify":true}`}}, nil},
		{"daemon tcp plaintext", "HW-CTR-002", testutil.Tree{"etc/docker/daemon.json": {Content: `{"hosts":["tcp://0.0.0.0:2375"]}`}}, []string{"/etc/docker/daemon.json"}},
		{"systemd override", "HW-CTR-002", testutil.Tree{"etc/systemd/system/docker.service.d/override.conf": {Content: "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375\n"}}, []string{"/etc/systemd/system/docker.service.d/override.conf:3"}},
		{"docker group", "HW-CTR-003", testutil.Tree{"etc/group": {Content: "docker:x:999:alice,bob\n"}}, []string{"user:alice", "user:bob"}},
		{"empty docker group", "HW-CTR-003", testutil.Tree{"etc/group": {Content: "docker:x:999:\n"}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, testutil.Host(testutil.Build(t, tc.tree)))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(testutil.Targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
		})
	}
}
