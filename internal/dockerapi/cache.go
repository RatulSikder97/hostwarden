package dockerapi

import (
	"context"
	"sync"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Cached wraps a ContainerLister so that concurrent checks in one scan share
// a single round of API calls.
func Cached(l host.ContainerLister) host.ContainerLister {
	return &cached{inner: l}
}

type cached struct {
	inner host.ContainerLister
	once  sync.Once
	cts   []host.Container
	err   error
}

func (c *cached) Containers(ctx context.Context) ([]host.Container, error) {
	c.once.Do(func() { c.cts, c.err = c.inner.Containers(ctx) })
	return c.cts, c.err
}
