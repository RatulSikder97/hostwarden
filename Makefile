BINARY  := hostwarden
PKG     := github.com/RatulSikder97/hostwarden
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/cli.Version=$(VERSION)
IMAGE   := hostwarden-misconfigured:demo

.PHONY: all build build-linux test race lint integration demo-sarif sample checks-md snapshot clean

all: lint race build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/hostwarden

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 ./cmd/hostwarden
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-arm64 ./cmd/hostwarden

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

integration:
	go test -tags integration -count=1 -v -timeout 20m ./test/...

# Scan the deliberately misconfigured container and write SARIF for code scanning.
demo-sarif:
	docker build -t $(IMAGE) -f test/Dockerfile .
	docker rm -f hostwarden-demo >/dev/null 2>&1 || true
	docker run -d --name hostwarden-demo $(IMAGE) >/dev/null
	until docker exec hostwarden-demo test -e /run/hostwarden-ready; do sleep 1; done
	docker exec hostwarden-demo /opt/hostwarden/hostwarden scan --format sarif > hostwarden.sarif
	docker exec hostwarden-demo /opt/hostwarden/hostwarden scan --color never | tee hostwarden-demo.txt
	docker rm -f hostwarden-demo >/dev/null

checks-md:
	go run ./cmd/hostwarden checks --format markdown

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist hostwarden.sarif hostwarden-demo.txt
