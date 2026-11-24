# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/RatulSikder97/hostwarden/internal/cli.Version=${VERSION}" \
      -o /out/hostwarden ./cmd/hostwarden

# Runs as root on purpose: auditing /etc/shadow, /proc/*/exe and the Docker
# socket of the host requires it. The host filesystem is mounted read-only.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/hostwarden /hostwarden
ENTRYPOINT ["/hostwarden"]
CMD ["scan", "--root", "/host", "--proc", "/proc"]
