# Dockerfile for cylonix-manager test deploy.
#
# This is intentionally simpler than docker/Dockerfile.alpine — it expects the
# cylonix-manager and cylonix-tailscale binaries/sources to be available via
# build contexts, so we don't have to push tailscale to a registry while the
# v0.28 merge is still being verified.
#
# Build via the wrapper at deploy/compose/build.sh.

# Use BUILDPLATFORM so the Go build runs natively on the host arch (e.g.
# darwin/arm64 → linux/arm64 builder), and cross-compile to TARGETARCH via
# GOARCH below. This avoids qemu emulation when targeting a different arch
# (e.g. building linux/amd64 from a Mac).
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder

ARG VERSION_LONG=""
ARG VERSION_SHORT=""
ARG VERSION_GIT_HASH=""
ARG TARGETARCH

# Layer 1: copy the cylonix-tailscale source (referenced via go.mod replace).
WORKDIR /go/src/cylonix-tailscale
COPY --from=tailscale-src . .

# Layer 2: copy cylonix-manager source.
WORKDIR /go/src/cylonix-manager
COPY . .

# Rewrite the go.mod replace directive to the in-container path.
RUN sed -i 's|tailscale.com => /Volumes/2TB-1/src/cylonix/tailscale|tailscale.com => /go/src/cylonix-tailscale|' go.mod

ENV GOCACHE=/tmp/go-cache
ENV CGO_ENABLED=0

RUN go mod download && \
    mkdir -p /out && \
    GOOS=linux GOARCH=$TARGETARCH go build -ldflags="\
        -X cylonix.io/version.longStamp=$VERSION_LONG \
        -X cylonix.io/version.shortStamp=$VERSION_SHORT \
        -X cylonix.io/version.gitCommitStamp=$VERSION_GIT_HASH" \
        -o /out/manager ./manager && \
    GOOS=linux GOARCH=$TARGETARCH go build -ldflags="\
        -X cylonix.io/version.longStamp=$VERSION_LONG \
        -X cylonix.io/version.shortStamp=$VERSION_SHORT \
        -X cylonix.io/version.gitCommitStamp=$VERSION_GIT_HASH" \
        -o /out/task ./cmd/task && \
    rm -rf /tmp/go-cache

# ---------------------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates gettext bash postgresql-client

COPY --from=builder /out/manager /usr/local/bin/manager
COPY --from=builder /out/task    /usr/local/bin/task

COPY docker/entrypoint.sh /opt/entrypoint.sh
COPY docker/defaults.sh   /opt/defaults.sh
COPY docker/templates     /opt/templates

ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["manager", "--log-level", "info"]
