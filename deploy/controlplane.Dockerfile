# syntax=docker/dockerfile:1
#
# Control-plane container image (Phase 0).
#
# Only the CONTROL PLANE is containerised. The agent is deliberately NOT: it
# ships as a single static, dependency-free host binary (architecture.md §6,
# "single-binary agent ergonomics") installed via .deb/.rpm next to Tetragon.
# The container tier is where the heavier, horizontally-scaled services live.
#
# Build context is the REPO ROOT (the build stage needs engine/). Build with:
#   docker build -f deploy/controlplane.Dockerfile -t controlplane .

# ---- build stage ----------------------------------------------------------
# 1.26.6 is the patched toolchain: govulncheck reports 7 stdlib advisories
# against 1.26.5 and earlier (net/url, html/template, crypto/tls, net/http,
# encoding/xml, encoding/asn1). This image is what actually ships, so building
# it with an unpatched compiler puts those CVEs in the signed artifact
# regardless of what CI runs.
FROM golang:1.27.1-bookworm AS build
WORKDIR /src

# Module cache layer: copy just the manifests first so `go mod download` is
# only re-run when dependencies change.
COPY engine/go.mod engine/go.sum ./
RUN go mod download

# Source. internal/api embeds internal/api/web via `//go:embed all:web`; the
# committed .keep keeps that directory present so the control-plane build
# compiles without staged Vite assets (the control plane serves no console).
COPY engine/ ./

# Static, stripped, reproducible-ish build. CGO_ENABLED=0 keeps it a single
# static binary (modernc.org/sqlite is pure-Go, so no libc needed).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
      -o /out/controlplane ./cmd/controlplane

# ---- runtime stage --------------------------------------------------------
# Distroless static + nonroot: no shell, no package manager, minimal CVE
# surface — appropriate for a security product's own control plane.
FROM gcr.io/distroless/static-debian12:nonroot
# Writable home so the sqlite state file (Phase 0 stub store) can be created
# when no external DSN is supplied; Phase 1 mounts Postgres/ClickHouse instead.
WORKDIR /home/nonroot
COPY --from=build /out/controlplane /usr/local/bin/controlplane
EXPOSE 9090
USER nonroot:nonroot
# No default credential is baked in (Phase 0, deliverable #3): run with
# -pass / -pass-hash, or the process fails fast at startup.
ENTRYPOINT ["/usr/local/bin/controlplane"]
