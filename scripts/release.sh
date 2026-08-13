#!/usr/bin/env bash
#
# scripts/release.sh — cut a versioned, checksummed, signed release.
#
# Agents are installed from these artifacts, on customer hosts, with root and
# CAP_BPF. A tampered agent binary is the worst compromise this platform has, so
# a release is not "build and upload" — it is: refuse to build dirty, refuse to
# build untested, checksum everything, and sign it if signing is available.
#
#   ./scripts/release.sh --version v0.4.0
#   ./scripts/release.sh --version v0.4.0 --publish     # + GitHub release
#
# Produces dist/<version>/:
#   agent-linux-amd64  controlplane-linux-amd64  engine-linux-amd64
#   SHA256SUMS  (+ SHA256SUMS.sig / .pem when cosign is present)
#   ebpf-soc-<version>-amd64.tar.gz   binaries + policies + install scripts

LOG_TAG="release"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

VERSION=""; PUBLISH=0; SKIP_TESTS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="${2:?}"; shift 2 ;;
    --publish)    PUBLISH=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

[[ -n "$VERSION" ]] || die "--version vX.Y.Z is required"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$ ]] || die "version must look like v0.4.0"

need_cmd go; need_cmd git

# ── Gate 1: the tree must be clean ─────────────────────────────────────────
# A release built from uncommitted changes cannot be reproduced from the tag,
# which makes the signature meaningless — it attests to a state nobody can check.
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  err "the working tree is dirty — a release must be reproducible from its tag"
  git -C "$REPO_ROOT" status --short | sed 's/^/    /'
  exit 1
fi
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
ok "clean tree at $COMMIT"

# ── Gate 2: tests ──────────────────────────────────────────────────────────
if (( SKIP_TESTS )); then
  warn "--skip-tests: shipping an agent that runs as root on customer hosts, untested"
else
  step_header "Tests"
  (cd "$REPO_ROOT/engine" && go vet ./... && go test ./...) || die "tests failed — not releasing"
  ok "Go suite passes"
fi

# ── Build ──────────────────────────────────────────────────────────────────
step_header "Build"
DIST="$REPO_ROOT/dist/$VERSION"
rm -rf "$DIST"; mkdir -p "$DIST"

# -trimpath and a pinned ldflags line keep the build reproducible: the same
# commit must produce the same bytes, or the checksum below proves nothing.
LDFLAGS="-s -w -X main.version=$VERSION -X main.commit=$COMMIT"
for cmd in engine agent controlplane; do
  log "building $cmd"
  (cd "$REPO_ROOT/engine" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="$LDFLAGS" -o "$DIST/$cmd-linux-amd64" "./cmd/$cmd") \
    || die "$cmd failed to build"
  file "$DIST/$cmd-linux-amd64" | grep -q 'statically linked' \
    || die "$cmd is not statically linked — the agent must have no runtime deps"
done
ok "three static linux/amd64 binaries"

# ── Bundle ─────────────────────────────────────────────────────────────────
step_header "Bundle"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
BUNDLE="ebpf-soc-$VERSION-amd64"
mkdir -p "$STAGE/$BUNDLE"
cp "$DIST"/*-linux-amd64 "$STAGE/$BUNDLE/"
cp -R "$REPO_ROOT/policies" "$REPO_ROOT/attacks" "$STAGE/$BUNDLE/"
mkdir -p "$STAGE/$BUNDLE/scripts"
cp "$SCRIPTS_DIR/install-agent.sh" "$SCRIPTS_DIR/preflight.sh" "$STAGE/$BUNDLE/scripts/"
cp -R "$SCRIPTS_DIR/lib" "$STAGE/$BUNDLE/scripts/"
printf '%s\n%s\n' "$VERSION" "$COMMIT" >"$STAGE/$BUNDLE/VERSION"
tar -czf "$DIST/$BUNDLE.tar.gz" -C "$STAGE" "$BUNDLE"
ok "$BUNDLE.tar.gz"

# ── Checksums ──────────────────────────────────────────────────────────────
step_header "Checksums"
(cd "$DIST" && if have_cmd sha256sum; then sha256sum ./*; else shasum -a 256 ./*; fi | sed 's|\./||' >SHA256SUMS)
ok "SHA256SUMS"
sed 's/^/    /' "$DIST/SHA256SUMS"

# ── Signing ────────────────────────────────────────────────────────────────
step_header "Signing"
if have_cmd cosign; then
  # Keyless: the identity comes from an OIDC token and the signature lands in
  # the Rekor transparency log, so anyone can verify who built this and when —
  # without us holding a private key that could be stolen.
  COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
    --output-signature "$DIST/SHA256SUMS.sig" \
    --output-certificate "$DIST/SHA256SUMS.pem" \
    "$DIST/SHA256SUMS" \
    && ok "SHA256SUMS signed (keyless, logged to Rekor)" \
    || warn "cosign signing failed — the artifacts are UNSIGNED"
else
  warn "cosign not installed — the artifacts are UNSIGNED"
  dim "customers install the agent as root; ship signatures: brew install cosign"
fi

# ── Publish ────────────────────────────────────────────────────────────────
if (( PUBLISH )); then
  step_header "Publish"
  need_cmd gh
  confirm "Tag $VERSION and publish a GitHub release?" n || { log "aborted (artifacts remain in $DIST)"; exit 0; }
  git -C "$REPO_ROOT" tag -a "$VERSION" -m "Release $VERSION"
  git -C "$REPO_ROOT" push origin "$VERSION"
  gh release create "$VERSION" "$DIST"/* \
    --title "$VERSION" \
    --notes "Static linux/amd64 agent, control plane, and engine. Verify with SHA256SUMS before installing."
  ok "published $VERSION"
fi

printf '\n%s══ %s ══%s\n\n' "$C_BOLD" "$VERSION" "$C_RESET"
printf '  artifacts   %s\n' "$DIST"
printf '  commit      %s\n' "$COMMIT"
printf '  verify      cd %s && sha256sum -c SHA256SUMS\n\n' "$DIST"
