#!/usr/bin/env bash
#
# scripts/release-git.sh — walk a release through git, one confirmed step at a
# time: gate → commit → push → merge → tag → verify.
#
# Every step shows you what it is about to do and waits. Nothing is pushed,
# merged, tagged or force-anything'd without an explicit yes.
#
# It exists because the ordering here is easy to get wrong in ways that are
# painful afterwards, and this repo has hit two of them:
#
#   * TAG AFTER THE MERGE, on main. Tagging the branch and then squash-merging
#     leaves the tag pointing at a commit that is not in main's history — an
#     orphaned tag, and /api/version then names a release nobody can find.
#
#   * DO NOT push the tag alongside the branch. .github/workflows/release.yml
#     fires on a v*.*.* tag and cuts a SIGNED, published artefact. Pushing both
#     together releases code before CI has judged it.
#
# It also refuses to tag a dirty tree, because a box running a dirty build is
# running code that exists nowhere else — every host reported `-dirty` for
# months before this was noticed.
#
# TWO MODES, because most pushes are not releases:
#
#   push     gate → branch → commit → push. Stops there. Use this for review,
#            for CI, for work in progress — anything not being shipped. No tag
#            is created, so nothing is built, signed, published or deployable.
#
#   release  the above, plus merge to main → tag → verify. A tag in this repo
#            MEANS "deployable": it fires release.yml, which publishes a signed
#            artefact, and deploy.yml will only install a released tag. Tag when
#            you intend to ship, not merely when you finish something.
#
#   ./scripts/release-git.sh                 # asks which
#   ./scripts/release-git.sh --push-only     # push for review/CI, no tag
#   ./scripts/release-git.sh --release --version v1.3.0
#   ./scripts/release-git.sh --skip-gates    # when CI has already passed
LOG_TAG="release-git"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

VERSION=""; SKIP_GATES=0; MODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="${2:?}"; MODE="release"; shift 2 ;;
    --push-only)  MODE="push"; shift ;;
    --release)    MODE="release"; shift ;;
    --skip-gates) SKIP_GATES=1; shift ;;
    -h|--help)    sed -n '3,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

cd "$REPO_ROOT"
have_cmd git || die "git not found"

# ── 0. where are we ──────────────────────────────────────────────────────────
step_header "0. current state"
BRANCH="$(git branch --show-current)"
CHANGED="$(git status --porcelain | wc -l | tr -d ' ')"
log "branch:     $BRANCH"
log "HEAD:       $(git log --oneline -1)"
log "describe:   $(git describe --tags --dirty --always 2>/dev/null || echo '(no tags)')"
log "uncommitted: $CHANGED path(s)"

if [[ "$CHANGED" == "0" ]]; then
  warn "nothing to commit — this script is for cutting a release from changes"
  confirm "continue anyway (e.g. only to tag an existing commit)?" n || exit 0
fi

# ── 1. mode + version ────────────────────────────────────────────────────────
step_header "1. what is this push?"
if [[ -z "$MODE" ]]; then
  log "push     — for review or CI. No tag, nothing published, not deployable."
  log "release  — merge to main, tag, publish a signed artefact. Deployable."
  read -r -p "$(printf '%s?%s mode [push/release]: ' "$C_YEL" "$C_RESET")" MODE </dev/tty
fi
case "$MODE" in
  push|p)    MODE="push" ;;
  release|r) MODE="release" ;;
  *) die "mode must be 'push' or 'release'" ;;
esac
ok "mode: $MODE"

if [[ "$MODE" == "release" ]]; then
  LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo 'none')"
  log "most recent tag: $LAST_TAG"
  if [[ -z "$VERSION" ]]; then
    read -r -p "$(printf '%s?%s new version (vX.Y.Z): ' "$C_YEL" "$C_RESET")" VERSION </dev/tty
  fi
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$ ]] || die "version must look like v1.3.0"
  git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null \
    && die "$VERSION already exists locally — pick another, or delete it deliberately"
  ok "cutting $VERSION"
else
  # A push-mode branch still needs a name. Default to the current branch, or
  # ask for a topic name if we are sitting on main.
  if [[ "$BRANCH" == "main" ]]; then
    read -r -p "$(printf '%s?%s branch name (e.g. fix/preset-applier): ' "$C_YEL" "$C_RESET")" TOPIC </dev/tty
    [[ -n "$TOPIC" ]] || die "a branch name is required — do not commit straight to main"
    VERSION="$TOPIC"
  else
    VERSION="$BRANCH"
  fi
fi

# ── 2. gates ─────────────────────────────────────────────────────────────────
# Run BEFORE committing. Finding a failure after the tag is pushed means either
# a force-push or a throwaway version number.
if (( SKIP_GATES )); then
  warn "skipping gates (--skip-gates)"
else
  step_header "2. gates"
  log "these are what CI runs; a failure here is a failure there"

  ( cd engine && gofmt -l . | grep -v gen/ | grep -q . ) \
    && die "gofmt: files need formatting (cd engine && gofmt -w .)"
  ok "gofmt"

  ( cd engine && go vet ./... ) || die "go vet failed"
  ok "go vet"

  # Linux specifically: ~10 files are behind //go:build linux and neither the
  # compiler nor the linter looks at them on darwin. A change can pass every
  # other gate and still not compile for the target that ships.
  ( cd engine && CGO_ENABLED=0 GOOS=linux go build ./... ) || die "linux build failed"
  ok "linux/amd64 build"

  if have_cmd golangci-lint; then
    ( cd engine && GOOS=linux golangci-lint run ./... ) || die "golangci-lint failed"
    ok "golangci-lint (GOOS=linux, as CI runs it)"
  else
    warn "golangci-lint not installed — CI will still run it"
  fi

  ( cd engine && go test ./... >/dev/null ) || die "go tests failed"
  ok "go test"

  ./scripts/ci/gen-openapi.py --check  >/dev/null || die "openapi.yaml is stale — run ./scripts/ci/gen-openapi.py"
  ./scripts/ci/gen-protodoc.py --check >/dev/null || die "wire-contract.md is stale — run ./scripts/ci/gen-protodoc.py"
  ok "generated API docs match the source"

  if [[ -d web/node_modules ]]; then
    ( cd web && npm run lint >/dev/null 2>&1 ) || die "web lint failed"
    ( cd web && npm run typecheck >/dev/null 2>&1 ) || die "web typecheck failed"
    ( cd web && npm test >/dev/null 2>&1 ) || die "web tests failed"
    ok "web lint · typecheck · test"
  else
    warn "web/node_modules missing — skipping the web suite (CI will run it)"
  fi
fi

# ── 3. branch ────────────────────────────────────────────────────────────────
step_header "3. release branch"
if [[ "$MODE" == "release" ]]; then REL_BRANCH="release/$VERSION"; else REL_BRANCH="$VERSION"; fi
if [[ "$BRANCH" == "$REL_BRANCH" ]]; then
  ok "already on $REL_BRANCH"
elif git rev-parse -q --verify "$REL_BRANCH" >/dev/null; then
  confirm "switch to the existing $REL_BRANCH?" y && git checkout "$REL_BRANCH"
else
  confirm "create branch $REL_BRANCH from $BRANCH?" y || die "aborted"
  git checkout -b "$REL_BRANCH"
  ok "on $REL_BRANCH"
fi

# ── 4. commit ────────────────────────────────────────────────────────────────
if [[ "$(git status --porcelain | wc -l | tr -d ' ')" != "0" ]]; then
  step_header "4. commit"
  git status --short | sed 's/^/  /'
  printf '\n'
  confirm "stage ALL of the above?" y || die "aborted — stage what you want and re-run"
  git add -A

  # Secret sweep on what is actually staged. gitleaks in CI scans history and
  # will catch more; this catches the obvious thing before it becomes history.
  if git diff --cached | grep -qiE 'BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN OPENSSH'; then
    die "a private key appears in the staged diff — unstage it"
  fi

  MSG_FILE="$(mktemp)"
  {
    if [[ "$MODE" == "release" ]]; then echo "release($VERSION): "; else echo ""; fi
    echo
    echo "# Lines starting with # are ignored."
    echo "# First line: short summary. Then a blank line, then the detail."
    echo "# Say WHAT changed and WHY it mattered — this is what a reviewer and"
    echo "# a future incident responder will read."
    echo "#"
    echo "# Changed files:"
    git diff --cached --name-status | sed 's/^/#   /'
  } >"$MSG_FILE"

  log "opening \$EDITOR for the commit message"
  "${EDITOR:-vi}" "$MSG_FILE" </dev/tty >/dev/tty 2>&1 || true
  # awk, not sed: `sed '/^\s*$/{ /./!d }'` is GNU-only and BSD sed (macOS)
  # rejects it with "extra characters at the end of d command". \s is a GNU
  # extension too. This drops comment lines and trims leading/trailing blanks
  # using POSIX classes only, so it behaves the same on a Mac and in CI.
  awk '
    /^[[:space:]]*#/ { next }
    { line[n++] = $0 }
    END {
      s = 0;     while (s < n   && line[s] ~ /^[[:space:]]*$/) s++
      e = n - 1; while (e >= s  && line[e] ~ /^[[:space:]]*$/) e--
      for (i = s; i <= e; i++) print line[i]
    }
  ' "$MSG_FILE" >"${MSG_FILE}.clean"
  [[ -s "${MSG_FILE}.clean" ]] || die "empty commit message — aborted"

  printf '\n%s─── message ───%s\n' "$C_DIM" "$C_RESET"
  sed 's/^/  /' "${MSG_FILE}.clean"
  printf '\n'
  confirm "commit with this message?" y || die "aborted"

  # The trailer is appended to the message FILE. `git commit -F x -m y` is
  # rejected outright ("options '-m' and '-F' cannot be used together"), and a
  # trailer needs a blank line before it to be parsed as one anyway.
  TRAILER="Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
  grep -qF "$TRAILER" "${MSG_FILE}.clean" || printf '\n%s\n' "$TRAILER" >>"${MSG_FILE}.clean"
  git commit -F "${MSG_FILE}.clean"
  rm -f "$MSG_FILE" "${MSG_FILE}.clean"
  ok "committed $(git log --oneline -1)"
fi

# ── 5. push the branch (NOT the tag) ─────────────────────────────────────────
step_header "5. push the branch"
log "the tag is pushed LAST, after the merge — see the header for why"
confirm "push $REL_BRANCH to origin?" y || die "aborted"
git push -u origin "$REL_BRANCH"
ok "pushed — CI runs on main, feat/** and release/** branches"

if [[ "$MODE" == "push" ]]; then
  printf '\n'
  ok "done — pushed for review, no tag created"
  log "nothing has been released or deployed. When this is ready to ship, run:"
  printf '  ./scripts/release-git.sh --release --version vX.Y.Z\n'
  exit 0
fi

log "open a PR against main and let it go green before continuing"
confirm "has CI passed (or are you merging without it)?" n || {
  log "re-run this script when CI is green; it will resume from here"
  exit 0
}

# ── 6. merge to main ─────────────────────────────────────────────────────────
step_header "6. merge to main"
confirm "merge $REL_BRANCH into main now?" y || {
  warn "merge it yourself (or via the PR), then re-run to tag"
  exit 0
}
git checkout main
git pull --ff-only origin main || die "main has diverged — reconcile before merging"
git merge --no-ff "$REL_BRANCH" -m "merge: $VERSION"
confirm "push main?" y || die "aborted — main is merged locally but not pushed"
git push origin main
ok "main updated"

# ── 7. tag ───────────────────────────────────────────────────────────────────
step_header "7. tag"
DIRTY="$(git status --porcelain | wc -l | tr -d ' ')"
[[ "$DIRTY" == "0" ]] || {
  git status --short | sed 's/^/  /'
  die "working tree is dirty — a tag must name a reproducible tree"
}
read -r -p "$(printf '%s?%s tag annotation [%s]: ' "$C_YEL" "$C_RESET" "$VERSION")" ANNOT </dev/tty
git tag -a "$VERSION" -m "${ANNOT:-$VERSION}"
ok "tagged $VERSION at $(git rev-parse --short HEAD) on main"

warn "pushing this tag fires .github/workflows/release.yml, which builds,"
warn "signs and PUBLISHES a release."
confirm "push tag $VERSION?" y || {
  warn "tag exists locally only — push it with: git push origin $VERSION"
  exit 0
}
git push origin "$VERSION"
ok "pushed"

# ── 8. verify ────────────────────────────────────────────────────────────────
step_header "8. verify"
DESC="$(git describe --tags --dirty)"
log "describe: $DESC"
[[ "$DESC" == "$VERSION" ]] || die "describe is '$DESC', expected a bare '$VERSION' — do NOT deploy this"
ok "clean tag, no -dirty suffix"

git merge-base --is-ancestor "$VERSION" main \
  && ok "tag is in main's history (not orphaned)" \
  || die "tag is NOT an ancestor of main — it would name a commit nobody can find"

# Query the DEREFERENCED ref explicitly. `ls-remote --tags origin <pattern>`
# returns only the tag-object sha — the ^{} line appears only when no pattern
# is given — so filtering for ^{} after passing a pattern always yields empty
# and this check warned on every correct push. An annotated tag's object sha is
# not its commit sha, which is the same distinction that made a correctly
# pushed tag look mismatched by hand.
REMOTE="$(git ls-remote origin "refs/tags/${VERSION}^{}" | awk '{print $1}')"
[[ -n "$REMOTE" ]] || REMOTE="$(git ls-remote origin "refs/tags/${VERSION}" | awk '{print $1}')"
LOCAL="$(git rev-list -n1 "$VERSION")"
[[ "$REMOTE" == "$LOCAL" ]] && ok "origin agrees: $LOCAL" || warn "origin tag differs ($REMOTE) — check before deploying"

printf '\n'
ok "$VERSION is ready to deploy"
log "deploy with the DNS names and TLS, never an IP:"
printf '  TLS=1 DATA_MODE=none TARGET_HOST=console.adanianlabs.io SSH_HOST=control-plane ./scripts/deploy/multi-tenant-ubuntu.sh\n'
printf '  TLS=1 TARGET_HOST=engine.adanianlabs.io SSH_HOST=single_tenant_engine ./scripts/deploy/single-tenant-ubuntu.sh\n'
printf '  make deploy-agent TENANT=<t> AGENT_HOST=<h> CP_SSH=control-plane CP_IP=172.31.45.193\n'
printf '  ./scripts/ci/verify-deploy.sh\n'
