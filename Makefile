# eBPF Threat Observability PoC — top-level Makefile
#
# Targets:
#   make build           native build of the engine binary -> engine/engine
#   make build-linux     cross-compile linux/amd64 (or arm64) -> engine/engine-linux-<arch>
#   make build-agent     native build of the choke-agent -> engine/agent
#   make build-controlplane  native build of the control-plane stub -> engine/controlplane
#   make proto-lint      validate the agent<->control-plane protobuf IDL (protoc only)
#   make proto           regenerate gRPC Go stubs into engine/gen (needs `make proto-tools` once)
#   make test            run all Go unit tests
#   make vet             go vet
#   make fake            run the engine in fake mode on :8080 (no Tetragon needed)
#   make deploy-console  multi-tenant control plane onto an Ubuntu server (SSH)
#   make deploy-engine   single-tenant engine + Tetragon onto an Ubuntu server
#   make deploy-agent    one real per-tenant agent onto its own Ubuntu host
#   make e2e             live end-to-end suite against a deployed rig
#   make policies-apply  copy + apply all TracingPolicies into a running tetragon container
#   make policies-list   list active policies in the tetragon container
#   make tarball         bundle policies/, attacks/, the linux binary, and README into a tar.gz
#   make clean           remove build artifacts

ROOT       := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ENGINE_DIR := $(ROOT)/engine
WEB_DIR    := $(ROOT)/web
EMBED_DIR  := $(ENGINE_DIR)/internal/api/web
BIN        := $(ENGINE_DIR)/engine
# Phase 0 build-target split (docs/plan/architecture.md §1). The agent and
# control-plane binaries compile over the SAME internal/ packages as the
# engine — new entrypoints only, no packages moved. See cmd/agent, cmd/controlplane.
AGENT_BIN  := $(ENGINE_DIR)/agent
CP_BIN     := $(ENGINE_DIR)/controlplane
LINUX_ARCH ?= amd64
LINUX_BIN  := $(ENGINE_DIR)/engine-linux-$(LINUX_ARCH)
AGENT_LINUX_BIN := $(ENGINE_DIR)/agent-linux-$(LINUX_ARCH)
CP_LINUX_BIN    := $(ENGINE_DIR)/controlplane-linux-$(LINUX_ARCH)
# Phase 1 wire contract (docs/plan/wire-contract.md). The agent↔control-plane
# protobuf/gRPC IDL and the generated Go stubs.
PROTO_DIR  := $(ENGINE_DIR)/proto
GEN_DIR    := $(ENGINE_DIR)/gen
# Pin protoc-gen-go to the module's protobuf version so generated code matches
# the runtime library (engine/go.mod: google.golang.org/protobuf v1.36.11).
PROTOC_GEN_GO_VERSION      ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.5.1
TETRA_CT   ?= tetragon
# Throwaway credential for the local `make fake` dev/UI target only. The engine
# no longer ships a built-in password default (Phase 0, deliverable #3), so dev
# tooling must pass one explicitly. Override with FAKE_PASS=… if you like; this
# is never used for a real deployment (see `make deploy`, which sets its own).
FAKE_PASS  ?= fake-dev

# Console credential for the deploy targets. Deliberately has NO default.
#
# These targets used to launch the engine with `-pass ebpf-soc-demo` and then
# echo that credential back to the operator. `deploy-remote` is the documented
# generic-SSH path for EC2, Azure and bare metal, so following the docs stood up
# an internet-reachable console on a password published in this repository. The
# default was removed from the binary in Phase 0 and left in the deploy path,
# which is the half that reaches production hosts.
ENGINE_USER ?= admin
ENGINE_PASS ?=

.PHONY: deploy-console deploy-engine deploy-agent e2e _require_ssh_host _require_engine_pass
.PHONY: web build build-linux build-agent build-agent-linux build-controlplane build-controlplane-linux proto proto-tools proto-lint test vet fake policies-apply policies-list tarball clean deploy redeploy deploy-remote redeploy-remote vm-logs vm-attack vm-status vm-up vm-doctor install install-vm tls-vm pg-vm devchoke netns-smoke

# Build and stage Vite's static output for go:embed. The redesigned UI is
# the release path; missing dist/ is a build failure, not a runtime fallback.
web:
	@test -f "$(WEB_DIR)/package.json" || { echo "web/package.json not found"; exit 1; }
	cd $(WEB_DIR) && npm run build
	@mkdir -p $(EMBED_DIR)
	@find $(EMBED_DIR) -mindepth 1 ! -name .keep -exec rm -rf {} +
	@test -f "$(WEB_DIR)/dist/index.html" || { echo "web/dist/index.html not found after npm run build"; exit 1; }
	@echo "→ staging Vite dist into $(EMBED_DIR)"
	@cp -R "$(WEB_DIR)/dist/." "$(EMBED_DIR)/"

# ─────────────────────────────────────────────────────────────────────────
# Release identity.
#
# A revision answers "which commit"; a customer asks "which VERSION", and only a
# tag answers that. `git describe` gives both: "v1.0.0" on a tag,
# "v1.0.0-3-gabc1234" off it, and a "-dirty" suffix when the tree is uncommitted.
#
# Go stamps vcs.revision/vcs.modified into the binary automatically, so the SHA
# and dirty flag work with no help. This adds the human-facing release name.
VERSION    ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo "")
LDFLAGS    := -X github.com/jeffmk/ebpf-poc-engine/internal/buildinfo.version=$(VERSION)
GOBUILD    := go build -ldflags "$(LDFLAGS)"

# Refuse to produce a RELEASE artefact from an uncommitted tree.
#
# A box running a dirty build is running code that exists nowhere else: it
# cannot be reproduced, diffed, or patched, and /api/version says so with a
# "-dirty" suffix that nobody reads until an incident. Ordinary `make
# build-linux` still works — this gate is opt-in via `make release`, so
# day-to-day iteration is unaffected while a handover build cannot be dirty.
.PHONY: require-clean
require-clean:
	@case "$(VERSION)" in \
	  "")        echo "release: no git tag reachable — tag first (git tag -a v1.0.0 -m ...)"; exit 1;; \
	  *-dirty)   echo "release: work tree is dirty ($(VERSION)) — commit or stash before cutting a release"; exit 1;; \
	  *)         echo "release: building $(VERSION)";; \
	esac

# ─────────────────────────────────────────────────────────────────────────
# API documentation.
#
#   make api-docs        render docs/api/dist/index.html (one self-contained file)
#   make api-docs-check  fail if the generated docs no longer match the source
#
# The spec and the wire contract are DERIVED from the code, so they cannot drift;
# CI runs the same --check gates. Open the rendered file directly — it needs no
# server and makes no network requests.
.PHONY: api-docs api-docs-check
api-docs:
	@./scripts/ci/gen-openapi.py
	@./scripts/ci/gen-protodoc.py
	@./scripts/ci/build-api-docs.sh

api-docs-check:
	@./scripts/ci/gen-openapi.py --check
	@./scripts/ci/gen-protodoc.py --check

# Install a PUBLISHED, SIGNED release onto the estate — the local counterpart of
# .github/workflows/deploy.yml, for operators who would rather not hold an SSH
# key in GitHub. Same guarantee either way: the signature over SHA256SUMS is
# verified against the release workflow's identity BEFORE anything is installed,
# so what lands on a host is what CI built rather than what this laptop compiled.
#
#   make deploy-release VERSION=v1.1.0 SSH_HOST=control-plane
.PHONY: verify-release deploy-release
verify-release:
	@[ -n "$(VER)" ] || { echo "VER=vX.Y.Z required"; exit 1; }
	@command -v cosign >/dev/null || { echo "cosign required: brew install cosign"; exit 1; }
	@command -v gh     >/dev/null || { echo "gh required: brew install gh"; exit 1; }
	@set -e; rm -rf $(ROOT)/dist/$(VER); mkdir -p $(ROOT)/dist/$(VER); \
	cd $(ROOT)/dist/$(VER) && gh release download "$(VER)"; \
	echo "→ verifying release signature"; \
	cosign verify-blob \
	  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
	  --certificate-identity-regexp '^https://github.com/.*/\.github/workflows/release\.yml@' \
	  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	  SHA256SUMS; \
	shasum -a 256 -c SHA256SUMS; \
	echo "  ✓ $(VER) is signed by the release workflow and intact"

# Every artefact a handover ships, from one tag, with hashes to match.
.PHONY: release
release: require-clean build-linux build-agent-linux build-controlplane-linux
	@echo
	@echo "release $(VERSION) — artefact digests:"
	@cd $(ENGINE_DIR) && shasum -a 256 engine-linux-$(LINUX_ARCH) agent-linux-$(LINUX_ARCH) controlplane-linux-$(LINUX_ARCH) | sed 's/^/  /'
	@# LC_ALL=C: the default collation differs between macOS and Linux (it orders
	@# "favicon-light.svg" against "favicon.svg" differently), which changes the
	@# order of lines fed into the rollup and therefore the digest. A digest the
	@# recipient cannot reproduce on their own machine verifies nothing.
	@cd $(WEB_DIR)/dist && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | sed 's/^/  console bundle: /'

build: web
	cd $(ENGINE_DIR) && $(GOBUILD) -o engine ./cmd/engine

build-linux: web
	cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 $(GOBUILD) -o engine-linux-$(LINUX_ARCH) ./cmd/engine
	@echo "→ $(LINUX_BIN)"

# ─────────────────────────────────────────────────────────────────────────
# Phase 0 build-target split (docs/plan/architecture.md §1).
# cmd/agent and cmd/controlplane are NEW entrypoints over the SAME internal/
# packages — the strangler seam for the eventual agent / control-plane split.
# cmd/engine stays built and unchanged; nothing is moved.
# ─────────────────────────────────────────────────────────────────────────

# The per-host sensing+enforcing agent (native; depends on web for the local
# debug-console assets, same as `build`).
build-agent: web
	cd $(ENGINE_DIR) && go build -o agent ./cmd/agent
	@echo "→ $(AGENT_BIN)"

# Static linux agent — the shipping form. CGO_ENABLED=0 keeps it a single
# dependency-free binary (the agent-ergonomics invariant, architecture.md §6).
build-agent-linux: web
	cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 $(GOBUILD) -o agent-linux-$(LINUX_ARCH) ./cmd/agent
	@echo "→ $(AGENT_LINUX_BIN)"

# The control-plane stub (native). Minimal HTTP over internal/api + internal/store;
# no embedded console, so no web dependency.
build-controlplane:
	cd $(ENGINE_DIR) && go build -o controlplane ./cmd/controlplane
	@echo "→ $(CP_BIN)"

# Static linux control plane — it runs in a container/K8s (architecture.md §3).
build-controlplane-linux:
	cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 $(GOBUILD) -o controlplane-linux-$(LINUX_ARCH) ./cmd/controlplane
	@echo "→ $(CP_LINUX_BIN)"

# ─────────────────────────────────────────────────────────────────────────
# Phase 1 wire contract (docs/plan/wire-contract.md).
# `proto-lint` validates the IDL with protoc alone (no language plugins) — safe
# to run in CI. `proto` regenerates the Go stubs under engine/gen (needs the
# plugins; `proto-tools` installs them, pinned to the module's protobuf version).
# ─────────────────────────────────────────────────────────────────────────
proto-tools:
	cd $(ENGINE_DIR) && go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	cd $(ENGINE_DIR) && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	@echo "→ installed protoc-gen-go $(PROTOC_GEN_GO_VERSION) + protoc-gen-go-grpc $(PROTOC_GEN_GO_GRPC_VERSION) (ensure $$(go env GOPATH)/bin is on PATH)"

# Syntax/import validation only — no plugins required, so this is the CI gate.
proto-lint:
	protoc -I $(PROTO_DIR) --descriptor_set_out=/dev/null $(PROTO_DIR)/ebpfsoc/v1/*.proto
	@echo "→ proto IDL valid"

proto: proto-lint
	@mkdir -p $(GEN_DIR)
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=module=github.com/jeffmk/ebpf-poc-engine/gen \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=module=github.com/jeffmk/ebpf-poc-engine/gen \
		$(PROTO_DIR)/ebpfsoc/v1/*.proto
	@echo "→ generated Go stubs under $(GEN_DIR)"

# Compile the network (per-device) choke data plane locally. Linux only —
# needs clang + the kernel uapi headers. The deploy path builds this on the
# target box via setup.sh; this target is for the netns lab / local testing.
DEVBPF_DIR := $(ENGINE_DIR)/internal/enforce/devbpf/bpf
devchoke:
	cd $(DEVBPF_DIR) && clang -O2 -g -target bpf -I/usr/include/$$(uname -m)-linux-gnu -c devchoke.c -o devchoke.o
	@echo "→ $(DEVBPF_DIR)/devchoke.o"

# Stage-0 end-to-end smoke test for the network choke in a 3-netns lab.
# Linux + root only. Builds the binary + object, then asserts jail-drops and
# thaw-restores forwarded traffic for one device MAC. Exits non-zero on any
# failed assertion so it works as a CI/dev gate.
netns-smoke: build-linux devchoke
	sudo bash $(ROOT)/scripts/dev/netns-smoke.sh "$(DEVBPF_DIR)/devchoke.o" "$(LINUX_BIN)"

test:
	cd $(ENGINE_DIR) && go test ./...

vet:
	cd $(ENGINE_DIR) && go vet ./...

# fake mode is retained for unit tests + UI iteration only. Production
# never uses it — see `make deploy` for the real path.
fake: build
	$(BIN) -fake -db $(ROOT)/fake-events.db -pass $(FAKE_PASS)

# All detection policies live flat in policies/. They used to be split across
# policies/ and policies/enforce/, which caused two problems: this target globbed
# only the first and quietly applied 3 of 5, and the directory name implied an
# enforcement posture the files did not have (see threat-model EN-1d). Everything
# here is detect-only, declared per policy via `policy-mode: monitor`.
# policies/choke/ is deliberately NOT applied here — those are the engine's own
# choke-ladder policies, passed to it with -choke-policies, not Tetragon's.
#
# `tetra tracingpolicy add` is CREATE-ONLY: a policy whose content changed keeps
# running the version loaded when Tetragon started, so an edit appears to apply
# and does nothing. Delete first, keyed by metadata.name (which is NOT the
# filename: network-watch.yaml declares "outbound-connections").
policies-apply:
	@for p in $(ROOT)/policies/*.yaml; do \
		[ -f "$$p" ] || continue; \
		base=$$(basename $$p); \
		pol=$$(awk '/^metadata:/{f=1;next} f&&/^[[:space:]]+name:/{gsub(/["'"'"'[:space:]]/,"",$$2);print $$2;exit}' "$$p"); \
		[ -n "$$pol" ] || pol=$${base%.yaml}; \
		echo "→ apply $$base (policy: $$pol)"; \
		docker cp "$$p" $(TETRA_CT):/tmp/ >/dev/null; \
		docker exec $(TETRA_CT) tetra tracingpolicy delete "$$pol" >/dev/null 2>&1 || true; \
		docker exec $(TETRA_CT) tetra tracingpolicy add /tmp/$$base || true ; \
	done
	$(MAKE) policies-list

policies-list:
	docker exec $(TETRA_CT) tetra tracingpolicy list

tarball: build-linux
	tar -czf ebpf-poc-$(LINUX_ARCH).tar.gz \
		-C $(ROOT) \
		Makefile scripts policies attacks README.md docs/development/build-plan.md \
		engine/internal/enforce/bpfmap/bpf/choke.c \
		engine/internal/enforce/devbpf/bpf/devchoke.c \
		engine/engine-linux-$(LINUX_ARCH)
	@echo "→ ebpf-poc-$(LINUX_ARCH).tar.gz"

clean:
	rm -f $(BIN) $(ENGINE_DIR)/engine-linux-amd64 $(ENGINE_DIR)/engine-linux-arm64
	rm -f $(AGENT_BIN) $(ENGINE_DIR)/agent-linux-amd64 $(ENGINE_DIR)/agent-linux-arm64
	rm -f $(CP_BIN) $(ENGINE_DIR)/controlplane-linux-amd64 $(ENGINE_DIR)/controlplane-linux-arm64
	rm -f $(ROOT)/fake-events.db $(ROOT)/events.db
	rm -f $(ROOT)/ebpf-poc-amd64.tar.gz $(ROOT)/ebpf-poc-arm64.tar.gz
	find $(EMBED_DIR) -mindepth 1 ! -name .keep -exec rm -rf {} +

# ═════════════════════════════════════════════════════════════════════════
# Ubuntu server deploy — the CURRENT path.
#
# Thin wrappers over scripts/deploy/*, which is where the provisioning
# actually lives (one shared lib.sh + a driver per target). See
# docs/deployment/aws-multi-host.md for the full five-host topology and
# scripts/deploy/README.md for the knobs.
#
#   make deploy-console SSH_HOST=cp TARGET_HOST=console.example.com TLS=1
#   make deploy-engine  SSH_HOST=eng TARGET_HOST=engine.example.com TLS=1
#   make deploy-agent   TENANT=acme-corp AGENT_HOST=agent-b CP_SSH=cp CP_IP=10.0.0.5
#   make e2e
# ═════════════════════════════════════════════════════════════════════════
SSH_HOST    ?=
TARGET_HOST ?=
TLS         ?= 0
TLS_EMAIL   ?=
DATA_MODE   ?=
# Shipped to agents so their device gateway enforces in-kernel rather than
# running the noop backend. Built by `make devchoke` (needs Linux + clang).
DEVCHOKE_OBJ ?= $(ENGINE_DIR)/internal/enforce/devbpf/bpf/devchoke.o
DEPLOY_ENV = $(if $(TARGET_HOST),TARGET_HOST=$(TARGET_HOST),) $(if $(filter 1,$(TLS)),TLS=1,) \
             $(if $(TLS_EMAIL),TLS_EMAIL=$(TLS_EMAIL),) $(if $(DATA_MODE),DATA_MODE=$(DATA_MODE),)

_require_ssh_host:
	@[ -n "$(SSH_HOST)" ] || { echo "SSH_HOST=user@host (or an ssh alias) required"; exit 1; }

# No console password may be baked into a deploy path. Fail before anything is
# started rather than silently standing up a known-credential console.
_require_engine_pass:
	@[ -n "$(ENGINE_PASS)" ] || { \
	  echo "ENGINE_PASS is required — this target starts a console on :8080."; \
	  echo "  make $(MAKECMDGOALS) ENGINE_PASS=\"$$(openssl rand -base64 24)\""; \
	  echo "(there is deliberately no default: the old one was published in this repo)"; \
	  exit 1; }

# Multi-tenant control plane: Postgres + Keycloak + control plane + nginx.
# Use DATA_MODE=none when real agents are managed separately, or every redeploy
# resurrects the sim-agents alongside them.
deploy-console: _require_ssh_host
	@SSH_HOST=$(SSH_HOST) $(DEPLOY_ENV) $(ROOT)/scripts/deploy/multi-tenant-ubuntu.sh

# Single-tenant engine + Tetragon. DEVCHOKE=1 also attaches the tc device plane.
deploy-engine: _require_ssh_host
	@SSH_HOST=$(SSH_HOST) $(DEPLOY_ENV) $(ROOT)/scripts/deploy/single-tenant-ubuntu.sh

# One REAL agent for one tenant, on its own host (its own kernel — that is what
# makes tenant separation real). Trust material and the enrolment token are
# pulled from the control plane rather than passed by hand.
deploy-agent:
	@[ -n "$(TENANT)" ]     || { echo "TENANT=<tenant-id> required";                exit 1; }
	@[ -n "$(AGENT_HOST)" ] || { echo "AGENT_HOST=<ssh host> required";             exit 1; }
	@[ -n "$(CP_SSH)" ]     || { echo "CP_SSH=<ssh host of the control plane> required"; exit 1; }
	@[ -n "$(CP_IP)" ]      || { echo "CP_IP=<control-plane address agents dial> required"; exit 1; }
	@set -e; \
	mkdir -p $(ROOT)/.deploy-build/trust; \
	echo "→ building the agent binary"; \
	cd $(ENGINE_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(ROOT)/.deploy-build/agent ./cmd/agent; \
	echo "→ pulling CA + fleet key + enrolment token from $(CP_SSH)"; \
	ssh -o BatchMode=yes $(CP_SSH) 'sudo cat /var/lib/ebpf-soc/ca.pem'    > $(ROOT)/.deploy-build/trust/ca.pem; \
	ssh -o BatchMode=yes $(CP_SSH) 'sudo cat /var/lib/ebpf-soc/fleet.pub' > $(ROOT)/.deploy-build/trust/fleet.pub; \
	TOK=$$(ssh -o BatchMode=yes $(CP_SSH) "sudo sed -n 's/^CP_ADMIN_TOKEN=//p' /etc/ebpf-soc/controlplane.env" | tr -d '\r'); \
	[ -n "$$TOK" ] || { echo "could not read CP_ADMIN_TOKEN from $(CP_SSH)"; exit 1; }; \
	[ -s $(DEVCHOKE_OBJ) ] || echo "  (no devchoke.o at $(DEVCHOKE_OBJ) — device choke will be audit-only; run 'make devchoke' on Linux)"; \
	CP_SSH=$(CP_SSH) $(ROOT)/scripts/deploy/provision-agent-ssh.sh \
	  "$(TENANT)" "$(AGENT_HOST)" "$(CP_IP)" "$$TOK" \
	  $(ROOT)/.deploy-build/trust/ca.pem $(ROOT)/.deploy-build/trust/fleet.pub \
	  $(ROOT)/.deploy-build/agent $$([ -s $(DEVCHOKE_OBJ) ] && echo $(DEVCHOKE_OBJ))

# Live end-to-end suite against a deployed rig (reads .deploy-build/e2e.env).
e2e:
	@$(ROOT)/scripts/e2e/all.sh

# ─────────────────────────────────────────────────────────────────────────
# LEGACY: Multipass deploy targets — drive the existing `ebpf` VM end-to-end.
# Override VM=<name> to target a different VM. Override REMOTE_DIR=<path>
# if you laid the bundle out somewhere other than /home/ubuntu/ebpf-poc.
# ─────────────────────────────────────────────────────────────────────────
VM         ?= ebpf
REMOTE_DIR ?= /home/ubuntu/ebpf-poc
REMOTE_USER ?= ubuntu
# Capture how REMOTE_DIR was set so SSH-based targets can auto-detect a
# provider-appropriate path ($HOME/ebpf-poc) when the user didn't override
# it — works across Multipass (ubuntu), Azure (azureuser), AWS (ec2-user),
# Scaleway, GCP, root, etc.
REMOTE_DIR_ORIGIN := $(origin REMOTE_DIR)

# Choke thresholds baked into the systemd unit. Tuned so Ubuntu's sshd
# MOTD churn (which scores ~84 from repeated /etc/passwd reads on each
# new SSH session) only reaches the tarpit tier — never quarantine
# (which would freeze sshd via cgroup.freeze and lock the operator out
# of the VM) or sever. Real attack chains routinely score >120 because
# they combine credential reads with curl|sh, base64 decode, chmod +x,
# privilege escalation etc. Override per-deploy with e.g.
# `make deploy SEVER_AT=60`.
THROTTLE_AT   ?= 20
TARPIT_AT     ?= 50
QUARANTINE_AT ?= 120
SEVER_AT      ?= 200

# Network (per-device / MAC) choke. Off by default — a Multipass VM is a
# single host, not a router, so there's nothing to forward-choke. Enable on
# a real inline gateway with `make deploy DEVCHOKE_IFACE=eth0,eth1` (the
# bridge slave ports). DEVCHOKE_FLAGS is appended to the engine ExecStart
# only when DEVCHOKE_IFACE is set.
DEVCHOKE_IFACE ?=
DEVCHOKE_FLAGS := $(if $(DEVCHOKE_IFACE),-devchoke-obj $(REMOTE_DIR)/bpf/devchoke.o -devchoke-iface $(DEVCHOKE_IFACE),)

# `deploy` rebuilds the Linux binary, syncs the bundle into the VM, applies
# policies (incl. enforce/), and (re)starts the engine as a systemd unit
# with the choke gateway enabled and -enforce on. No `make fake` here —
# this is the real path: real Tetragon, real cgroup v2 enforcement.
# vm-up / vm-doctor — self-heal multipass VM state before any deploy.
# multipassd 1.16.x on macOS occasionally wedges in "Unknown" or "Starting"
# (daemon SSH probe gets stuck even though the guest is up and reachable).
# scripts/multipass-doctor.sh detects both and recovers automatically; if
# a daemon kickstart is needed it'll prompt for sudo (or print the exact
# command if sudo is not cached).
vm-doctor:
	@$(ROOT)/scripts/multipass-doctor.sh $(VM)

vm-up: vm-doctor

deploy: _require_engine_pass build-linux vm-up
	@command -v multipass >/dev/null || { echo "multipass not found — install via brew: brew install --cask multipass"; exit 1; }
	@multipass info $(VM) >/dev/null 2>&1 || { echo "multipass VM '$(VM)' not found — run: multipass launch 22.04 --name $(VM) --cpus 2 --memory 4G --disk 20G"; exit 1; }
	@echo "→ syncing bundle into $(VM):$(REMOTE_DIR)"
	multipass exec $(VM) -- mkdir -p $(REMOTE_DIR) $(REMOTE_DIR)/bpf
	multipass transfer $(LINUX_BIN) $(VM):$(REMOTE_DIR)/engine-linux-$(LINUX_ARCH)
	tar -cz -C $(ROOT) policies attacks scripts | multipass exec $(VM) -- tar -xz -C $(REMOTE_DIR)
	multipass transfer $(ROOT)/engine/internal/enforce/bpfmap/bpf/choke.c $(VM):$(REMOTE_DIR)/bpf/choke.c
	multipass transfer $(ROOT)/engine/internal/enforce/devbpf/bpf/devchoke.c $(VM):$(REMOTE_DIR)/bpf/devchoke.c
	multipass exec $(VM) -- chmod +x $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH)
	multipass exec $(VM) -- chmod +x $(REMOTE_DIR)/scripts/setup.sh
	@echo "→ ensuring tetragon + cgroup v2 are ready"
	multipass exec $(VM) -- bash -lc "cd $(REMOTE_DIR) && TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh"
	@echo "→ applying TracingPolicies (detection + enforcement)"
	multipass exec $(VM) -- bash -lc "for p in $(REMOTE_DIR)/policies/*.yaml; do [ -f \$$p ] || continue; sudo docker cp \$$p tetragon:/tmp/ && sudo docker exec tetragon tetra tracingpolicy add /tmp/\$$(basename \$$p) || true; done"
	@echo "→ (re)starting engine with choke gateway + enforcement"
	-multipass exec $(VM) -- bash -lc "sudo systemctl stop ebpf-engine; sudo systemctl reset-failed ebpf-engine; sudo pkill -f engine-linux-amd64; exit 0"
	multipass exec $(VM) -- sudo mkdir -p /var/lib/ebpf-engine
	multipass exec $(VM) -- bash -lc "sudo systemd-run --unit=ebpf-engine --description='eBPF Choke Gateway' --property=Restart=always --property=RestartSec=2 --property=StandardOutput=append:/var/log/ebpf-engine.log --property=StandardError=append:/var/log/ebpf-engine.log --property=WorkingDirectory=$(REMOTE_DIR) $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH) -tetragon unix:///var/run/tetragon/tetragon.sock -db /var/lib/ebpf-engine/events.db -http :8080 -user $(ENGINE_USER) -pass $(ENGINE_PASS) -policies $(REMOTE_DIR)/policies -attacks $(REMOTE_DIR)/attacks -honeypots /var/lib/ebpf-engine/honey -choke-policies $(REMOTE_DIR)/policies/choke -enforce -cgroup-root /sys/fs/cgroup -throttle-at $(THROTTLE_AT) -tarpit-at $(TARPIT_AT) -quarantine-at $(QUARANTINE_AT) -sever-at $(SEVER_AT) -bpf-obj $(REMOTE_DIR)/bpf/choke.o -bpf-cgroup /sys/fs/cgroup $(DEVCHOKE_FLAGS)"
	@sleep 2
	@echo
	@echo "──────────────────────────────────────────────────────────────"
	@echo " Engine status:"
	@multipass exec $(VM) -- bash -lc "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || true"
	@echo
	@VM_IP=$$(multipass info $(VM) | awk '/IPv4/{print $$2; exit}'); echo " UI:           http://$$VM_IP:8080/"; echo " Choke console: http://$$VM_IP:8080/choke"; echo " login:        $(ENGINE_USER) / (the ENGINE_PASS you supplied)"
	@echo "──────────────────────────────────────────────────────────────"

# `redeploy` is `deploy` minus the setup.sh step — fast iteration once the
# VM has been bootstrapped once. Linux refuses to overwrite a running
# executable (ETXTBSY), so we stage the new binary as `.new`, then `mv`
# it over the live one — rename(2) is atomic and unaffected by the old
# inode still being held open. systemctl restart picks it up.
redeploy: _require_engine_pass build-linux
	multipass transfer $(LINUX_BIN) $(VM):$(REMOTE_DIR)/engine-linux-$(LINUX_ARCH).new
	multipass exec $(VM) -- bash -lc "chmod +x $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH).new && mv -f $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH).new $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH)"
	tar -cz -C $(ROOT) policies attacks | multipass exec $(VM) -- tar -xz -C $(REMOTE_DIR)
	multipass exec $(VM) -- bash -lc "sudo systemctl restart ebpf-engine 2>/dev/null || sudo pkill -TERM -f engine-linux-amd64 || true"
	@sleep 2
	@multipass exec $(VM) -- bash -lc "sudo systemctl is-active ebpf-engine 2>/dev/null; sudo journalctl -u ebpf-engine -n 5 --no-pager 2>/dev/null || true"

# ─────────────────────────────────────────────────────────────────────────
# Generic SSH-based deploy — for Azure, EC2, GCP, bare metal — anywhere
# you can ssh and sudo. Mirrors `deploy` step-for-step but uses ssh/scp
# instead of multipass exec/transfer.
#
# Usage:
#   make deploy-remote HOST=azureuser@52.151.10.20
#   make deploy-remote HOST=ec2-user@1.2.3.4 SSH_OPTS="-i ~/.ssh/aws.pem"
#   make redeploy-remote HOST=...                  # binary + policies, skip setup.sh
#
# Prerequisites on the remote host:
#   - Ubuntu 22.04+ (kernel ≥5.10 for BTF, required by Tetragon)
#   - passwordless sudo for $(HOST) user (the deploy uses sudo extensively)
#   - inbound :8080 open in your security group / NSG
#   - 2 vCPU / 2GB RAM minimum (4GB recommended; setup.sh pulls a ~500MB image)
# ─────────────────────────────────────────────────────────────────────────
HOST     ?=
SSH_OPTS ?=
SSH       = ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $(SSH_OPTS) $(HOST)
SCP       = scp -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $(SSH_OPTS)

deploy-remote: _require_engine_pass build-linux
	@if [ -z "$(HOST)" ]; then echo "HOST=user@ip required, e.g. make deploy-remote HOST=azureuser@52.x.y.z"; exit 1; fi
	@command -v ssh >/dev/null || { echo "ssh not found"; exit 1; }
	@$(SSH) -o BatchMode=yes true 2>/dev/null || { echo "cannot reach $(HOST) over ssh — check key, firewall, host"; exit 1; }
	@set -e; \
	if [ "$(REMOTE_DIR_ORIGIN)" = "command line" ] || [ "$(REMOTE_DIR_ORIGIN)" = "environment" ] || [ "$(REMOTE_DIR_ORIGIN)" = "environment override" ]; then \
	  REMOTE_DIR='$(REMOTE_DIR)'; \
	else \
	  REMOTE_DIR="$$($(SSH) 'echo $$HOME')/ebpf-poc"; \
	fi; \
	echo "→ remote dir: $$REMOTE_DIR"; \
	echo "→ stopping any running engine so the binary is writable"; \
	$(SSH) "sudo systemctl stop ebpf-engine 2>/dev/null; sudo pkill -f engine-linux-amd64 2>/dev/null; exit 0" || true; \
	echo "→ syncing bundle into $(HOST):$$REMOTE_DIR"; \
	$(SSH) "mkdir -p $$REMOTE_DIR"; \
	$(SCP) $(LINUX_BIN) $(HOST):$$REMOTE_DIR/engine-linux-$(LINUX_ARCH); \
	tar -cz -C $(ROOT) policies attacks scripts | $(SSH) "tar -xz -C $$REMOTE_DIR"; \
	$(SSH) "chmod +x $$REMOTE_DIR/engine-linux-$(LINUX_ARCH) $$REMOTE_DIR/scripts/setup.sh"; \
	echo "→ ensuring tetragon + cgroup v2 are ready"; \
	$(SSH) "cd $$REMOTE_DIR && TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh"; \
	echo "→ applying TracingPolicies (detection + enforcement)"; \
	$(SSH) "for p in $$REMOTE_DIR/policies/*.yaml; do [ -f \"\$$p\" ] || continue; sudo docker cp \"\$$p\" tetragon:/tmp/ && sudo docker exec tetragon tetra tracingpolicy add /tmp/\$$(basename \"\$$p\") || true; done"; \
	echo "→ (re)starting engine with choke gateway + enforcement"; \
	$(SSH) "sudo systemctl stop ebpf-engine 2>/dev/null; sudo systemctl reset-failed ebpf-engine 2>/dev/null; sudo pkill -f engine-linux-amd64 2>/dev/null; exit 0" || true; \
	$(SSH) "sudo mkdir -p /var/lib/ebpf-engine"; \
	$(SSH) "sudo systemd-run --unit=ebpf-engine --description='eBPF Choke Gateway' --property=Restart=always --property=RestartSec=2 --property=StandardOutput=append:/var/log/ebpf-engine.log --property=StandardError=append:/var/log/ebpf-engine.log --property=WorkingDirectory=$$REMOTE_DIR $$REMOTE_DIR/engine-linux-$(LINUX_ARCH) -tetragon unix:///var/run/tetragon/tetragon.sock -db /var/lib/ebpf-engine/events.db -http :8080 -user $(ENGINE_USER) -pass $(ENGINE_PASS) -policies $$REMOTE_DIR/policies -attacks $$REMOTE_DIR/attacks -honeypots /var/lib/ebpf-engine/honey -choke-policies $$REMOTE_DIR/policies/choke -enforce -cgroup-root /sys/fs/cgroup -throttle-at $(THROTTLE_AT) -tarpit-at $(TARPIT_AT) -quarantine-at $(QUARANTINE_AT) -sever-at $(SEVER_AT)"; \
	sleep 2; \
	echo; \
	echo "──────────────────────────────────────────────────────────────"; \
	echo " Engine status:"; \
	$(SSH) "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || true"; \
	echo; \
	HOST_PART=$$(echo "$(HOST)" | sed 's/.*@//'); \
	VM_IP=$$($(SSH) "hostname -I 2>/dev/null | awk '{print \$$1}'" 2>/dev/null); \
	if [ "$$HOST_PART" = "orb" ]; then \
	  USER_PART=$$(echo "$(HOST)" | sed 's/@.*//'); \
	  PRIMARY="http://$${USER_PART}.orb.local:8080"; \
	else \
	  PRIMARY="http://$${HOST_PART}:8080"; \
	fi; \
	echo " UI:           $$PRIMARY/"; \
	[ -n "$$VM_IP" ] && echo " Direct IP:    http://$$VM_IP:8080/"; \
	echo " Choke console: $$PRIMARY/choke"; \
	echo " login:        $(ENGINE_USER) / (the ENGINE_PASS you supplied)"; \
	echo "──────────────────────────────────────────────────────────────"

# Fast iteration variant — binary + policies only, no setup.sh.
# Stages the binary as `.new` then atomically renames it over the
# running executable. Linux refuses direct overwrite (ETXTBSY) but
# rename(2) is fine: the old inode stays alive for the running process,
# the new path points at the new inode, and systemctl restart picks
# it up cleanly. Falls back to pkill (Restart=always respawns).
redeploy-remote: _require_engine_pass build-linux
	@if [ -z "$(HOST)" ]; then echo "HOST=user@ip required"; exit 1; fi
	@set -e; \
	if [ "$(REMOTE_DIR_ORIGIN)" = "command line" ] || [ "$(REMOTE_DIR_ORIGIN)" = "environment" ] || [ "$(REMOTE_DIR_ORIGIN)" = "environment override" ]; then \
	  REMOTE_DIR='$(REMOTE_DIR)'; \
	else \
	  REMOTE_DIR="$$($(SSH) 'echo $$HOME')/ebpf-poc"; \
	fi; \
	echo "→ remote dir: $$REMOTE_DIR"; \
	echo "→ staging new binary as .new (no need to stop the engine first)"; \
	$(SCP) $(LINUX_BIN) $(HOST):$$REMOTE_DIR/engine-linux-$(LINUX_ARCH).new; \
	$(SSH) "chmod +x $$REMOTE_DIR/engine-linux-$(LINUX_ARCH).new && mv -f $$REMOTE_DIR/engine-linux-$(LINUX_ARCH).new $$REMOTE_DIR/engine-linux-$(LINUX_ARCH)"; \
	tar -cz -C $(ROOT) policies attacks | $(SSH) "tar -xz -C $$REMOTE_DIR"; \
	echo "→ restarting engine to load the new binary"; \
	$(SSH) "sudo systemctl restart ebpf-engine 2>/dev/null || sudo pkill -TERM -f engine-linux-amd64 || true"; \
	sleep 2; \
	$(SSH) "sudo systemctl is-active ebpf-engine 2>/dev/null; sudo journalctl -u ebpf-engine -n 5 --no-pager 2>/dev/null || true"

# `install-vm` is the production-grade alternative to `deploy`: it syncs
# the bundle into /opt/ebpf-engine on the VM, runs the proper installer
# (deploy/install.sh) which lays down a real systemd unit, a config file
# under /etc/ebpf-engine/, and the BPF data plane under /opt/.../bpf/.
# Use `make deploy` for fast iteration, `make install-vm` when you want
# the persistent layout. They're not interchangeable mid-deploy — pick one.
install-vm: _require_engine_pass build-linux vm-up
	multipass exec $(VM) -- bash -c "rm -rf /tmp/ebpf-poc-install && mkdir -p /tmp/ebpf-poc-install/engine/internal/enforce/bpfmap/bpf"
	tar -cz -C $(ROOT) deploy policies attacks scripts | multipass exec $(VM) -- tar -xz -C /tmp/ebpf-poc-install
	multipass transfer $(LINUX_BIN) $(VM):/tmp/ebpf-poc-install/engine/engine-linux-amd64
	multipass transfer $(ROOT)/engine/internal/enforce/bpfmap/bpf/choke.c $(VM):/tmp/ebpf-poc-install/engine/internal/enforce/bpfmap/bpf/choke.c
	multipass exec $(VM) -- mkdir -p /tmp/ebpf-poc-install/engine/internal/enforce/devbpf/bpf
	multipass transfer $(ROOT)/engine/internal/enforce/devbpf/bpf/devchoke.c $(VM):/tmp/ebpf-poc-install/engine/internal/enforce/devbpf/bpf/devchoke.c
	multipass exec $(VM) -- sudo bash -c "cd /tmp/ebpf-poc-install && SRC_ROOT=/tmp/ebpf-poc-install bash deploy/install.sh"

# `tls-vm` puts nginx in front of the engine on :443 with a self-signed
# cert. Operators replace the cert with a real one (Let's Encrypt or
# their internal CA) by dropping fullchain.pem + privkey.pem into
# /etc/nginx/ebpf/ — the include line picks them up on the next reload.
tls-vm:
	multipass exec $(VM) -- sudo bash -c "command -v nginx >/dev/null || apt-get install -y --no-install-recommends nginx-light openssl"
	multipass exec $(VM) -- sudo mkdir -p /etc/nginx/ebpf
	multipass transfer $(ROOT)/deploy/nginx/ebpf-engine.conf $(VM):/tmp/ebpf-engine.conf
	multipass exec $(VM) -- sudo bash -c "cp /tmp/ebpf-engine.conf /etc/nginx/sites-available/ebpf-engine && ln -sf /etc/nginx/sites-available/ebpf-engine /etc/nginx/sites-enabled/ebpf-engine && rm -f /etc/nginx/sites-enabled/default"
	multipass exec $(VM) -- sudo bash -c "[ -f /etc/nginx/ebpf/fullchain.pem ] || (cd /etc/nginx/ebpf && openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privkey.pem -out fullchain.pem -subj '/CN=ebpf-engine.local' 2>/dev/null)"
	multipass exec $(VM) -- sudo nginx -t
	multipass exec $(VM) -- sudo systemctl reload nginx || multipass exec $(VM) -- sudo systemctl restart nginx
	@VM_IP=$$(multipass info $(VM) | awk '/IPv4/{print $$2; exit}'); echo "→ https://$$VM_IP/ (self-signed; replace /etc/nginx/ebpf/fullchain.pem + privkey.pem with a real cert)"

# `pg-vm` brings up a Postgres 16 container on the VM and seeds the
# engine database + user. Idempotent: if the container is already running
# this is a no-op. Default credentials engine/engine — operator changes
# them via POSTGRES_USER/POSTGRES_PASSWORD env vars.
PG_USER     ?= engine
PG_PASSWORD ?= engine
PG_DB       ?= ebpf
PG_PORT     ?= 5432
pg-vm:
	multipass exec $(VM) -- bash -c "sudo docker ps --format '{{.Names}}' | grep -q '^ebpf-pg$$' || sudo docker run -d --name ebpf-pg --restart unless-stopped -p $(PG_PORT):5432 -e POSTGRES_USER=$(PG_USER) -e POSTGRES_PASSWORD=$(PG_PASSWORD) -e POSTGRES_DB=$(PG_DB) postgres:16-alpine"
	@echo "→ waiting for Postgres to accept connections"
	@for i in $$(seq 1 30); do \
	  if multipass exec $(VM) -- sudo docker exec ebpf-pg pg_isready -U $(PG_USER) -d $(PG_DB) >/dev/null 2>&1; then \
	    echo "→ ready"; break; \
	  fi; sleep 1; \
	done
	@echo "→ DSN: postgres://$(PG_USER):***@127.0.0.1:$(PG_PORT)/$(PG_DB)?sslmode=disable"
	@echo "  set in /etc/ebpf-engine/engine.yaml as:"
	@echo "    store:  postgres"
	@echo "    pg_dsn: postgres://$(PG_USER):$(PG_PASSWORD)@127.0.0.1:$(PG_PORT)/$(PG_DB)?sslmode=disable"

vm-logs:
	multipass exec $(VM) -- sudo journalctl -u ebpf-engine -f --no-pager

vm-status:
	@multipass exec $(VM) -- bash -lc "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || true; cat /sys/fs/cgroup/choke-throttled/cgroup.procs 2>/dev/null | wc -l | xargs -I{} echo 'throttled pids: {}'; cat /sys/fs/cgroup/choke-tarpit/cgroup.procs 2>/dev/null | wc -l | xargs -I{} echo 'tarpit pids: {}'; cat /sys/fs/cgroup/choke-quarantined/cgroup.procs 2>/dev/null | wc -l | xargs -I{} echo 'quarantined pids: {}'"

# Run a real attack scenario inside the VM to exercise the choke chain.
# Override SCRIPT=03-reverse-shell.sh to pick a different script.
SCRIPT ?= 01-webshell.sh
vm-attack:
	multipass exec $(VM) -- sudo bash $(REMOTE_DIR)/attacks/$(SCRIPT)

# ─────────────────────────────────────────────────────────────────────────
# Fleet operations (Tier 1) — fan multipass operations across multiple VMs.
# Every choke-gateway HTTP operation (status / preset / thresholds /
# snapshot / kill-switch / thaw / jail / merged decisions+alerts) lives
# in `scripts/chokectl` instead, which reads ./chokectl.hosts.
#
# Use VMS for multipass-side fanout (deploy / attack / logs):
#   make deploy-all VMS="ebpf-1 ebpf-2 ebpf-3"
# or set a default in your shell:
#   export VMS="ebpf-1 ebpf-2 ebpf-3 ebpf-4 ebpf-5 ebpf-6 ebpf-7"
# ─────────────────────────────────────────────────────────────────────────
.PHONY: deploy-all redeploy-all vm-status-all vm-attack-all fleet-status fleet-decisions fleet-alerts fleet-snapshot
VMS ?= $(VM)

deploy-all:
	@for vm in $(VMS); do \
	  echo ""; echo "═══════════════════════════════════ $$vm ═══════════════════════════════════"; \
	  $(MAKE) deploy VM=$$vm || echo "→ $$vm: deploy FAILED"; \
	done

redeploy-all: build-linux
	@for vm in $(VMS); do \
	  echo ""; echo "═══════════════════════════════════ $$vm ═══════════════════════════════════"; \
	  $(MAKE) redeploy VM=$$vm || echo "→ $$vm: redeploy FAILED"; \
	done

vm-status-all:
	@for vm in $(VMS); do \
	  ip=$$(multipass info $$vm 2>/dev/null | awk '/IPv4/{print $$2; exit}'); \
	  printf '%-12s ' "$$vm"; \
	  if [ -z "$$ip" ]; then echo "(not running)"; continue; fi; \
	  jar=/tmp/chokectl-cookies-mk-$$vm; \
	  curl -s -m 3 -c $$jar -d "user=$(ENGINE_USER)&pass=$$ENGINE_PASS" http://$$ip:8080/api/login -o /dev/null 2>/dev/null; \
	  curl -s -m 3 -b $$jar "http://$$ip:8080/api/choke/state" 2>/dev/null \
	    | python3 -c 'import sys,json;d=json.load(sys.stdin); t=d.get("thresholds") or {}; print(d.get("mode","?"), "kill="+("on" if d.get("kill_switched") else "off"), "thr="+str(t.get("throttle_at","?"))+"/"+str(t.get("tarpit_at","?"))+"/"+str(t.get("quarantine_at","?"))+"/"+str(t.get("sever_at","?")), "tracked="+str(d.get("tracked",0)))' \
	    || echo "(unreachable)"; \
	  rm -f $$jar; \
	done

vm-attack-all:
	@for vm in $(VMS); do \
	  echo "→ attack $(SCRIPT) on $$vm"; \
	  multipass exec $$vm -- sudo bash $(REMOTE_DIR)/attacks/$(SCRIPT) 2>&1 | sed "s/^/  $$vm: /" || true; \
	done

# Convenience targets that delegate to chokectl. The script reads
# ./chokectl.hosts (override with CHOKECTL_HOSTS=...).
fleet-status:
	@$(ROOT)/scripts/chokectl status

fleet-decisions:
	@$(ROOT)/scripts/chokectl decisions $(N)

fleet-alerts:
	@$(ROOT)/scripts/chokectl alerts $(N)

fleet-snapshot:
	@$(ROOT)/scripts/chokectl snapshot
