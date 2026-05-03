# eBPF Threat Observability PoC — top-level Makefile
#
# Targets:
#   make build           native build of the engine binary -> engine/engine
#   make build-linux     cross-compile linux/amd64 (or arm64) -> engine/engine-linux-<arch>
#   make test            run all Go unit tests
#   make vet             go vet
#   make fake            run the engine in fake mode on :8080 (no Tetragon needed)
#   make policies-apply  copy + apply all TracingPolicies into a running tetragon container
#   make policies-list   list active policies in the tetragon container
#   make tarball         bundle policies/, attacks/, the linux binary, and README into a tar.gz
#   make clean           remove build artifacts

ROOT       := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ENGINE_DIR := $(ROOT)/engine
BIN        := $(ENGINE_DIR)/engine
LINUX_ARCH ?= amd64
LINUX_BIN  := $(ENGINE_DIR)/engine-linux-$(LINUX_ARCH)
TETRA_CT   ?= tetragon

.PHONY: build build-linux test vet fake policies-apply policies-list tarball clean deploy redeploy deploy-remote redeploy-remote vm-logs vm-attack vm-status

build:
	cd $(ENGINE_DIR) && go build -o engine ./cmd/engine

build-linux:
	cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 go build -o engine-linux-$(LINUX_ARCH) ./cmd/engine
	@echo "→ $(LINUX_BIN)"

test:
	cd $(ENGINE_DIR) && go test ./...

vet:
	cd $(ENGINE_DIR) && go vet ./...

# fake mode is retained for unit tests + UI iteration only. Production
# never uses it — see `make deploy` for the real path.
fake: build
	$(BIN) -fake -db $(ROOT)/fake-events.db

policies-apply:
	@for p in $(ROOT)/policies/*.yaml; do \
		echo "→ apply $$(basename $$p)"; \
		docker cp "$$p" $(TETRA_CT):/tmp/ ; \
		docker exec $(TETRA_CT) tetra tracingpolicy add /tmp/$$(basename $$p) || true ; \
	done
	$(MAKE) policies-list

policies-list:
	docker exec $(TETRA_CT) tetra tracingpolicy list

tarball: build-linux
	tar -czf ebpf-poc-$(LINUX_ARCH).tar.gz \
		-C $(ROOT) \
		Makefile scripts policies attacks README.md docs/development/build-plan.md \
		engine/engine-linux-$(LINUX_ARCH)
	@echo "→ ebpf-poc-$(LINUX_ARCH).tar.gz"

clean:
	rm -f $(BIN) $(ENGINE_DIR)/engine-linux-amd64 $(ENGINE_DIR)/engine-linux-arm64
	rm -f $(ROOT)/fake-events.db $(ROOT)/events.db
	rm -f $(ROOT)/ebpf-poc-amd64.tar.gz $(ROOT)/ebpf-poc-arm64.tar.gz

# ─────────────────────────────────────────────────────────────────────────
# Multipass deploy targets — drive the existing `ebpf` VM end-to-end.
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

# `deploy` rebuilds the Linux binary, syncs the bundle into the VM, applies
# policies (incl. enforce/), and (re)starts the engine as a systemd unit
# with the choke gateway enabled and -enforce on. No `make fake` here —
# this is the real path: real Tetragon, real cgroup v2 enforcement.
deploy: build-linux
	@command -v multipass >/dev/null || { echo "multipass not found — install via brew: brew install --cask multipass"; exit 1; }
	@multipass info $(VM) >/dev/null 2>&1 || { echo "multipass VM '$(VM)' not found — run: multipass launch 22.04 --name $(VM) --cpus 2 --memory 4G --disk 20G"; exit 1; }
	@echo "→ syncing bundle into $(VM):$(REMOTE_DIR)"
	multipass exec $(VM) -- mkdir -p $(REMOTE_DIR)
	multipass transfer $(LINUX_BIN) $(VM):$(REMOTE_DIR)/engine-linux-$(LINUX_ARCH)
	tar -cz -C $(ROOT) policies attacks scripts | multipass exec $(VM) -- tar -xz -C $(REMOTE_DIR)
	multipass exec $(VM) -- chmod +x $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH)
	multipass exec $(VM) -- chmod +x $(REMOTE_DIR)/scripts/setup.sh
	@echo "→ ensuring tetragon + cgroup v2 are ready"
	multipass exec $(VM) -- bash -lc "cd $(REMOTE_DIR) && TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh"
	@echo "→ applying TracingPolicies (detection + enforcement)"
	multipass exec $(VM) -- bash -lc "for p in $(REMOTE_DIR)/policies/*.yaml $(REMOTE_DIR)/policies/enforce/*.yaml; do [ -f \$$p ] || continue; sudo docker cp \$$p tetragon:/tmp/ && sudo docker exec tetragon tetra tracingpolicy add /tmp/\$$(basename \$$p) || true; done"
	@echo "→ (re)starting engine with choke gateway + enforcement"
	-multipass exec $(VM) -- bash -lc "sudo systemctl stop ebpf-engine; sudo systemctl reset-failed ebpf-engine; sudo pkill -f engine-linux-amd64; exit 0"
	multipass exec $(VM) -- sudo mkdir -p /var/lib/ebpf-engine
	multipass exec $(VM) -- bash -lc "sudo systemd-run --unit=ebpf-engine --description='eBPF Choke Gateway' --property=Restart=always --property=RestartSec=2 --property=StandardOutput=append:/var/log/ebpf-engine.log --property=StandardError=append:/var/log/ebpf-engine.log --property=WorkingDirectory=$(REMOTE_DIR) $(REMOTE_DIR)/engine-linux-$(LINUX_ARCH) -tetragon unix:///var/run/tetragon/tetragon.sock -db /var/lib/ebpf-engine/events.db -http :8080 -user admin -pass ebpf-soc-demo -policies $(REMOTE_DIR)/policies -attacks $(REMOTE_DIR)/attacks -honeypots /var/lib/ebpf-engine/honey -choke-policies $(REMOTE_DIR)/policies/choke -enforce -cgroup-root /sys/fs/cgroup -throttle-at $(THROTTLE_AT) -tarpit-at $(TARPIT_AT) -quarantine-at $(QUARANTINE_AT) -sever-at $(SEVER_AT)"
	@sleep 2
	@echo
	@echo "──────────────────────────────────────────────────────────────"
	@echo " Engine status:"
	@multipass exec $(VM) -- bash -lc "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || true"
	@echo
	@VM_IP=$$(multipass info $(VM) | awk '/IPv4/{print $$2; exit}'); echo " UI:           http://$$VM_IP:8080/"; echo " Choke console: http://$$VM_IP:8080/choke"; echo " login:        admin / ebpf-soc-demo"
	@echo "──────────────────────────────────────────────────────────────"

# `redeploy` is `deploy` minus the setup.sh step — fast iteration once the
# VM has been bootstrapped once. Linux refuses to overwrite a running
# executable (ETXTBSY), so we stage the new binary as `.new`, then `mv`
# it over the live one — rename(2) is atomic and unaffected by the old
# inode still being held open. systemctl restart picks it up.
redeploy: build-linux
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

deploy-remote: build-linux
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
	$(SSH) "for p in $$REMOTE_DIR/policies/*.yaml $$REMOTE_DIR/policies/enforce/*.yaml; do [ -f \"\$$p\" ] || continue; sudo docker cp \"\$$p\" tetragon:/tmp/ && sudo docker exec tetragon tetra tracingpolicy add /tmp/\$$(basename \"\$$p\") || true; done"; \
	echo "→ (re)starting engine with choke gateway + enforcement"; \
	$(SSH) "sudo systemctl stop ebpf-engine 2>/dev/null; sudo systemctl reset-failed ebpf-engine 2>/dev/null; sudo pkill -f engine-linux-amd64 2>/dev/null; exit 0" || true; \
	$(SSH) "sudo mkdir -p /var/lib/ebpf-engine"; \
	$(SSH) "sudo systemd-run --unit=ebpf-engine --description='eBPF Choke Gateway' --property=Restart=always --property=RestartSec=2 --property=StandardOutput=append:/var/log/ebpf-engine.log --property=StandardError=append:/var/log/ebpf-engine.log --property=WorkingDirectory=$$REMOTE_DIR $$REMOTE_DIR/engine-linux-$(LINUX_ARCH) -tetragon unix:///var/run/tetragon/tetragon.sock -db /var/lib/ebpf-engine/events.db -http :8080 -user admin -pass ebpf-soc-demo -policies $$REMOTE_DIR/policies -attacks $$REMOTE_DIR/attacks -honeypots /var/lib/ebpf-engine/honey -choke-policies $$REMOTE_DIR/policies/choke -enforce -cgroup-root /sys/fs/cgroup -throttle-at $(THROTTLE_AT) -tarpit-at $(TARPIT_AT) -quarantine-at $(QUARANTINE_AT) -sever-at $(SEVER_AT)"; \
	sleep 2; \
	echo; \
	echo "──────────────────────────────────────────────────────────────"; \
	echo " Engine status:"; \
	$(SSH) "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || true"; \
	echo; \
	HOST_IP=$$(echo "$(HOST)" | sed 's/.*@//'); echo " UI:           http://$$HOST_IP:8080/"; echo " Choke console: http://$$HOST_IP:8080/choke"; echo " login:        admin / ebpf-soc-demo"; \
	echo "──────────────────────────────────────────────────────────────"

# Fast iteration variant — binary + policies only, no setup.sh.
# Stages the binary as `.new` then atomically renames it over the
# running executable. Linux refuses direct overwrite (ETXTBSY) but
# rename(2) is fine: the old inode stays alive for the running process,
# the new path points at the new inode, and systemctl restart picks
# it up cleanly. Falls back to pkill (Restart=always respawns).
redeploy-remote: build-linux
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
	  curl -s -m 3 -c $$jar -d 'user=admin&pass=ebpf-soc-demo' http://$$ip:8080/api/login -o /dev/null 2>/dev/null; \
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
