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

.PHONY: build build-linux test vet fake policies-apply policies-list tarball clean

build:
	cd $(ENGINE_DIR) && go build -o engine ./cmd/engine

build-linux:
	cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 go build -o engine-linux-$(LINUX_ARCH) ./cmd/engine
	@echo "→ $(LINUX_BIN)"

test:
	cd $(ENGINE_DIR) && go test ./...

vet:
	cd $(ENGINE_DIR) && go vet ./...

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
		Makefile scripts policies attacks README.md docs/build.md \
		engine/engine-linux-$(LINUX_ARCH)
	@echo "→ ebpf-poc-$(LINUX_ARCH).tar.gz"

clean:
	rm -f $(BIN) $(ENGINE_DIR)/engine-linux-amd64 $(ENGINE_DIR)/engine-linux-arm64
	rm -f $(ROOT)/fake-events.db $(ROOT)/events.db
	rm -f $(ROOT)/ebpf-poc-amd64.tar.gz $(ROOT)/ebpf-poc-arm64.tar.gz
