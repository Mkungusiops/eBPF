# eBPF Threat Observability PoC — 5-Day Build Plan

> A proactive, kernel-level threat observability tool built on Tetragon, with a Go correlation engine, SQLite event store, and a live web UI. Designed to be buildable by one engineer in five working days.

---

## Table of Contents

1. [The Stack](#the-stack)
2. [Goal & Success Criteria](#goal--success-criteria)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Day 1 — Foundation: Get Kernel Events Flowing](#day-1--foundation-get-kernel-events-flowing)
6. [Day 2 — Detection Policies](#day-2--detection-policies)
7. [Day 3 — Correlation & Scoring Engine](#day-3--correlation--scoring-engine)
8. [Day 4 — Visibility UI](#day-4--visibility-ui)
9. [Day 5 — Attack Simulation, Validation, Demo](#day-5--attack-simulation-validation-demo)
10. [Troubleshooting](#troubleshooting)
11. [References](#references)

---

## The Stack

### At a glance

| Layer | Choice | Why |
|---|---|---|
| **Framework** | Tetragon (host mode, Docker) | Saves ~2 weeks vs writing libbpf+C from scratch |
| **Detection rules** | TracingPolicy YAML | Tetragon's policy CRD; compiles to eBPF in-kernel |
| **Language** | Go 1.22+ | First-class Tetragon client; ecosystem parity |
| **gRPC client** | `github.com/cilium/tetragon/api/v1/tetragon` | Official Go bindings |
| **Database** | SQLite via `modernc.org/sqlite` | Pure Go, no CGO, single file |
| **HTTP server** | Go stdlib `net/http` | No framework needed at this scope |
| **Frontend** | Single HTML + Tailwind CDN + vanilla JS | No build pipeline |
| **Host OS** | Ubuntu 22.04 LTS | Kernel 5.15+ with BTF enabled |
| **Container runtime** | Docker | Trivial Tetragon installation |
| **Debug CLI** | `tetra` | Tetragon's official client |

### Why this stack

**Tetragon is the framework.** It gives you pre-written eBPF programs, a declarative policy language (TracingPolicy YAML), a gRPC event stream, process tree tracking with stable `exec_id`s, and CO-RE compatibility across kernel versions. Without it, "framework" decomposes into libbpf + bpftool + your own C + your own Go loader — the right answer for a long-term production build, the wrong answer for a 5-day window.

**Go is the language.** Three concrete reasons:
1. Tetragon's official Go client (`github.com/cilium/tetragon/api/v1/tetragon`) is first-class and maintained. Other languages require generating gRPC bindings yourself.
2. The eBPF cloud-native ecosystem — Cilium, Hubble, Tetragon, Inspektor Gadget, Pixie, Parca — is uniformly Go. Patterns and code are liftable from any of them.
3. Single static binary, no runtime, no interpreter. Exactly what a security tool deployed to many hosts needs.

**SQLite over ClickHouse/Postgres.** No ops, indexed queries, transactional, single file. Swap to ClickHouse on day 30 when you outgrow one host.

**Vanilla JS over React.** A single HTML file with Server-Sent Events does everything the UI needs. Migrating to React costs you a Webpack/Vite/npm tangent that has no place in week one.

### What you don't need (and why)

| Tempting choice | Why we're not using it |
|---|---|
| Raw libbpf + C | Adds 2+ weeks; Tetragon already wraps it |
| Falco | Less flexible for custom correlation logic |
| Tracee | Event model more rigid than Tetragon's policies |
| Rust + Aya | Tetragon's Rust client story is immature |
| BCC (Python) | No CO-RE; needs kernel headers on every target |
| Kubernetes | Adds operational complexity to a single-host PoC |
| Kafka / Redpanda | SQLite handles single-host volume fine |
| ClickHouse / Postgres | Stateful service to operate; defer to v2 |
| Gin / Echo / Fiber | Five HTTP routes don't need a framework |
| React / Vue / Svelte | No build pipeline = save half a day |
| OpenTelemetry collector | Useful in production, overkill for PoC |

> **The discipline:** if at any point you're tempted to add a framework or service, ask *"does this save more time than it costs to learn?"* In a 5-day window, the answer is almost always no.

### Verify before starting

Before Day 1 begins, confirm your environment can support this stack. If anything below fails, fix it first — don't carry the problem into Day 1.

```bash
# Kernel and BTF (REQUIRED — non-negotiable)
uname -r                          # must be 5.15 or higher
ls /sys/kernel/btf/vmlinux        # this file must exist

# Architecture
uname -m                          # x86_64 or aarch64

# Tools you'll need installed during Day 1 §1.1–1.5
which curl git make jq            # all should resolve

# Ports
ss -tlnp | grep -E ':(8080)\s' || echo "port 8080 free"
```

If `uname -r` is below 5.15 or `/sys/kernel/btf/vmlinux` doesn't exist, **stop and switch VMs**. No amount of cleverness later compensates for missing BTF.

---

## Goal & Success Criteria

**What we're building:** A kernel-instrumented threat observability tool that watches process execution, privilege transitions, sensitive file access, and network behavior in real time. It correlates events into process trees, scores chains of suspicious activity, and surfaces alerts *while attacks are unfolding* — not after the fact.

**Why this is "proactive":** We catch attacks during their early phases (recon, initial execution, credential staging) before exfiltration or persistence completes. We do *not* prevent (that requires BPF LSM enforcement, out of scope for 5 days). We detect early enough that a human operator could respond.

**Done looks like:**

- Tetragon running on a Linux host, emitting kernel events
- 4 working TracingPolicies covering execution, privilege escalation, file access, network anomalies
- Go correlation engine consuming Tetragon's gRPC stream, building process trees, scoring chains
- SQLite store persisting events and alerts for query and replay
- Web UI showing live event stream, alert list, and process tree visualization
- Three attack simulations that demonstrably trigger alerts in real time
- 3-minute demo video and a clean README

**Out of scope:** prevention/enforcement, ML/UEBA, multi-host scaling, production hardening, persistence beyond SQLite, authentication on the UI, Kubernetes integration.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Linux Host (Ubuntu 22.04+)                  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     Linux Kernel (5.15+)                     │   │
│  │  ┌────────┐  ┌────────┐  ┌──────────┐  ┌──────────────────┐  │   │
│  │  │execve  │  │kprobes │  │tracepoint│  │  BPF programs    │  │   │
│  │  └───┬────┘  └───┬────┘  └────┬─────┘  └────────┬─────────┘  │   │
│  └──────┼───────────┼────────────┼─────────────────┼────────────┘   │
│         │           │            │                 │                │
│         ▼           ▼            ▼                 ▼                │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                Tetragon (eBPF agent, host mode)              │   │
│  │   - Loads TracingPolicies as eBPF programs                   │   │
│  │   - Process tree tracking (exec_id stable across PID reuse)  │   │
│  │   - Exposes gRPC at /var/run/tetragon/tetragon.sock          │   │
│  └────────────────────────────┬─────────────────────────────────┘   │
│                               │ gRPC stream                         │
│                               ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              Correlation Engine (Go service)                 │   │
│  │   - Subscribes to GetEvents stream                           │   │
│  │   - Builds in-memory process tree (TTL'd)                    │   │
│  │   - Scoring rules + chain detection                          │   │
│  │   - Persists to SQLite                                       │   │
│  │   - Exposes HTTP API + SSE stream on :8080                   │   │
│  └────────────────────────────┬─────────────────────────────────┘   │
│                               │                                     │
│                               ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                 SQLite (events.db)                           │   │
│  │   tables: events, alerts, processes                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTP + SSE
                                 ▼
                  ┌─────────────────────────────────┐
                  │  Browser UI (single HTML page)  │
                  │   - Live event feed             │
                  │   - Alert list (severity sort)  │
                  │   - Process tree drilldown      │
                  └─────────────────────────────────┘
```

---

## Prerequisites

**Hardware / VM:**
- Linux VM with **kernel ≥ 5.15** (Ubuntu 22.04 LTS or 24.04 LTS recommended)
- 4 vCPU, 8 GB RAM, 40 GB disk
- Root or sudo access
- Internet connectivity

**Why these versions:** Tetragon needs BTF (BPF Type Format) shipped in the kernel, ring buffers (5.8+), and modern kprobe support. Ubuntu 22.04 ships with kernel 5.15+ and BTF enabled — don't fight this.

**You'll install during Day 1:**
Docker, Go 1.22+, the `tetra` CLI, and pull the Tetragon container image. Standard tools (`git`, `curl`, `make`, `jq`) come from `apt`.

---

## Day 1 — Foundation: Get Kernel Events Flowing

**Goal by EOD:** Tetragon is running, you can see real kernel events streaming when you run commands on the host.

**Time budget:** 6 hours. If you're stuck past 4 hours on installation, jump to the Troubleshooting section.

### 1.1 Provision and prepare the VM

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl make jq build-essential

# Verify kernel and BTF (must both succeed)
uname -r
ls -la /sys/kernel/btf/vmlinux
```

### 1.2 Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
docker run --rm hello-world  # sanity check
```

### 1.3 Install Go

```bash
GO_VERSION=1.22.5
curl -LO https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### 1.4 Run Tetragon in host mode

We're running Tetragon directly on the host as a Docker container — no Kubernetes. This is the fastest path for a PoC.

```bash
sudo mkdir -p /var/run/tetragon

docker run -d --name tetragon \
  --pid=host \
  --cgroupns=host \
  --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  -v /var/run/tetragon:/var/run/tetragon \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -v /proc:/procRoot \
  --restart unless-stopped \
  quay.io/cilium/tetragon:latest \
  /usr/bin/tetragon \
  --bpf-lib /var/lib/tetragon/ \
  --export-filename /var/log/tetragon/tetragon.log \
  --server-address unix:///var/run/tetragon/tetragon.sock \
  --enable-process-cred \
  --enable-process-ns

# Verify
docker ps | grep tetragon
docker logs tetragon | tail -30
```

You should see log lines indicating BPF programs loaded successfully. If you see verifier errors, check the Troubleshooting section.

### 1.5 Install the `tetra` CLI

```bash
TETRA_VERSION=v1.1.2  # check https://github.com/cilium/tetragon/releases for latest
curl -L https://github.com/cilium/tetragon/releases/download/${TETRA_VERSION}/tetra-linux-amd64.tar.gz | tar -xz
sudo mv tetra /usr/local/bin/
tetra version
```

### 1.6 Watch live kernel events

In one terminal, start streaming events:

```bash
sudo tetra getevents -o compact --server-address unix:///var/run/tetragon/tetragon.sock
```

In another terminal:

```bash
ls /tmp
cat /etc/hostname
```

You should see `process_exec` events for `ls` and `cat` appear in the first terminal in real time.

### 1.7 Day 1 EOD checklist

- [ ] Kernel ≥ 5.15 confirmed
- [ ] `/sys/kernel/btf/vmlinux` exists
- [ ] Docker installed and working
- [ ] Go installed (`go version` shows 1.22+)
- [ ] Tetragon container running
- [ ] `tetra getevents` shows live `process_exec` events when you run commands
- [ ] You've read at least one TracingPolicy from [the Tetragon examples](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)

---

## Day 2 — Detection Policies

**Goal by EOD:** Four working TracingPolicies, each tested and triggering correctly on simulated bad behavior, not triggering on normal activity.

**Time budget:** 7 hours. Most of this is iteration on YAML — the syntax has a learning curve.

```bash
mkdir -p ~/ebpf-poc/policies
cd ~/ebpf-poc/policies
```

### 2.1 Policy 1: Suspicious process execution

Process exec events come for free with Tetragon (we enabled `--enable-process-cred`). No TracingPolicy needed — Tetragon emits `process_exec` events for every `execve` automatically, with full ancestry. We'll handle the *suspicious-chain* logic in the correlation engine on Day 3.

Verify now:

```bash
bash -c 'wget -q -O - https://example.com | head -5'
```

You should see `process_exec` events showing `bash` → `wget` with parent linkage.

### 2.2 Policy 2: Privilege escalation watch

Save as `policies/privilege-escalation.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "privilege-escalation"
spec:
  kprobes:
    - call: "__x64_sys_setuid"
      syscall: true
      args:
        - index: 0
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "0"
    - call: "__x64_sys_setreuid"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "int"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Equal"
              values:
                - "0"
```

Apply and test:

```bash
docker cp policies/privilege-escalation.yaml tetragon:/tmp/
docker exec tetragon tetra tracingpolicy add /tmp/privilege-escalation.yaml

# In another terminal:
sudo -i
```

You should see a `process_kprobe` event with function `__x64_sys_setuid` or `__x64_sys_setreuid`.

### 2.3 Policy 3: Sensitive file access

Save as `policies/sensitive-files.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sensitive-file-access"
spec:
  kprobes:
    - call: "security_file_permission"
      syscall: false
      return: true
      args:
        - index: 0
          type: "file"
        - index: 1
          type: "int"
      returnArg:
        index: 0
        type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
                - "/etc/sudoers"
                - "/root/.ssh/"
                - "/home/"
            - index: 1
              operator: "Mask"
              values:
                - "2"   # MAY_WRITE
                - "4"   # MAY_READ
          matchActions:
            - action: Post
```

We hook `security_file_permission` (the LSM hook called for every file access permission check) rather than `open` directly — this catches all access paths and is more reliable than syscall hooks for files.

Apply and test:

```bash
docker cp policies/sensitive-files.yaml tetragon:/tmp/
docker exec tetragon tetra tracingpolicy add /tmp/sensitive-files.yaml

sudo cat /etc/shadow > /dev/null
```

You should see a `process_kprobe` event for `security_file_permission` with the matched file path.

### 2.4 Policy 4: Suspicious network connections

Save as `policies/network-watch.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "outbound-connections"
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                - "/usr/bin/bash"
                - "/bin/bash"
                - "/usr/bin/sh"
                - "/bin/sh"
                - "/usr/bin/zsh"
                - "/usr/bin/dash"
                - "/usr/bin/nc"
                - "/usr/bin/ncat"
                - "/usr/bin/socat"
          matchActions:
            - action: Post
```

The `matchBinaries` selector means this policy only fires when the calling process is one of those shells/network tools — keeping the noise floor low. Normal `tcp_connect` from `curl`, `apt`, `chrome` etc. is filtered at the kernel level (the eBPF program drops it before sending to userspace).

Apply and test:

```bash
docker cp policies/network-watch.yaml tetragon:/tmp/
docker exec tetragon tetra tracingpolicy add /tmp/network-watch.yaml

bash -c 'exec 3<>/dev/tcp/example.com/80; echo "GET / HTTP/1.0" >&3'
```

### 2.5 List active policies

```bash
docker exec tetragon tetra tracingpolicy list
```

### 2.6 Day 2 EOD checklist

- `process_exec` events visible without any custom policy
- `privilege-escalation` policy applied; triggers on `sudo -i`
- `sensitive-file-access` policy applied; triggers on `cat /etc/shadow`
- `outbound-connections` policy applied; triggers on bash opening a TCP socket
- All three custom policies show in `tetra tracingpolicy list`
- Manually verified each fires on its trigger and stays quiet on normal activity

---

## Day 3 — Correlation & Scoring Engine

**Goal by EOD:** A Go service subscribed to Tetragon's gRPC stream, maintaining a process tree, scoring event chains, persisting to SQLite, and emitting alerts.

**Time budget:** 8 hours. The biggest day.

### 3.1 Project setup

```bash
cd ~/ebpf-poc
mkdir -p engine/{cmd,internal}
cd engine
go mod init github.com/yourname/ebpf-poc-engine

go get github.com/cilium/tetragon/api/v1/tetragon@latest
go get google.golang.org/grpc@latest
go get modernc.org/sqlite@latest   # pure-Go SQLite driver, no CGO
```

Final layout:

```
engine/
├── cmd/
│   └── engine/
│       └── main.go
├── internal/
│   ├── store/
│   │   └── sqlite.go
│   ├── tree/
│   │   └── processtree.go
│   ├── score/
│   │   └── scorer.go
│   └── api/
│       ├── http.go
│       └── index.go
├── go.mod
└── go.sum
```

### 3.2 SQLite store (`internal/store/sqlite.go`)

```go
package store

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
)

type Event struct {
	ID         int64
	Timestamp  time.Time
	EventType  string
	PID        uint32
	ParentPID  uint32
	ExecID     string
	Binary     string
	Args       string
	UID        uint32
	PolicyName string
	RawJSON    string
}

type Alert struct {
	ID          int64
	Timestamp   time.Time
	Severity    string
	Title       string
	Description string
	ExecID      string
	Score       int
	EventIDs    []int64
}

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		event_type TEXT NOT NULL,
		pid INTEGER,
		parent_pid INTEGER,
		exec_id TEXT,
		binary TEXT,
		args TEXT,
		uid INTEGER,
		policy_name TEXT,
		raw_json TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_exec_id ON events(exec_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);

	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		exec_id TEXT,
		score INTEGER,
		event_ids TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) InsertEvent(e *Event) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO events
		(timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.EventType, e.PID, e.ParentPID, e.ExecID,
		e.Binary, e.Args, e.UID, e.PolicyName, e.RawJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) InsertAlert(a *Alert) (int64, error) {
	idsJSON, _ := json.Marshal(a.EventIDs)
	res, err := s.db.Exec(`
		INSERT INTO alerts (timestamp, severity, title, description, exec_id, score, event_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.Severity, a.Title, a.Description, a.ExecID, a.Score, string(idsJSON))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name
		FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.PID, &e.ParentPID,
			&e.ExecID, &e.Binary, &e.Args, &e.UID, &e.PolicyName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) RecentAlerts(limit int) ([]Alert, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, severity, title, description, exec_id, score, event_ids
		FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var idsJSON string
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Severity, &a.Title, &a.Description,
			&a.ExecID, &a.Score, &idsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &a.EventIDs)
		out = append(out, a)
	}
	return out, nil
}

func (s *Store) EventsByExecID(execID string) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name
		FROM events WHERE exec_id = ? ORDER BY id ASC`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.PID, &e.ParentPID,
			&e.ExecID, &e.Binary, &e.Args, &e.UID, &e.PolicyName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
```

### 3.3 Process tree (`internal/tree/processtree.go`)

```go
package tree

import (
	"sync"
	"time"
)

type Node struct {
	ExecID    string
	PID       uint32
	ParentID  string
	Binary    string
	Args      string
	UID       uint32
	StartTime time.Time
	Score     int
	Events    []string
}

type Tree struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	ttl   time.Duration
}

func New(ttl time.Duration) *Tree {
	t := &Tree{
		nodes: make(map[string]*Node),
		ttl:   ttl,
	}
	go t.gcLoop()
	return t
}

func (t *Tree) Add(n *Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[n.ExecID] = n
}

func (t *Tree) Get(execID string) (*Node, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n, ok := t.nodes[execID]
	return n, ok
}

func (t *Tree) AddScore(execID string, delta int, eventType string) (*Node, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.nodes[execID]
	if !ok {
		return nil, false
	}
	n.Score += delta
	n.Events = append(n.Events, eventType)
	return n, true
}

func (t *Tree) Ancestors(execID string, max int) []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var chain []*Node
	cur := execID
	for i := 0; i < max; i++ {
		n, ok := t.nodes[cur]
		if !ok {
			break
		}
		chain = append([]*Node{n}, chain...)
		if n.ParentID == "" {
			break
		}
		cur = n.ParentID
	}
	return chain
}

func (t *Tree) ChainScore(execID string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	score := 0
	cur := execID
	for i := 0; i < 10; i++ {
		n, ok := t.nodes[cur]
		if !ok {
			break
		}
		score += n.Score
		if n.ParentID == "" {
			break
		}
		cur = n.ParentID
	}
	return score
}

func (t *Tree) gcLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		t.gc()
	}
}

func (t *Tree) gc() {
	cutoff := time.Now().Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, n := range t.nodes {
		if n.StartTime.Before(cutoff) {
			delete(t.nodes, k)
		}
	}
}
```

### 3.4 Scoring engine (`internal/score/scorer.go`)

This is the heart of "proactive" detection: simple per-event rules with chain logic for combinations.

```go
package score

import (
	"strings"
)

func Score(eventType, binary, args, policyName string, uid uint32) (int, string) {
	switch eventType {
	case "process_exec":
		return scoreExec(binary, args, uid)
	case "process_kprobe":
		return scoreKprobe(policyName, args)
	}
	return 0, ""
}

func scoreExec(binary, args string, uid uint32) (int, string) {
	bin := strings.ToLower(binary)

	suspiciousDownloaders := []string{"wget", "curl"}
	for _, s := range suspiciousDownloaders {
		if strings.Contains(bin, s) {
			lower := strings.ToLower(args)
			if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
				strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
				return 25, "Pipe to shell from downloader (curl|sh pattern)"
			}
			return 3, "Network downloader executed"
		}
	}

	reverseShellTools := []string{"nc", "ncat", "socat"}
	for _, s := range reverseShellTools {
		if strings.HasSuffix(bin, "/"+s) || bin == s {
			if strings.Contains(args, "-e") || strings.Contains(args, "/bin/") {
				return 20, "Reverse shell tool with -e or shell argument"
			}
			return 5, "Network tool executed"
		}
	}

	if strings.Contains(strings.ToLower(args), "base64") &&
		(strings.Contains(args, "-d") || strings.Contains(args, "--decode")) {
		return 15, "Base64 decode in command line"
	}

	if (strings.HasSuffix(bin, "/bash") || strings.HasSuffix(bin, "/sh")) &&
		strings.Contains(args, "-c") {
		return 1, "Shell -c invocation"
	}

	if strings.HasSuffix(bin, "/chmod") && strings.Contains(args, "+x") {
		return 5, "Made file executable"
	}

	return 0, ""
}

func scoreKprobe(policyName, args string) (int, string) {
	switch policyName {
	case "privilege-escalation":
		return 15, "Privilege escalation: setuid to root"
	case "sensitive-file-access":
		if strings.Contains(args, "/etc/shadow") || strings.Contains(args, "/.ssh/") {
			return 20, "Access to credential file: " + args
		}
		return 8, "Sensitive file accessed: " + args
	case "outbound-connections":
		return 12, "Shell or network tool made outbound connection"
	}
	return 0, ""
}

func Severity(score int) string {
	switch {
	case score >= 40:
		return "critical"
	case score >= 20:
		return "high"
	case score >= 10:
		return "medium"
	case score >= 5:
		return "low"
	}
	return "info"
}
```

**Why these scores?** Calibrated so that any single event on its own won't trigger an alert above "low" — it takes a *chain* (e.g., bash exec + curl download + chmod +x + outbound conn) to reach "high" or "critical". This is what makes detection proactive: an attacker is flagged as the behavior pattern emerges, before they finish.

### 3.5 Main service (`cmd/engine/main.go`)

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/yourname/ebpf-poc-engine/internal/api"
	"github.com/yourname/ebpf-poc-engine/internal/score"
	"github.com/yourname/ebpf-poc-engine/internal/store"
	"github.com/yourname/ebpf-poc-engine/internal/tree"
)

func main() {
	var (
		tetragonAddr = flag.String("tetragon", "unix:///var/run/tetragon/tetragon.sock", "Tetragon gRPC address")
		dbPath       = flag.String("db", "events.db", "SQLite database path")
		httpAddr     = flag.String("http", ":8080", "HTTP listen address")
	)
	flag.Parse()

	st, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	httpSrv := api.NewServer(st, pt, broadcast)
	go httpSrv.Start(*httpAddr)

	conn, err := grpc.Dial(*tetragonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial tetragon: %v", err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigC; log.Println("shutting down"); cancel() }()

	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		log.Fatalf("get events: %v", err)
	}

	log.Println("subscribed to Tetragon event stream")

	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Printf("stream closed: %v", err)
			return
		}
		handleEvent(resp, st, pt, broadcast)
	}
}

func handleEvent(resp *tetragon.GetEventsResponse, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	switch ev := resp.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		handleExec(ev.ProcessExec, st, pt, broadcast)
	case *tetragon.GetEventsResponse_ProcessKprobe:
		handleKprobe(ev.ProcessKprobe, st, pt, broadcast)
	case *tetragon.GetEventsResponse_ProcessExit:
		// no-op for PoC
	}
}

func handleExec(ev *tetragon.ProcessExec, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	if ev.Process == nil {
		return
	}
	p := ev.Process
	parentID := ""
	if ev.Parent != nil {
		parentID = ev.Parent.ExecId
	}
	node := &tree.Node{
		ExecID:    p.ExecId,
		PID:       p.Pid.GetValue(),
		ParentID:  parentID,
		Binary:    p.Binary,
		Args:      p.Arguments,
		UID:       p.Uid.GetValue(),
		StartTime: time.Now(),
	}
	pt.Add(node)

	delta, reason := score.Score("process_exec", p.Binary, p.Arguments, "", p.Uid.GetValue())
	if delta > 0 {
		pt.AddScore(p.ExecId, delta, "process_exec")
	}

	e := &store.Event{
		Timestamp: time.Now(),
		EventType: "process_exec",
		PID:       p.Pid.GetValue(),
		ExecID:    p.ExecId,
		Binary:    p.Binary,
		Args:      p.Arguments,
		UID:       p.Uid.GetValue(),
	}
	id, err := st.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	broadcast <- api.Broadcast{Type: "event", Payload: e}
	checkAlert(p.ExecId, st, pt, broadcast, reason)
}

func handleKprobe(ev *tetragon.ProcessKprobe, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	if ev.Process == nil {
		return
	}
	p := ev.Process
	policyName := ev.PolicyName

	argStr := ""
	for _, a := range ev.Args {
		if fileArg := a.GetFileArg(); fileArg != nil {
			argStr += fileArg.Path + " "
		}
		if intArg := a.GetIntArg(); intArg != 0 {
			argStr += fmt.Sprintf("%d ", intArg)
		}
	}
	argStr = strings.TrimSpace(argStr)

	delta, reason := score.Score("process_kprobe", p.Binary, argStr, policyName, p.Uid.GetValue())
	if delta > 0 {
		pt.AddScore(p.ExecId, delta, "process_kprobe:"+policyName)
	}

	e := &store.Event{
		Timestamp:  time.Now(),
		EventType:  "process_kprobe",
		PID:        p.Pid.GetValue(),
		ExecID:     p.ExecId,
		Binary:     p.Binary,
		Args:       argStr,
		UID:        p.Uid.GetValue(),
		PolicyName: policyName,
	}
	id, err := st.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	broadcast <- api.Broadcast{Type: "event", Payload: e}
	checkAlert(p.ExecId, st, pt, broadcast, reason)
}

func checkAlert(execID string, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast, reason string) {
	chainScore := pt.ChainScore(execID)
	if chainScore < 10 {
		return
	}
	severity := score.Severity(chainScore)
	chain := pt.Ancestors(execID, 8)
	var binaries []string
	for _, n := range chain {
		binaries = append(binaries, n.Binary)
	}
	title := fmt.Sprintf("Suspicious chain: %s (score %d)", strings.Join(binaries, " → "), chainScore)
	a := &store.Alert{
		Timestamp:   time.Now(),
		Severity:    severity,
		Title:       title,
		Description: reason,
		ExecID:      execID,
		Score:       chainScore,
	}
	id, err := st.InsertAlert(a)
	if err != nil {
		log.Printf("insert alert: %v", err)
		return
	}
	a.ID = id
	broadcast <- api.Broadcast{Type: "alert", Payload: a}
	log.Printf("[ALERT %s] %s", severity, title)
}
```

### 3.6 HTTP API skeleton (`internal/api/http.go`)

Stub for Day 3 — fleshed out tomorrow:

```go
package api

import (
	"github.com/yourname/ebpf-poc-engine/internal/store"
	"github.com/yourname/ebpf-poc-engine/internal/tree"
)

type Broadcast struct {
	Type    string
	Payload interface{}
}

type Server struct {
	store     *store.Store
	tree      *tree.Tree
	broadcast <-chan Broadcast
}

func NewServer(st *store.Store, pt *tree.Tree, broadcast <-chan Broadcast) *Server {
	return &Server{store: st, tree: pt, broadcast: broadcast}
}

func (s *Server) Start(addr string) error {
	for range s.broadcast {
		// drain so the channel doesn't block
	}
	return nil
}
```

### 3.7 Build and run

```bash
cd ~/ebpf-poc/engine
go build -o engine ./cmd/engine
sudo ./engine -tetragon unix:///var/run/tetragon/tetragon.sock -db events.db
```

Trigger activity in another terminal:

```bash
sudo cat /etc/shadow > /dev/null
sudo -i
exit
```

You should see `[ALERT high]` lines in the engine log when the chain score crosses the threshold.

```bash
sqlite3 ~/ebpf-poc/engine/events.db "SELECT id, severity, title FROM alerts ORDER BY id DESC LIMIT 5;"
```

### 3.8 Day 3 EOD checklist

- [ ] `go build` succeeds with no errors
- [ ] Engine runs and connects to Tetragon's gRPC socket
- [ ] Events visible in `events.db` via `sqlite3` query
- [ ] Running `sudo cat /etc/shadow` produces an alert in the `alerts` table
- [ ] Alert log lines appear on the engine's stdout
- [ ] Process tree handles parent-child linkage correctly

---

## Day 4 — Visibility UI

**Goal by EOD:** Browser-based UI showing live events, alerts (severity-sorted), and process-tree drilldown.

**Time budget:** 6 hours.

### 4.1 Replace `internal/api/http.go` with the real implementation

```go
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/yourname/ebpf-poc-engine/internal/store"
	"github.com/yourname/ebpf-poc-engine/internal/tree"
)

type Broadcast struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Server struct {
	store     *store.Store
	tree      *tree.Tree
	broadcast <-chan Broadcast

	subsMu sync.Mutex
	subs   map[chan Broadcast]struct{}
}

func NewServer(st *store.Store, pt *tree.Tree, broadcast <-chan Broadcast) *Server {
	return &Server{
		store:     st,
		tree:      pt,
		broadcast: broadcast,
		subs:      make(map[chan Broadcast]struct{}),
	}
}

func (s *Server) Start(addr string) error {
	go s.fanout()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/process/", s.handleProcess)
	mux.HandleFunc("/api/stream", s.handleSSE)
	log.Printf("HTTP listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) fanout() {
	for b := range s.broadcast {
		s.subsMu.Lock()
		for ch := range s.subs {
			select {
			case ch <- b:
			default:
			}
		}
		s.subsMu.Unlock()
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, indexHTML)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.RecentEvents(200)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.store.RecentAlerts(100)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, alerts)
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	execID := r.URL.Path[len("/api/process/"):]
	chain := s.tree.Ancestors(execID, 10)
	events, _ := s.store.EventsByExecID(execID)
	writeJSON(w, map[string]interface{}{
		"chain":  chain,
		"events": events,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}

	ch := make(chan Broadcast, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		close(ch)
		s.subsMu.Unlock()
	}()

	ctx := r.Context()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case b := <-ch:
			data, _ := json.Marshal(b)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
```

### 4.2 Embedded HTML UI (`internal/api/index.go`)

```go
package api

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>eBPF Threat Observability — Live</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .sev-critical { background: #7f1d1d; color: white; }
  .sev-high { background: #b45309; color: white; }
  .sev-medium { background: #ca8a04; color: white; }
  .sev-low { background: #1e40af; color: white; }
  .sev-info { background: #4b5563; color: white; }
  pre { white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body class="bg-slate-100 text-slate-900">
<div class="max-w-7xl mx-auto p-6">
  <header class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold">eBPF Threat Observability</h1>
    <div id="status" class="text-sm text-slate-500">connecting…</div>
  </header>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <section class="lg:col-span-1 bg-white rounded-lg shadow p-4">
      <h2 class="font-semibold mb-3">Alerts</h2>
      <div id="alerts" class="space-y-2 max-h-[70vh] overflow-y-auto"></div>
    </section>

    <section class="lg:col-span-2 bg-white rounded-lg shadow p-4">
      <h2 class="font-semibold mb-3">Live Events</h2>
      <div id="events" class="text-xs font-mono space-y-1 max-h-[70vh] overflow-y-auto"></div>
    </section>
  </div>

  <section id="drilldown" class="hidden mt-6 bg-white rounded-lg shadow p-4">
    <div class="flex justify-between items-center mb-3">
      <h2 class="font-semibold">Process Chain</h2>
      <button onclick="closeDrilldown()" class="text-sm text-slate-500">close</button>
    </div>
    <div id="drilldown-body"></div>
  </section>
</div>

<script>
const alertsEl = document.getElementById('alerts');
const eventsEl = document.getElementById('events');
const statusEl = document.getElementById('status');

function severityClass(s) { return 'sev-' + s; }
function fmtTime(t) { return new Date(t).toLocaleTimeString(); }

function renderAlert(a) {
  const div = document.createElement('div');
  div.className = 'p-2 rounded cursor-pointer ' + severityClass(a.Severity || a.severity);
  const sev = (a.Severity || a.severity || 'info').toUpperCase();
  const title = a.Title || a.title;
  const ts = fmtTime(a.Timestamp || a.timestamp);
  const score = a.Score || a.score;
  div.innerHTML = '<div class="flex justify-between text-xs opacity-90"><span>' + sev + '</span><span>' + ts + '</span></div>' +
                  '<div class="font-semibold mt-1">' + title + '</div>' +
                  '<div class="text-xs mt-1">score: ' + score + '</div>';
  div.onclick = () => openDrilldown(a.ExecID || a.exec_id);
  return div;
}

function renderEvent(e) {
  const div = document.createElement('div');
  const ts = fmtTime(e.Timestamp || e.timestamp);
  const type = (e.EventType || e.event_type || '').padEnd(15);
  const bin = e.Binary || e.binary || '';
  const args = e.Args || e.args || '';
  const policy = e.PolicyName || e.policy_name || '';
  div.className = 'border-b border-slate-100 py-1';
  div.textContent = ts + ' | ' + type + ' | ' + bin + ' ' + args + (policy ? ' [' + policy + ']' : '');
  div.style.cursor = 'pointer';
  div.onclick = () => openDrilldown(e.ExecID || e.exec_id);
  return div;
}

function prepend(container, node, max) {
  container.prepend(node);
  while (container.children.length > max) container.removeChild(container.lastChild);
}

async function loadInitial() {
  const [aRes, eRes] = await Promise.all([fetch('/api/alerts'), fetch('/api/events')]);
  const alerts = await aRes.json();
  const events = await eRes.json();
  alertsEl.innerHTML = '';
  eventsEl.innerHTML = '';
  (alerts || []).forEach(a => alertsEl.appendChild(renderAlert(a)));
  (events || []).forEach(e => eventsEl.appendChild(renderEvent(e)));
}

async function openDrilldown(execID) {
  if (!execID) return;
  const res = await fetch('/api/process/' + encodeURIComponent(execID));
  const data = await res.json();
  const body = document.getElementById('drilldown-body');
  let html = '<div class="text-sm text-slate-500 mb-2">exec_id: ' + execID + '</div>';
  html += '<div class="mb-3"><div class="font-semibold mb-1">Ancestor chain</div><pre class="bg-slate-50 p-2 rounded text-xs">';
  (data.chain || []).forEach((n, i) => {
    html += '  '.repeat(i) + '└ ' + n.Binary + ' ' + (n.Args || '') + '  (pid=' + n.PID + ', uid=' + n.UID + ', score=' + n.Score + ')\n';
  });
  html += '</pre></div>';
  html += '<div><div class="font-semibold mb-1">Events for this process</div><pre class="bg-slate-50 p-2 rounded text-xs">';
  (data.events || []).forEach(e => {
    html += fmtTime(e.Timestamp) + '  ' + e.EventType + '  ' + (e.PolicyName || '') + '  ' + (e.Args || '') + '\n';
  });
  html += '</pre></div>';
  body.innerHTML = html;
  document.getElementById('drilldown').classList.remove('hidden');
  document.getElementById('drilldown').scrollIntoView({behavior: 'smooth'});
}
function closeDrilldown() { document.getElementById('drilldown').classList.add('hidden'); }

function connect() {
  const es = new EventSource('/api/stream');
  es.onopen = () => statusEl.textContent = '● connected';
  es.onerror = () => statusEl.textContent = '✕ disconnected';
  es.onmessage = (msg) => {
    try {
      const b = JSON.parse(msg.data);
      if (b.type === 'event') prepend(eventsEl, renderEvent(b.payload), 200);
      if (b.type === 'alert') prepend(alertsEl, renderAlert(b.payload), 100);
    } catch (e) { console.error(e); }
  };
}

loadInitial().then(connect);
</script>
</body>
</html>
`
```

### 4.3 Rebuild and run

```bash
cd ~/ebpf-poc/engine
go build -o engine ./cmd/engine
sudo ./engine -http :8080
```

Open `http://<vm-ip>:8080` in your browser. Trigger events and watch them stream in real time.

### 4.4 Day 4 EOD checklist

- UI loads at `http://<host>:8080`
- Live event feed updates within ~1 second of activity
- Alerts appear with correct severity colors
- Clicking an alert opens drilldown showing ancestor chain
- Drilldown shows all events for the selected process

---

## Day 5 — Attack Simulation, Validation, Demo

**Goal by EOD:** Three scripted attack scenarios that demonstrably trigger alerts; recorded demo; clean README.

**Time budget:** 5–6 hours.

### 5.1 Attack scenario scripts

A complete set of six attack-simulation scripts is provided separately in `attacks/` (covering execution, credential access, C2, privilege escalation, LOLBins, and persistence). Drop them into `~/ebpf-poc/attacks/` and `chmod +x *.sh`.

Quick reference — what each one tests:

| Script | Triggers | Expected severity |
|---|---|---|
| `01-webshell.sh` | exec(curl) + chmod +x + cat /etc/shadow | HIGH/CRITICAL |
| `02-credential-theft.sh` | sensitive-file-access on `~/.ssh/`, shadow, sudoers | HIGH |
| `03-reverse-shell.sh` | outbound-connections kprobe from bash | MEDIUM/HIGH |
| `04-privilege-escalation.sh` | setuid kprobe + multiple root execs | HIGH |
| `05-living-off-the-land.sh` | curl \| sh + base64 patterns | CRITICAL |
| `06-persistence.sh` | chmod +x + dotfile recon | MEDIUM |

### 5.2 Validation matrix

For each scenario:

1. Run the script
2. Check the UI — alert should appear within 2 seconds
3. Click the alert and verify the process chain reconstructs the attack
4. Confirm severity and score look right

If any scenario doesn't trigger as expected:
- Is the relevant TracingPolicy active? `docker exec tetragon tetra tracingpolicy list`
- Are events showing in the engine logs?
- Does the score in `internal/score/scorer.go` add up to the threshold?

Tune the scoring rules until each scenario triggers with appropriate severity. **This is the most important hour of Day 5.**

### 5.3 Recording the demo

Use [asciinema](https://asciinema.org/) for terminal demos or any screen recorder for the UI:

```bash
sudo apt install -y asciinema
asciinema rec demo.cast
```

Demo script (3 minutes):

1. **0:00 – 0:30** — Architecture overview, point at the running Tetragon container and engine
2. **0:30 – 1:30** — Run `attacks/01-webshell.sh` while showing the UI; alert appears, click into drilldown to show process chain
3. **1:30 – 2:15** — Run `attacks/02-credential-theft.sh`; show how multiple events compound into one high-severity alert
4. **2:15 – 3:00** — Run `attacks/03-reverse-shell.sh`; show network event, drilldown to parent shell

The narrative point: *the alert fired while the attack was unfolding, before the script finished*. That's the proactive value.

### 5.4 README

Create `~/ebpf-poc/README.md` summarizing what the PoC is, how to run it, the architecture, honest limitations, and what's next.

### 5.5 Day 5 EOD checklist

- All six attack scripts trigger alerts of expected severity
- Process chain drilldown shows the full attack sequence for each scenario
- Demo recording captures the "alert fires while attack is in progress" moment
- README is written with honest limitations section
- Code is in a git repo with a clean commit history
- You can hand the PoC to someone else and they can run it from the README in under 10 minutes

---

## Troubleshooting

**Tetragon container won't start:**
- Check `docker logs tetragon`
- Most common: missing BTF. Verify `/sys/kernel/btf/vmlinux` exists on the host.
- Second most common: cgroup v1 vs v2 issues. Ubuntu 22.04+ uses cgroup v2 by default; older systems may need additional mounts.

**TracingPolicy applied but doesn't fire:**
- Check the kprobe symbol exists: `sudo cat /proc/kallsyms | grep <symbol>`
- Some kernels prefix syscalls with `__x64_sys_` (x86_64). On ARM64 it's `__arm64_sys_`. Adjust accordingly.
- LSM hooks (`security_*`) require the kernel to be built with the BPF LSM enabled. Ubuntu 22.04 has it on by default.

**`go build` fails on tetragon import:**
- The Tetragon Go API moves quickly. Pin to a specific version: `go get github.com/cilium/tetragon/api/v1/tetragon@v1.1.2` (or whatever current release is).
- Some types/methods may have been renamed; cross-reference with [the api proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/events.proto).

**Engine connects but no events arrive:**
- Verify Tetragon socket exists: `ls -la /var/run/tetragon/tetragon.sock`
- Test directly: `sudo tetra getevents` should show events. If empty, Tetragon itself isn't seeing kernel events — check Tetragon logs.
- If events flow to `tetra` but not your engine, you may have a gRPC version skew.

**UI loads but no live updates:**
- Check browser dev tools → Network → `/api/stream` should show as pending (it's a long-lived SSE connection).
- Some corporate proxies break SSE. Test with a direct connection.
- Check that the broadcast channel isn't blocked.

**Alerts not firing for an attack scenario:**
- Confirm the chain score reaches the threshold. Add a log line in `checkAlert` printing the score every event.
- Process tree TTL (10 min) should be plenty, but if events are old, they may have been GC'd.
- The `Ancestors` walk depends on `parent.exec_id` being set — verify Tetragon is sending it in `process_exec` events.

**"Verifier rejected program" errors in Tetragon logs:**
- Almost always a kernel-version-vs-policy-syntax issue. Simplify the policy.
- The verifier is strict; complex match conditions can hit complexity limits. Break one large policy into multiple smaller ones.

---

## References

**Stack documentation:**
- [Tetragon docs](https://tetragon.io/) — primary framework
- [TracingPolicy reference](https://tetragon.io/docs/concepts/tracing-policy/) — detection rules
- [Tetragon Go API](https://pkg.go.dev/github.com/cilium/tetragon/api/v1/tetragon) — gRPC client
- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — pure-Go SQLite
- [Example TracingPolicies](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)

**eBPF & kernel:**
- [eBPF.io documentation](https://ebpf.io/what-is-ebpf/)
- [Cilium BPF reference guide](https://docs.cilium.io/en/stable/bpf/)
- [bpftrace one-liners](https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md) — useful for ad-hoc verification

**Threat detection theory:**
- [MITRE ATT&CK](https://attack.mitre.org/) — taxonomy of attacker behaviors
- [Sigma rules](https://github.com/SigmaHQ/sigma) — open detection rules; many translate well to TracingPolicies

**For going beyond the PoC:**
- Tetragon's enforcement actions (`SIGKILL`, `Override`) — turn this into a prevention tool
- [BTFHub](https://github.com/aquasecurity/btfhub) — extend kernel support back to ~4.18
- [OCSF schema](https://schema.ocsf.io/) — when you're ready to normalize events

---

*Built in 5 days on a boring stack. Production-ready in 5 months on the same one.*
