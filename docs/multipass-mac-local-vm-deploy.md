# Local VM deploy (macOS → Multipass)

End-to-end recipe for running the engine against **real kernel events** on a
local Ubuntu VM, no cloud needed. This is what `-fake` mode is *not*: events
flow from real `execve` / kprobe calls through Tetragon eBPF programs.

## Prerequisites

- macOS with Homebrew
- ~5 GB free disk, ~4 GB free RAM
- The repo's `ebpf-poc-amd64.tar.gz` (run `make tarball` if missing)

## 1. Install Multipass

```bash
brew install --cask multipass
```

The cask installer needs your sudo password (it ships a system daemon).
First `multipass version` call may take a few seconds while the daemon
generates its root cert.

## 2. Launch the VM

```bash
multipass launch 22.04 --name ebpf --cpus 2 --memory 4G --disk 20G
multipass info ebpf            # grab the IPv4 — you'll use it to open the UI
```

Image download is ~600 MB on first run; total ~2-3 min.

## 3. Transfer & extract the bundle

```bash
multipass transfer ebpf-poc-amd64.tar.gz ebpf:/home/ubuntu/
multipass exec ebpf -- bash -c '
  mkdir -p /home/ubuntu/ebpf-poc &&
  tar -xzf /home/ubuntu/ebpf-poc-amd64.tar.gz -C /home/ubuntu/ebpf-poc
'
```

The `LIBARCHIVE.xattr.com.apple.provenance` warnings are harmless — macOS
extended attributes that Linux `tar` doesn't recognize.

## 4. Run setup.sh

```bash
multipass exec ebpf -- bash -c '
  cd /home/ubuntu/ebpf-poc &&
  TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
'
```

Installs Docker, Go 1.22.5, the `tetra` CLI, pulls Tetragon, starts it
with `--privileged --pid=host`, and waits for the gRPC socket. Idempotent —
safe to re-run.

> **Why pin `TETRAGON_IMAGE`?** The script's default is
> `quay.io/cilium/tetragon:latest`, but Cilium no longer publishes a
> `:latest` tag on quay.io. Pin to a published tag (check
> <https://quay.io/repository/cilium/tetragon?tab=tags>). v1.6.1 is the
> latest stable as of this writing.

## 5. Apply TracingPolicies

```bash
multipass exec ebpf -- bash -c 'cd /home/ubuntu/ebpf-poc && sudo make policies-apply'
```

You should see three policies enabled:

```
ID   NAME                    STATE     SENSORS
1    outbound-connections    enabled   generic_kprobe
2    privilege-escalation    enabled   generic_kprobe
3    sensitive-file-access   enabled   generic_kprobe
```

These are now eBPF programs running in the kernel.

## 6. Start the engine

```bash
multipass exec ebpf -- bash -c '
  cd /home/ubuntu/ebpf-poc &&
  sudo nohup ./engine/engine-linux-amd64 \
    -tetragon unix:///var/run/tetragon/tetragon.sock \
    -db events.db -http :8080 \
    > engine.log 2>&1 & disown
'
```

Open the UI in your browser:

```
http://<vm-ip>:8080
```

(`multipass info ebpf` → `IPv4` line.)

## 7. Fire real attacks

Each script triggers actual syscalls — Tetragon kprobes catch them, the
engine builds a process tree, scores the chain, and pushes alerts via SSE.

```bash
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/01-webshell.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/02-credential-theft.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/03-reverse-shell.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/04-privilege-escalation.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/05-living-off-the-land.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/06-persistence.sh
```

## How to tell it's real (vs `-fake`)

| Signal             | Fake mode                        | Real mode                                       |
|--------------------|----------------------------------|-------------------------------------------------|
| `exec_id`          | `fake-bash-1`, `fake-curl-1`     | base64-encoded kernel ID (`ZmVhNj...`)          |
| PIDs               | `1000`, `2000`, `3000` (literals)| Real kernel-assigned PIDs                       |
| Process binary     | Synthesized from a static list   | Whatever actually ran on the VM                 |
| Outbound IPs       | Always `127.0.0.1:4444`          | Whatever the attack script connected to         |
| Timestamps         | Generator's wall-clock           | Same — but ordering is causally tied to syscalls |

Quick check via the API:

```bash
curl -sS http://<vm-ip>:8080/api/alerts | jq '.[0]'
```

Real `exec_id`s are long base64 strings. Fake ones start with `fake-`.

## Operational one-liners

| Goal                          | Command                                                                                |
|-------------------------------|----------------------------------------------------------------------------------------|
| Tail engine logs              | `multipass exec ebpf -- sudo tail -f /home/ubuntu/ebpf-poc/engine.log`                 |
| Tail raw Tetragon events      | `multipass exec ebpf -- sudo docker exec tetragon tetra getevents -o compact`          |
| Re-list active policies       | `multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy list`            |
| Restart Tetragon              | `multipass exec ebpf -- sudo docker restart tetragon`                                  |
| Kill engine                   | `multipass exec ebpf -- sudo pkill engine-linux-am`                                    |
| Stop the VM (preserves state) | `multipass stop ebpf`                                                                  |
| Resume the VM                 | `multipass start ebpf`                                                                 |
| Delete the VM entirely        | `multipass delete ebpf && multipass purge`                                             |

## Known gotchas

- **`tar` errors about `LIBARCHIVE.xattr.com.apple.provenance`** — harmless,
  just macOS xattrs the Linux `tar` doesn't understand. Files extract fine.
- **`quay.io/cilium/tetragon:latest: not found`** — the `:latest` tag isn't
  published. Pin to a versioned tag via `TETRAGON_IMAGE=...`.
- **`make tarball` failed before this doc was written** — the rule referenced
  `build.md` at the repo root, but it lives in `docs/build.md`. Fixed in the
  Makefile.
- **First `multipass exec` after launch hangs / SSH timeout** — cloud-init is
  still finishing. Wait ~20 s and retry.
- **Engine logs say "tetragon socket not ready"** — the Tetragon container
  takes a few seconds after `docker run` to bind the socket. The setup
  script waits for it, but if you start the engine yourself before that,
  retry once.
