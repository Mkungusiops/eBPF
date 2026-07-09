# Multipass VM setup (macOS host)

First-run guide to bring up a local Ubuntu Linux VM on macOS with Multipass
and get the engine running against **real kernel events** — the fastest way
to exercise the Choke Gateway without a cloud host. Every block runs from
your **macOS host** unless marked `[inside VM]`.

Once the VM exists, day-to-day operation lives in
[../operations/run-on-multipass-vm.md](../operations/run-on-multipass-vm.md);
demo-prep / clean-slate steps live in
[../operations/reset-engine-and-policies.md](../operations/reset-engine-and-policies.md).

## Prerequisites

- macOS with Homebrew
- ~5 GB free disk, ~4 GB free RAM
- Go 1.25+ and Node 18+ (to build the UI + cross-compile the Linux binary via `make`)

## 1. Install Multipass

```bash
brew install --cask multipass
multipass version
```

## 2. Launch the VM

Ubuntu 22.04+ gives you a kernel ≥ 5.15 with BTF, which Tetragon needs.

```bash
multipass launch 22.04 --name ebpf --cpus 2 --memory 4G --disk 20G
multipass info ebpf
```

Wait ~30 s after launch for cloud-init to finish before deploying.

## 3. Deploy — the fast path

From the repo root on the macOS host, one command builds the Linux binary,
syncs the bundle, runs `setup.sh` (Docker + Tetragon + cgroup v2), applies
every TracingPolicy, and starts the engine with the Choke Gateway enabled:

```bash
make deploy
```

It prints the dashboard URLs when it finishes:

```
 UI:            http://<vm-ip>:8080/
 Choke console: http://<vm-ip>:8080/choke
 login:         admin / ebpf-soc-demo
```

After the first `make deploy`, use `make redeploy` for fast iteration (skips
`setup.sh` and policy re-apply). See the Makefile's `deploy`/`redeploy`
targets — the long-form manual equivalent is documented step-by-step in
[../operations/run-on-multipass-vm.md](../operations/run-on-multipass-vm.md).

## 4. Verify

```bash
make vm-status                        # engine active? + cgroup tier counts
make vm-logs                          # tail engine logs (Ctrl-C to stop)
multipass info ebpf | awk '/IPv4/{print $2}'   # the IP to open in a browser
```

Open `http://<vm-ip>:8080/` and log in with `admin / ebpf-soc-demo`.

## 5. Fire an attack

```bash
make vm-attack SCRIPT=03-reverse-shell.sh
```

Watch the SOC dashboard fill and, on `/choke`, the process walk up the state
ladder (`pristine → throttled → tarpit → …`). The full attack matrix and the
enforcement-verification steps are in
[../operations/run-on-multipass-vm.md](../operations/run-on-multipass-vm.md).

## Tear down / rebuild

To start over from a clean VM:

```bash
multipass stop ebpf
multipass delete ebpf
multipass purge
```

Then repeat from step 2. If Multipass itself wedges (a known macOS
`multipassd` issue), `scripts/multipass-doctor.sh ebpf` — run automatically
by `make deploy` via the `vm-up` target — detects and recovers it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `multipass VM 'ebpf' not found` | Run step 2 to launch it. |
| `quay.io/cilium/tetragon:latest: not found` | The `:latest` tag is unpublished; the deploy pins `v1.6.1`. If running `setup.sh` by hand, set `TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1`. |
| Flood of `sshd → … → run-parts` critical alerts | Ubuntu's MOTD noise from each `multipass exec`, not a real attack — see [../operations/run-on-multipass-vm.md](../operations/run-on-multipass-vm.md#gotchas-weve-hit) and mute the policies via [../operations/reset-engine-and-policies.md](../operations/reset-engine-and-policies.md). |
| `The client is not authenticated with the Multipass service` | macOS auto-update desynced the client cert — recovery steps in [../operations/run-on-multipass-vm.md](../operations/run-on-multipass-vm.md#gotchas-weve-hit). |
</content>
