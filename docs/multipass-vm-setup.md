# Board demo: tear-down + fresh VM end-to-end

End-to-end recipe to delete the existing `ebpf` VM and bring a new one all
the way up to a running engine ready for a live presentation. All blocks
run from your **macOS host** — no need to shell into the VM.

Total time from step 1 to a usable dashboard: ~5–8 min (image download +
`setup.sh` dominate).

## 1. Tear down the current VM

```bash
multipass list
multipass stop ebpf
multipass delete ebpf
multipass purge
```

## 2. Launch a fresh VM

```bash
multipass launch 22.04 --name ebpf --cpus 2 --memory 4G --disk 20G
multipass info ebpf
```

Wait ~30s after launch for cloud-init to finish before the next step.

## 3. Build & transfer the bundle (from repo root)

```bash
make tarball
multipass transfer ebpf-poc-amd64.tar.gz ebpf:/home/ubuntu/
```

## 4. Extract & install dependencies (Docker, Go, Tetragon, tetra)

```bash
multipass exec ebpf -- bash -c '
  mkdir -p /home/ubuntu/ebpf-poc &&
  tar -xzf /home/ubuntu/ebpf-poc-amd64.tar.gz -C /home/ubuntu/ebpf-poc &&
  cd /home/ubuntu/ebpf-poc &&
  TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
'
```

## 5. Apply TracingPolicies into the kernel

```bash
multipass exec ebpf -- sudo make -C /home/ubuntu/ebpf-poc policies-apply
```

Should print three policies `enabled`: `outbound-connections`,
`privilege-escalation`, `sensitive-file-access`.

## 6. Create engine data dir

```bash
multipass exec ebpf -- sudo mkdir -p /var/lib/ebpf-engine
```

## 7. Start the engine as a transient systemd unit (board-demo grade)

Idempotent — safe to re-run on a fresh VM, on a VM with a stuck `nohup`
engine, or on a VM where the systemd unit already exists. The first three
lines clear any prior state; `systemd-run` then registers the engine
fresh.

```bash
multipass exec ebpf -- sudo systemctl stop ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo systemctl reset-failed ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo pkill -f engine-linux-amd64 || true
sleep 2
multipass exec ebpf -- sudo systemd-run \
  --unit=ebpf-engine \
  --description="eBPF SOC engine (transient, board demo)" \
  --property=Restart=always \
  --property=RestartSec=2 \
  --property=StandardOutput=append:/var/log/ebpf-engine.log \
  --property=StandardError=append:/var/log/ebpf-engine.log \
  --property=WorkingDirectory=/home/ubuntu/ebpf-poc \
  /home/ubuntu/ebpf-poc/engine/engine-linux-amd64 \
    -tetragon  unix:///var/run/tetragon/tetragon.sock \
    -db        /var/lib/ebpf-engine/events.db \
    -http      :8080 \
    -user      admin -pass ebpf-soc-demo \
    -policies  /home/ubuntu/ebpf-poc/policies \
    -attacks   /home/ubuntu/ebpf-poc/attacks \
    -honeypots /var/lib/ebpf-engine/honey
```

## 8. Verify everything is up

```bash
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp | grep 8080
multipass info ebpf | awk '/IPv4/{print $2}'   # → use this IP in the browser
```

## 9. Open the dashboard

Browser → `http://<vm-ip>:8080` · login **admin / ebpf-soc-demo**

## 10. Pre-demo: clean slate just before going on

```bash
# Mute MOTD-noise policies, wipe DB, restart engine, re-enable
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable privilege-escalation
multipass exec ebpf -- sudo systemctl stop ebpf-engine
multipass exec ebpf -- sudo rm -f /var/lib/ebpf-engine/events.db
multipass exec ebpf -- sudo systemctl start ebpf-engine
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable privilege-escalation
```

## 11. Live attack to fire alerts on stage

```bash
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/02-credential-theft.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/03-reverse-shell.sh
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/04-privilege-escalation.sh
```

## Operational helpers (anytime)

```bash
multipass exec ebpf -- sudo systemctl restart ebpf-engine          # restart
multipass exec ebpf -- sudo journalctl -u ebpf-engine -f           # live logs
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy list
multipass exec ebpf -- sudo tail -30 /var/log/ebpf-engine.log
```

## Build and deploy - Fix

```bash
make build-linux 2>&1 | tail -2 && \
multipass transfer engine/engine-linux-amd64 ebpf:/tmp/engine-new && \
multipass exec ebpf -- sudo mv /tmp/engine-new /home/ubuntu/ebpf-poc/engine/engine-linux-amd64 && \
multipass exec ebpf -- sudo chmod +x /home/ubuntu/ebpf-poc/engine/engine-linux-amd64 && \
multipass exec ebpf -- sudo systemctl restart ebpf-engine
sleep 5
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp 2>/dev/null | grep 8080
echo "---SERVED---"
VM=192.168.252.3
curl -sS -c /tmp/c.txt -o /dev/null -X POST -d 'user=admin&pass=ebpf-soc-demo' http://$VM:8080/api/login
curl -sS -b /tmp/c.txt http://$VM:8080/ | grep -cE "classifyAlert|classifyBinary|cls-attack|hideBaseline|BASELINE_ROOT_PATTERNS"
```



