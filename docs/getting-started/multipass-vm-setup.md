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
multipass delete --purge ebpf 2>&1 | tail -3; echo "---"; multipass list 2>&1 | head -10

# Stop engine before redeploy
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ubuntu@192.168.252.4 "sudo systemctl stop ebpf-engine; sudo systemctl reset-failed ebpf-engine; sudo pkill -f engine-linux-amd64; sleep 1; sudo ss -tlnp | grep ':8080' || echo 'port-free'" 2>&1; echo "exit=$?"

# Check engine state
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ubuntu@192.168.252.4 "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || echo 'port-free'" 2>&1; echo "exit=$?"

# Run deploy remote
make deploy-remote HOST=ubuntu@192.168.252.4 2>&1 | tail -40

# Run redeploy remote
make redeploy VM=ebpf
```



## 2. Re-apply policies and restart engine after VM reboot

```bash
multipass exec ebpf -- sudo make -C /home/ubuntu/ebpf-poc policies-apply 2>&1 | tail -10
echo "---START ENGINE---"
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
sleep 4
echo "---STATUS---"
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp 2>/dev/null | grep 8080
```

## 3. Launch a fresh VM

```bash
multipass launch 22.04 --name ebpf --cpus 2 --memory 4G --disk 20G
multipass info ebpf
```

Wait ~30s after launch for cloud-init to finish before the next step.

## 4. Build & transfer the bundle (from repo root)

```bash
make tarball
multipass transfer ebpf-poc-amd64.tar.gz ebpf:/home/ubuntu/
```

## 5. Extract & install dependencies (Docker, Go, Tetragon, tetra)

```bash
multipass exec ebpf -- bash -c '
  mkdir -p /home/ubuntu/ebpf-poc &&
  tar -xzf /home/ubuntu/ebpf-poc-amd64.tar.gz -C /home/ubuntu/ebpf-poc &&
  cd /home/ubuntu/ebpf-poc &&
  TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
'
make deploy 2>&1 | tail -50
make deploy VM=ebpf-2
make deploy VM=staging-east

#Target Azure VM
make redeploy-remote HOST=azureuser@20.238.49.130 \
  SSH_OPTS="-i /Users/jeff/Code/safeai-security-client-key.pem"
```

## 6. Apply TracingPolicies into the kernel

```bash
multipass exec ebpf -- sudo make -C /home/ubuntu/ebpf-poc policies-apply
```

Should print three policies `enabled`: `outbound-connections`,
`privilege-escalation`, `sensitive-file-access`.

## 7. Create engine data dir

```bash
multipass exec ebpf -- sudo mkdir -p /var/lib/ebpf-engine
```

## 8. Start the engine as a transient systemd unit 

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

## 9. Verify everything is up

```bash
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp | grep 8080
multipass info ebpf | awk '/IPv4/{print $2}'   # → use this IP in the browser
```

## 10. Open the dashboard

Browser → `http://<vm-ip>:8080` · login **admin / ebpf-soc-demo**

## 11. Pre-demo: clean slate just before going on

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

## 12. Live attack to fire alerts on stage

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


# Build Engine and VM deploy
Cross-compile engine binary
make build-linux 2>&1 | tail -10

Build from repo root
pwd; cd /Users/jeff/Code/eBPF && make build-linux 2>&1 | tail -10

Stop engine before redeploy
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ubuntu@192.168.252.4 "sudo systemctl stop ebpf-engine; sudo systemctl reset-failed ebpf-engine; sudo pkill -f engine-linux-amd64 || true; sleep 1; sudo ss -tlnp | grep ':8080' || echo 'port-free'" 2>&1; echo "exit=$?"

Confirm engine fully stopped
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ubuntu@192.168.252.4 "sudo systemctl is-active ebpf-engine; sudo ss -tlnp | grep ':8080' || echo 'port-free'" 2>&1; echo "exit=$?"

Deploy to VM
make deploy-remote HOST=ubuntu@192.168.252.4 2>&1 | tail -10

Read deploy output
tail -12 /private/tmp/claude-501/-Users-jeff-Code-eBPF/e99fdcb7-7961-4ce5-bd29-ad686f357b4e/tasks/bsuq34sym.output

Smoke-test live-proc endpoint
curl -s -m 5 -c /tmp/jc -d 'user=admin&pass=ebpf-soc-demo' http://192.168.252.4:8080/api/login -o /dev/null && curl -s -m 5 -b /tmp/jc 'http://192.168.252.4:8080/api/choke/proc/1' | head -c 600; echo
```



