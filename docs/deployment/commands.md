# Deployment commands

Sequential commands to redeploy the engine binary to the multipass VM
and the Azure VM after local code changes. Run from the repo root on
the macOS host.

The Makefile targets stage the new binary as `engine-linux-amd64.new`
and atomically `mv` it over the running executable, so the engine
**does not** need to be stopped before the transfer.

## Multipass (`ebpf` VM at 192.168.252.4)

```bash
make redeploy
```

Equivalent to:

```bash
make build-linux

multipass transfer \
  /Users/jeff/Code/eBPF/engine/engine-linux-amd64 \
  ebpf:/home/ubuntu/ebpf-poc/engine-linux-amd64.new

multipass exec ebpf -- bash -lc \
  "chmod +x /home/ubuntu/ebpf-poc/engine-linux-amd64.new && \
   mv -f /home/ubuntu/ebpf-poc/engine-linux-amd64.new \
         /home/ubuntu/ebpf-poc/engine-linux-amd64"

tar -cz -C /Users/jeff/Code/eBPF policies attacks | \
  multipass exec ebpf -- tar -xz -C /home/ubuntu/ebpf-poc

multipass exec ebpf -- bash -lc \
  "sudo systemctl restart ebpf-engine 2>/dev/null || \
   sudo pkill -TERM -f engine-linux-amd64 || true"

sleep 2
multipass exec ebpf -- bash -lc \
  "sudo systemctl is-active ebpf-engine; \
   sudo journalctl -u ebpf-engine -n 5 --no-pager"
```

## Azure (`safeai-security-client` at 20.238.49.130, soc.adanianlabs.io)

```bash
make redeploy-remote \
  HOST=azureuser@20.238.49.130 \
  SSH_OPTS="-i /Users/jeff/Code/safeai-security-client-key.pem"
```

Equivalent to:

```bash
KEY=/Users/jeff/Code/safeai-security-client-key.pem
HOST=azureuser@20.238.49.130

make build-linux

scp -i "$KEY" \
  /Users/jeff/Code/eBPF/engine/engine-linux-amd64 \
  "$HOST":/home/azureuser/ebpf-poc/engine-linux-amd64.new

ssh -i "$KEY" "$HOST" \
  "chmod +x /home/azureuser/ebpf-poc/engine-linux-amd64.new && \
   mv -f /home/azureuser/ebpf-poc/engine-linux-amd64.new \
         /home/azureuser/ebpf-poc/engine-linux-amd64"

tar -cz -C /Users/jeff/Code/eBPF policies attacks | \
  ssh -i "$KEY" "$HOST" "tar -xz -C /home/azureuser/ebpf-poc"

ssh -i "$KEY" "$HOST" \
  "sudo systemctl restart ebpf-engine 2>/dev/null || \
   sudo pkill -TERM -f engine-linux-amd64 || true"

sleep 2
ssh -i "$KEY" "$HOST" \
  "sudo systemctl is-active ebpf-engine; \
   sudo journalctl -u ebpf-engine -n 5 --no-pager"
curl -sS -o /dev/null -w 'HTTPS: %{http_code}\n' https://soc.adanianlabs.io/login
```

### One-time: enable the `/fleet` multi-host console on Azure

Run these once. After that, `make redeploy-remote` re-uses the same
argv on restart so the fleet flag persists.

```bash
KEY=/Users/jeff/Code/safeai-security-client-key.pem
HOST=azureuser@20.238.49.130

# 1. Write the hosts file (chokectl.hosts format).
ssh -i "$KEY" "$HOST" 'cat > /home/azureuser/ebpf-poc/fleet.hosts <<EOF
# /api/fleet/* fans out to every peer below.
self           http://127.0.0.1:8080
multipass-ebpf http://192.168.252.4:8080
EOF'

# 2. Stop the current transient unit.
ssh -i "$KEY" "$HOST" \
  "sudo systemctl stop ebpf-engine 2>/dev/null; \
   sudo pkill -f engine-linux-amd64 2>/dev/null; sleep 1; exit 0"

# 3. Restart the transient unit with -fleet-hosts wired in.
ssh -i "$KEY" "$HOST" \
  "sudo systemctl reset-failed ebpf-engine 2>/dev/null; \
   sudo systemd-run \
     --unit=ebpf-engine \
     --description='eBPF SOC engine (fleet-enabled, detect-only)' \
     --property=Restart=always --property=RestartSec=2 \
     --property=StandardOutput=append:/var/log/ebpf-engine.log \
     --property=StandardError=append:/var/log/ebpf-engine.log \
     --property=WorkingDirectory=/home/azureuser/ebpf-poc \
     /home/azureuser/ebpf-poc/engine-linux-amd64 \
       -tetragon  unix:///var/run/tetragon/tetragon.sock \
       -db        /var/lib/ebpf-engine/events.db \
       -http      127.0.0.1:8080 \
       -user      admin -pass ebpf-soc-demo \
       -policies  /home/azureuser/ebpf-poc/policies \
       -attacks   /home/azureuser/ebpf-poc/attacks \
       -honeypots /var/lib/ebpf-engine/honey \
       -choke-policies /home/azureuser/ebpf-poc/policies/choke \
       -fleet-hosts    /home/azureuser/ebpf-poc/fleet.hosts"

# 4. Verify the fleet endpoints respond.
curl -sS -c /tmp/c-az.txt -X POST \
  --data-urlencode "user=admin" --data-urlencode "pass=ebpf-soc-demo" \
  https://soc.adanianlabs.io/api/login -o /dev/null \
  -w 'login: %{http_code}\n'
curl -sS -b /tmp/c-az.txt https://soc.adanianlabs.io/api/fleet/hosts
curl -sS -b /tmp/c-az.txt -o /dev/null -w '/fleet HTML: %{http_code}\n' \
  https://soc.adanianlabs.io/fleet
```

Edit `fleet.hosts` to add/remove peers — the engine reloads it
automatically (30s cache TTL). No restart needed.
