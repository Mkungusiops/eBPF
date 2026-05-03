# Azure deployment — engine on a fresh Ubuntu VM behind nginx + TLS

End-to-end recipe for shipping the engine to an Azure VM and serving it
behind nginx with a Let's Encrypt cert. All blocks run from your **macOS
host** unless otherwise noted.

Working example used in this guide:
- **VM**: `safeai-security-client` (Ubuntu 24.04, kernel 6.17.x-azure)
- **Public IP**: `20.238.49.130`
- **SSH user**: `azureuser`
- **Domain**: `soc.adanianlabs.io` (A record → public IP)

Total time end-to-end: ~10–15 min (Tetragon image pull + Let's Encrypt
both dominate).

## 1. Prerequisites

On the VM:
- Ubuntu 22.04+ (kernel ≥5.10 — required by Tetragon for BTF)
- Passwordless sudo for the SSH user
- 2 vCPU / 4 GB RAM minimum

In the Azure NSG attached to the VM's NIC, open these inbound ports
(source `*`, action `Allow`):

| Port | Protocol | Why |
|---|---|---|
| 22  | TCP | SSH |
| 80  | TCP | Let's Encrypt HTTP-01 challenge + nginx HTTP→HTTPS redirect |
| 443 | TCP | nginx HTTPS |

Do **not** open 8080 in the NSG once nginx is fronting the engine —
it's bound to `127.0.0.1` only after step 4 below.

```bash
# Verify reachability before deploying:
nc -z -w 5 <PUBLIC_IP> 22 && echo "22 OK"
nc -z -w 5 <PUBLIC_IP> 80 && echo "80 OK"
nc -z -w 5 <PUBLIC_IP> 443 && echo "443 OK"
```

Tighten the SSH key on your Mac:

```bash
chmod 600 /path/to/your-key.pem
```

## 2. First-time deploy

The Makefile auto-detects the remote `$HOME/ebpf-poc` path, so the same
command works for `azureuser`, `ec2-user`, `ubuntu`, `scaleway`, `root`,
etc.

```bash
make deploy-remote \
  HOST=azureuser@20.238.49.130 \
  SSH_OPTS="-i /Users/jeff/Code/safeai-security-client-key.pem"
```

This will:
1. Cross-compile `engine-linux-amd64` locally
2. SCP the binary, `policies/`, `attacks/`, and `scripts/` to the VM
3. Run `scripts/setup.sh` (installs Docker, pulls Tetragon
   `quay.io/cilium/tetragon:v1.6.1`, sets up cgroup v2)
4. Apply detection + enforcement TracingPolicies into the kernel
5. Start the engine as a transient systemd unit (`ebpf-engine`)

After this finishes, the engine is reachable on `http://<public-ip>:8080`
with default credentials `admin / ebpf-soc-demo`.

## 3. nginx + Let's Encrypt (HTTPS)

Once port 80 is reachable from the public internet (the ACME HTTP-01
challenge needs it), provision TLS via certbot:

```bash
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> 'bash -s' <<'EOF'
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq nginx certbot python3-certbot-nginx

sudo tee /etc/nginx/sites-available/<DOMAIN> >/dev/null <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    "" close;
}

server {
    listen 80;
    listen [::]:80;
    server_name <DOMAIN>;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    client_max_body_size 16m;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        $connection_upgrade;
        proxy_buffering    off;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
}
NGINX

sudo ln -sf /etc/nginx/sites-available/<DOMAIN> /etc/nginx/sites-enabled/<DOMAIN>
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable --now nginx
sudo certbot --nginx --non-interactive --agree-tos \
  --email <EMAIL> --domains <DOMAIN> --redirect
EOF
```

Replace `<DOMAIN>`, `<PUBLIC_IP>`, `<EMAIL>` with your values. Certbot
appends a 443 server block to the nginx config, sets up a
`certbot.timer` for auto-renewal, and turns on the 80→443 redirect.

WebSocket / SSE upgrade is wired in via `proxy_buffering off` and the
`Upgrade`/`Connection` headers — required for the live alert stream.

## 4. Bind the engine to localhost

After nginx is fronting requests, restart the engine with `-http
127.0.0.1:8080` so port 8080 is no longer reachable externally:

```bash
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> '
  sudo systemctl stop ebpf-engine
  sudo systemctl reset-failed ebpf-engine
  sudo pkill -f engine-linux-amd64 || true
  sleep 2
  sudo systemd-run \
    --unit=ebpf-engine \
    --description="eBPF SOC engine (detect-only behind nginx)" \
    --property=Restart=always \
    --property=RestartSec=2 \
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
      -choke-policies /home/azureuser/ebpf-poc/policies/choke
'
```

Note: this command leaves `-enforce` **off**. Re-enable it only after
tuning thresholds — see the gotcha below.

## 5. Verify

```bash
curl -sS -o /dev/null -w "HTTP %{http_code}\n" http://<DOMAIN>/      # → 301
curl -sS -o /dev/null -w "HTTPS %{http_code}\n" https://<DOMAIN>/    # → 200/302
echo | openssl s_client -servername <DOMAIN> -connect <DOMAIN>:443 \
  2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Browser → `https://<DOMAIN>` · login `admin / ebpf-soc-demo`.

## 6. Iteration loop

After local code changes:

```bash
make redeploy-remote \
  HOST=azureuser@<PUBLIC_IP> \
  SSH_OPTS="-i /path/to/key.pem"
```

This rebuilds the binary, syncs `policies/` + `attacks/`, and runs
`systemctl restart ebpf-engine`. ~10–20s end-to-end.

The redeploy works while the engine is running: Linux refuses to
overwrite a running executable (`ETXTBSY`), so the Makefile stages the
new binary as `engine-linux-amd64.new` and atomically renames it over
the live one. The old inode stays alive for the running process while
the new path points at the new inode; `systemctl restart` then loads
the new binary cleanly. No manual stop step required.

In-memory sessions are dropped on restart — log back in via the UI.
The SQLite DB at `/var/lib/ebpf-engine/events.db` and applied
TracingPolicies persist across restarts.

## 7. Optional — turn on the `/fleet` multi-host console

The browser-side Fleet panel (sidebar → Fleet) is a per-operator
directory: it pings each host's `/api/whoami` from the browser and
surfaces reachability + mode. It works same-origin out of the box but
hits CORS limits across origins, since the engine ships no
`Access-Control-Allow-*` headers.

For a real cross-host control plane — apply a preset to N hosts at
once, push thresholds, flip the kill-switch fleet-wide, thaw all
frozen cgroups — start the engine with `--fleet-hosts=PATH`. The local
engine then logs into each peer with the shared admin credential and
fans out HTTP calls server-side, so the operator's browser only ever
talks to its own engine and CORS is moot.

Write the hosts file (chokectl.hosts format — one `<name> <url>` per
line, `#` for comments):

```bash
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> 'cat > /home/azureuser/ebpf-poc/fleet.hosts <<EOF
# /api/fleet/* fans out to every peer below.
self           http://127.0.0.1:8080
multipass-ebpf http://192.168.252.4:8080
EOF'
```

Add `-fleet-hosts /home/azureuser/ebpf-poc/fleet.hosts` to the
`systemd-run` argv from §4 and restart. The endpoint set comes alive:

| Endpoint | Action |
|---|---|
| `GET /fleet` | the embedded console UI |
| `GET /api/fleet/hosts` | list peers |
| `GET /api/fleet/state` | per-host mode/tracked/audit/kill-switch |
| `GET /api/fleet/cgroups` | per-host throttled/tarpit/quarantined PIDs |
| `GET /api/fleet/decisions?limit=N` | recent gateway decisions per host |
| `GET /api/fleet/alerts` | recent alerts per host |
| `POST /api/fleet/preset` | apply a preset to all peers |
| `PUT /api/fleet/thresholds` | push thresholds to all peers |
| `POST /api/fleet/kill-switch` | flip kill-switch on all peers |
| `POST /api/fleet/thaw` | release frozen cgroups on all peers |

All write endpoints are JSON-bodied and follow the same shape as the
single-host `/api/choke/*` endpoints they wrap. Each fanout response
is `{ "hosts": [{name, url, ok, status, data | error}, …] }`.

The hosts file is reloaded automatically when its mtime changes (cache
TTL is 30s) — edit the file, wait 30s, no restart needed.

Peers that aren't reachable from the operator host (e.g. multipass on
a private LAN, hit from an Azure operator) come back as `ok: false`
with an `error` string. The UI shows them as down in the row; healthy
peers continue to fan out normally.

## Gotcha: `-enforce` will quarantine your sudo

The choke gateway scores `sshd → bash → sudo → systemctl` chains at
~150–200 because each new SSH session reads `/etc/passwd` for MOTD and
`sudo` reads `/etc/shadow`. With default thresholds (`-quarantine-at
120 -sever-at 200`), `sudo` lands in the `choke-quarantined` cgroup and
gets `cgroup.freeze`d — every subsequent admin command hangs forever.

If you hit this, rescue from your Mac (engine still serves HTTP, so the
API works even when sudo is frozen):

```bash
DOMAIN=https://soc.adanianlabs.io   # or http://<ip>:8080 if pre-TLS
curl -sS -c /tmp/c -X POST -d 'user=admin&pass=ebpf-soc-demo' $DOMAIN/api/login
# 1. Stop new enforcement actions:
curl -sS -b /tmp/c -X POST -H 'Content-Type: application/json' \
  -d '{"on":true}' $DOMAIN/api/choke/kill-switch
# 2. Release the frozen cgroup:
curl -sS -b /tmp/c -X POST -H 'Content-Type: application/json' \
  -d '{"reason":"unblock sudo"}' $DOMAIN/api/choke/thaw
```

Then SSH in (sudo will work) and either restart the engine without
`-enforce` (as in step 4) or re-tune thresholds before re-enabling:

```text
-throttle-at 50 -tarpit-at 120 -quarantine-at 250 -sever-at 500
```

…and add admin chains to the system-critical exemption list in the
gateway config so `sudo systemctl ...` doesn't trip over the threshold.

## Operational helpers

```bash
# live engine logs
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> \
  'sudo journalctl -u ebpf-engine -f'

# tetragon policy state
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> \
  'sudo docker exec tetragon tetra tracingpolicy list'

# choke cgroup membership
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> '
  for c in choke-throttled choke-tarpit choke-quarantined; do
    n=$(wc -l </sys/fs/cgroup/$c/cgroup.procs 2>/dev/null || echo 0)
    f=$(cat /sys/fs/cgroup/$c/cgroup.freeze 2>/dev/null || echo -)
    echo "$c: pids=$n freeze=$f"
  done'

# cert state + renewal status
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> '
  sudo certbot certificates
  sudo systemctl status certbot.timer --no-pager'

# nginx reload after config edit
ssh -i /path/to/key.pem azureuser@<PUBLIC_IP> \
  'sudo nginx -t && sudo systemctl reload nginx'
```

## NSG hardening (after step 4)

Once 8080 is loopback-only, prune broad NSG rules so only the necessary
ports are reachable from the internet:

```text
Keep:
  300  SSH    22   Allow Any
  320  HTTP   80   Allow Any
  340  HTTPS 443   Allow Any

Remove:
  350  allowAllPorts (1024-65535)   ← was used during bring-up; not needed now
```
