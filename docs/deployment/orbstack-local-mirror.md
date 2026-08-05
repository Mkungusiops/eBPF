# OrbStack local mirror — deployment runbook

A **durable, systemd-managed local mirror** of the multi-tenant SOC platform,
running inside a single [OrbStack](https://orbstack.dev) Linux machine on macOS.
It stands in for the deployed estate (`console.adanianlabs.io` /
`auth.adanianlabs.io`) for development when that box is unavailable, and doubles
as a rehearsal for the real deploy — the layout mirrors production
(`systemd` units + nginx + Postgres + Keycloak + control plane).

There is **no live eBPF** on macOS; a dev-only `cmd/simagent` enrolls like a real
agent (mTLS) and feeds synthetic telemetry + heartbeats so every console panel
renders with realistic tenant data. All isolation/RLS/RBAC paths are exercised
for real.

> Credentials are **not** in this file. See `docs/credentials/local-stack.md`
> (gitignored). Placeholders below like `<KC_ADMIN_PW>` map to that file.

---

## 1. Architecture

```
  macOS host  ──browser──▶  http://192.168.139.126/         (Console)
                            http://192.168.139.126:8090/     (Engine)
                            http://192.168.139.126:8085/     (Keycloak)
                                   │
              ┌────────────────────┴─────────────────────────────┐
              │  OrbStack Linux machine `ebpf-soc` (Ubuntu)       │
              │                                                   │
              │  nginx :80 ──▶ /var/www/console (SOC dist)        │
              │      │  proxy /api,/auth ──▶ control-plane :9090  │
              │      ▼                                            │
              │  ebpf-soc-controlplane  (http 9090 / grpc 9443)   │
              │      ├── Postgres :5432  (RLS store, db ebpf_soc) │
              │      └── Keycloak :8085  (OIDC realm ebpf-soc)    │
              │                                                   │
              │  ebpf-sim-adanian / ebpf-sim-acme (seed agents)   │
              │  ebpf-engine :8090 (soc single-host, -fake)       │
              │                                                   │
              │  all units: systemd, Restart=always, enabled      │
              └───────────────────────────────────────────────────┘
```

Canonical host = the machine IP (`192.168.139.126`); every browser-facing URL and
the OIDC issuer/redirect use it, so the Keycloak issuer is consistent for both the
browser and the control plane.

---

## 2. Prerequisites (on the Mac)

- OrbStack installed (`orb` on PATH).
- Go toolchain (to cross-compile the linux binaries).
- The repo at `/Users/jeff/Code/eBPF-SOC` with a built `web/dist`
  (`cd web && npm run build`).

---

## 3. Deploy from scratch

### 3.1 Cross-compile the binaries (on the Mac)

```bash
cd engine
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/cp-linux       ./cmd/controlplane
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/simagent-linux ./cmd/simagent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/engine-linux   ./cmd/engine
```

### 3.2 Create the machine

```bash
orb create ubuntu ebpf-soc
IP=$(orb -m ebpf-soc bash -c "hostname -I | awk '{print \$1}'")   # e.g. 192.168.139.126
```

OrbStack mounts the Mac filesystem into the machine, so it can read `/tmp/*` and
`/Users/...` directly (no scp needed).

### 3.3 Base packages

```bash
orb -m ebpf-soc sudo bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq postgresql nginx openjdk-21-jre-headless unzip curl'
```

### 3.4 Stage binaries + frontend + Keycloak

```bash
orb -m ebpf-soc sudo bash -c '
  install -m0755 /tmp/cp-linux       /usr/local/bin/ebpf-soc-controlplane
  install -m0755 /tmp/simagent-linux /usr/local/bin/ebpf-simagent
  install -m0755 /tmp/engine-linux   /usr/local/bin/ebpf-engine
  mkdir -p /var/www/console /etc/ebpf-soc /var/lib/ebpf-soc
  cp -r /Users/jeff/Code/eBPF-SOC/web/dist/. /var/www/console/
  curl -fsSL -o /opt/kc.tgz https://github.com/keycloak/keycloak/releases/download/26.0.8/keycloak-26.0.8.tar.gz
  cd /opt && tar xzf kc.tgz && mv keycloak-26.0.8 keycloak && rm kc.tgz'
```

### 3.5 Postgres

```bash
orb -m ebpf-soc sudo bash -c "
  sudo -u postgres psql -tAc \"ALTER USER postgres PASSWORD '<PG_PW>';\"
  sudo -u postgres createdb ebpf_soc 2>/dev/null || true"
```

### 3.6 Keycloak (systemd) + realm

`/etc/ebpf-soc/keycloak.env`:

```ini
KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=<KC_ADMIN_PW>
KC_HTTP_PORT=8085
KC_HTTP_ENABLED=true
KC_HOSTNAME_STRICT=false
KC_HEALTH_ENABLED=true
```

`/etc/systemd/system/ebpf-keycloak.service`:

```ini
[Unit]
Description=Keycloak (ebpf-soc console SSO)
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/ebpf-soc/keycloak.env
ExecStart=/opt/keycloak/bin/kc.sh start-dev
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```

`systemctl enable --now ebpf-keycloak`, wait for `curl localhost:8085/realms/master`
= 200, then configure the realm with `kcadm.sh` (realm `ebpf-soc`, roles
`tenant-analyst` + `msoc-admin`, client `console-bff` with
`redirectUris=["http://$IP/auth/callback"]`, a User-Attribute→`tenant` protocol
mapper, `unmanagedAttributePolicy=ENABLED`, the password policy
`length(14) and upperCase(1) and lowerCase(1) and digits(3) and specialChars(3)`,
and the three users **with email/firstName/lastName/emailVerified=true**). Capture
the generated client secret.

> **Keycloak 26 gotcha:** users missing email/first/last name dead-end on the
> `VERIFY_PROFILE` required action; the custom `tenant` claim needs
> `unmanagedAttributePolicy=ENABLED` + the attribute mapper.

### 3.7 Control plane (systemd)

`/etc/ebpf-soc/controlplane.env`:

```ini
CP_OIDC_CLIENT_SECRET=<CONSOLE_BFF_SECRET>
CP_ADMIN_TOKEN=<CP_ADMIN_TOKEN>
```

`/etc/systemd/system/ebpf-soc-controlplane.service` (`ExecStart` one line):

```ini
[Unit]
Description=ebpf-soc control plane
After=network-online.target postgresql.service ebpf-keycloak.service
Wants=network-online.target
[Service]
EnvironmentFile=/etc/ebpf-soc/controlplane.env
ExecStart=/usr/local/bin/ebpf-soc-controlplane -http 127.0.0.1:9090 -grpc 127.0.0.1:9443 -server-name localhost -store postgres -pg-dsn postgres://postgres:<PG_PW>@127.0.0.1:5432/ebpf_soc?sslmode=disable -oidc-issuer http://192.168.139.126:8085/realms/ebpf-soc -oidc-client-id console-bff -oidc-redirect-url http://192.168.139.126/auth/callback -app-url / -state-dir /var/lib/ebpf-soc -fleet-pubkey-out /var/lib/ebpf-soc/fleet.pub
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```

> **`-state-dir` is mandatory** — it persists the CA + fleet signing key. Without
> it the CA regenerates every restart and agents' cached mTLS certs are rejected
> (`x509: certificate signed by unknown authority "ebpf-soc-ca"`), which silently
> empties the choke/devices/fleet views. `-fleet-pubkey-out` publishes the fleet
> signing pubkey the sim-agents pin to accept commands.

### 3.8 nginx (systemd)

`/etc/nginx/sites-available/console` (symlink into `sites-enabled`, remove
`default`):

```nginx
server {
    listen 80 default_server;
    server_name _;
    root /var/www/console;
    index index.html;
    # SOC app hardcodes /login and /api/logout (engine paths) — send to the BFF.
    # $scheme://$http_host keeps the port; a bare relative redirect loses it.
    location = /login      { return 302 $scheme://$http_host/auth/login; }
    location = /api/logout { return 302 $scheme://$http_host/auth/logout; }
    location /api/  { proxy_pass http://127.0.0.1:9090; proxy_http_version 1.1;
        proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1d; proxy_buffering off; }
    location /auth/ { proxy_pass http://127.0.0.1:9090; proxy_http_version 1.1;
        proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; }
    location /healthz { proxy_pass http://127.0.0.1:9090; }
    location / { try_files $uri $uri.html /index.html; }
}
```

### 3.9 Sim-agents + engine (systemd)

Two sim units (one per tenant), each:

```ini
ExecStart=/usr/local/bin/ebpf-simagent -cp-http http://127.0.0.1:9090 -cp-grpc 127.0.0.1:9443 -server-name localhost -admin-token <CP_ADMIN_TOKEN> -tenant <TENANT> -state-dir /var/lib/ebpf-<label> -label <label> -fleet-pubkey /var/lib/ebpf-soc/fleet.pub
```

Engine unit (`-fake`, no eBPF):

```ini
ExecStart=/usr/local/bin/ebpf-engine -fake -pass '<ENGINE_PW>' -store sqlite -db /var/lib/ebpf-engine/events.db -http :8090 -secret /var/lib/ebpf-engine/secret -policies /var/lib/ebpf-engine/policies -attacks /var/lib/ebpf-engine/attacks -honeypots /var/lib/ebpf-engine/honey
```

`systemctl daemon-reload && systemctl enable --now ebpf-soc-controlplane nginx
ebpf-sim-adanian ebpf-sim-acme ebpf-engine`.

---

## 4. Verify

```bash
# console reachable, login flow → Keycloak
curl -s -o /dev/null -w '%{http_code}\n'  http://192.168.139.126/
curl -s -o /dev/null -w '%{redirect_url}\n' http://192.168.139.126/auth/login   # → …:8085/realms/ebpf-soc/…

# services
orb -m ebpf-soc bash -c 'systemctl is-active postgresql ebpf-keycloak ebpf-soc-controlplane nginx ebpf-sim-adanian ebpf-sim-acme ebpf-engine'
```

A headless OIDC login as `analyst` should return a tenant-scoped `whoami`, with
alerts/events/choke/devices/fleet populated and `?tenant=acme-corp` → 404
(isolation). Interactive: `POST /api/choke/manual {exec_id,action:"sever"}` →
`STATUS_APPLIED` and the process shows `severed`.

---

## 5. Operations

```bash
orb -m ebpf-soc systemctl status  <svc>
orb -m ebpf-soc journalctl -u <svc> -f
orb -m ebpf-soc sudo systemctl restart <svc>
orb restart ebpf-soc          # reboot the whole machine — all units auto-start
orb stop ebpf-soc / orb start ebpf-soc
```

Update a binary: rebuild on the Mac, `install -m0755 /tmp/<bin>
/usr/local/bin/<svc>`, `systemctl restart <svc>`.

---

## 6. Gotchas (learned the hard way)

- **Use the machine IP** (`192.168.139.126`), not `localhost`/`127.0.0.1` — on the
  Mac, `localhost`→IPv6 `::1` and host-port collisions cause confusing routing.
- **Secure cookies over HTTP**: the BFF previously hardcoded `Secure` cookies,
  which the browser refuses to send back over plain HTTP → OIDC login dead-ends on
  the callback. Fixed in `cmd/controlplane/main.go` (derives `Secure` from the
  redirect-URL scheme). Serve HTTPS or keep the redirect URL `http://…` for local.
- **CA stability**: always give the CP `-state-dir`; if agents get stranded on an
  old CA, `rm -rf` their `-state-dir` so they re-enroll.
- **nginx port drop**: `return 302 /auth/login` builds an absolute URL from
  nginx's own listen port (80), dropping `:8080`-style ports — use
  `$scheme://$http_host/...`.

---

## 7. Teardown

```bash
orb delete -f ebpf-soc     # removes the whole machine + its data
```

---

## Relationship to production

This mirrors, but does not replace, the Azure deploy
(`docs/deployment/azure.md`, `docs/deployment/controlplane-migration.md`). The
CP/engine binaries and the frontend `dist` are identical; only the substrate
(local systemd machine vs. Azure VM) and TLS (HTTP local vs. Let's Encrypt)
differ. Fixes made here — the `Secure`-cookie derivation, the fleet mapping, the
per-process jail/thaw wiring — are in the shared code and carry to Azure on the
next redeploy.
