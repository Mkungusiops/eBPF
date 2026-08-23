# The local estate on OrbStack

The whole platform — multi-tenant control plane, single-tenant engine, and one
real agent per tenant — running on your Mac as OrbStack Linux VMs, with **real
eBPF**.

```bash
make deploy-local      # bring the estate up
make destroy-local     # delete every machine
```

That is the guide. The rest of this document explains what you get, how to drive
it, and the traps that cost time when working on it.

---

## Real eBPF, not a simulation

**An OrbStack machine is a full Linux VM with its own BTF-enabled kernel**, so
Tetragon attaches for real — on the engine and on every agent VM. macOS having
no eBPF says nothing about the Linux VMs running on it.

This is worth stating plainly because the opposite was true early on and the
belief outlived it. `--engine-mode fake` still exists for UI work when you want
synthesised events without a kernel, but it is **opt-in**, not the default.

One genuine limitation: the **device (per-MAC) choke stays audit-only**. It
enforces on a two-NIC inline bridge, which a single-interface OrbStack machine is
not. For that, see
[network-choke-gateway.md](network-choke-gateway.md).

---

## What comes up

| Machine | Role | Default |
| --- | --- | --- |
| `ebpf-soc` | Multi-tenant control plane: Postgres, Keycloak, control plane, nginx | always |
| `ebpf-engine` | Single-tenant engine + Tetragon | always |
| `ebpf-agent-adanian`, `ebpf-agent-acme` | One real agent VM per tenant, enrolled into the control plane | `--data-mode real` |

Tenants default to `adanian-internal acme-corp`; agent VM names are derived from
the tenant id. The engine listens on `:8090`.

The script prints every URL, the generated credentials, and the SSH tunnel
command for each agent console when it finishes. Agent consoles bind to loopback
inside their VM, so they need `ssh -L 8080:127.0.0.1:8080 ebpf-agent-adanian@orb`
rather than a direct URL.

---

## Driving it

```bash
make deploy-local                                    # everything
./scripts/deploy/estate-orbstack.sh --only engine    # cp | agents | engine | verify
./scripts/deploy/estate-orbstack.sh --data-mode sim  # fabricated telemetry, no agent VMs
./scripts/deploy/estate-orbstack.sh --engine-mode fake
./scripts/deploy/estate-orbstack.sh --tenants "acme-corp"
ASSUME_YES=1 make deploy-local                       # unattended
DRY_RUN=1 make deploy-local                          # print the plan, build nothing
```

Pass flags through the Makefile with `ARGS`:

```bash
make deploy-local ARGS="--only cp"
```

`--only verify` re-runs the verification pass against a running estate without
deploying: it checks each unit is active, and that the engine has not silently
fallen back to `--fake` when you asked for Tetragon.

### Why this is a separate script from `estate.sh`

`estate.sh` reaches six SSH hosts, insists on TLS and real DNS names, and refuses
to leave a sim-agent running beside a real one because that combination fakes
containment in production. Locally, every machine is on the OrbStack bridge,
plaintext HTTP is the correct answer, and `--data-mode sim` is a legitimate
choice. Teaching `estate.sh` a "local mode" would put those production rails
behind an if-statement.

The ordering also is not guessable: agents enrol **into** the control plane, so
running the engine script first and the console script second yields two
components that have never heard of each other, both reporting success.

---

## Operations

```bash
orb -m ebpf-soc systemctl status <svc>
orb -m ebpf-soc journalctl -u <svc> -f
orb -m ebpf-soc sudo systemctl restart <svc>

orb restart ebpf-soc              # reboot the machine — all units auto-start
orb stop ebpf-soc | orb start ebpf-soc
```

Control-plane units: `postgresql`, `ebpf-keycloak`, `ebpf-soc-controlplane`,
`nginx`. Engine unit: `ebpf-engine`.

To ship a code change, re-run the relevant slice — `--only cp` or `--only
engine` — rather than hand-installing binaries. The provisioners build from the
working tree.

---

## Gotchas, learned the hard way

**Use the machine IP, not `localhost`.** On the Mac, `localhost` resolves to IPv6
`::1` and host-port collisions produce confusing routing. The script prints the
IPs; they are assigned by OrbStack and change between rebuilds, so do not
hard-code one.

**Secure cookies over plain HTTP.** The BFF once hardcoded `Secure` on session
cookies, which a browser refuses to send back over HTTP, dead-ending OIDC login
at the callback. It now derives `Secure` from the redirect-URL scheme
(`cmd/controlplane/main.go`). If you change how the local origin is built, keep
the redirect URL on `http://` or serve HTTPS — do not mix.

**Keycloak is proxied on the console origin**, not a separate port. The issuer is
`$TARGET_SCHEME://$TARGET_HOST/realms/ebpf-soc` and the admin console is at
`/admin/` on the same host. Older notes citing `:8085` predate the proxy.

**CA stability.** Always give the control plane a `-state-dir`. If agents get
stranded on an old CA, `rm -rf` their `-state-dir` so they re-enrol.

**nginx drops the port on absolute redirects.** `return 302 /auth/login` builds
the URL from nginx's own listen port (80), losing a `:8080`-style port. Use
`$scheme://$http_host/...`.

---

## Relationship to production

The binaries and the frontend bundle are identical to the AWS estate
([aws-multi-host.md](aws-multi-host.md)). What differs is the substrate — local
OrbStack VMs versus EC2 hosts — and TLS, which is plaintext HTTP here and Let's
Encrypt there. Fixes made locally are in shared code and carry over on the next
`make deploy-estate`.

---

## Related

- [`scripts/deploy/README.md`](../../scripts/deploy/README.md) — every deploy script and how they compose
- [aws-multi-host.md](aws-multi-host.md) — the production reference deployment
- [../getting-started/developer-onboarding.md](../getting-started/developer-onboarding.md) — build, test, and the other local-run options
- [../operations/enforcement-traps.md](../operations/enforcement-traps.md) — before you turn enforcement on
