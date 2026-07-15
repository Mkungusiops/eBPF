// Command controlplane is the control-plane build target: the central,
// multi-tenant half of the agent / control-plane split (docs/plan/architecture.md
// §3). It assembles the proven Phase-1 packages (internal/controlplane) into a
// running control plane:
//
//   - agent-facing mTLS gRPC: enrollment, tenant-stamped ingest → central store,
//     command dispatch, heartbeat, fleet policy distribution;
//   - operator HTTP: health, a tenant-scoped read API, and enrollment-token
//     minting, gated by authz (OIDC/BFF, or an admin bearer for headless use).
//
// Every tenant-isolation layer is enforced: tenant derived from the agent cert
// (Layer 1), stamped at ingest (Layer 2), stored tenant-partitioned (Layer 3),
// read only through an authz decision (Layer 4).
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/bff"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/controlplane"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

const cpVersion = "0.3.0-controlplane"

func main() {
	var (
		grpcAddr   = flag.String("grpc", ":9443", "agent-facing mTLS gRPC listen address")
		httpAddr   = flag.String("http", ":9090", "operator HTTP listen address")
		serverName = flag.String("server-name", "localhost", "TLS server name (cert SAN) agents connect to")

		storeKind = flag.String("store", "sqlite", "central store backend: sqlite | postgres | clickhouse")
		dbPath    = flag.String("db", "controlplane.db", "SQLite path (store=sqlite)")
		pgDSN     = flag.String("pg-dsn", "", "Postgres DSN (store=postgres); RLS-enforced central store")
		chDSN     = flag.String("ch-dsn", "", "ClickHouse DSN (store=clickhouse); events firehose store")

		stateDir    = flag.String("state-dir", "", "directory to persist the CA + fleet signing key across restarts (stable trust for agents); empty generates them per start")
		caOut       = flag.String("ca-out", "", "write the CA bundle PEM here (agents pin it)")
		fleetPubOut = flag.String("fleet-pubkey-out", "", "write the fleet command/policy signing public key (hex) here")

		// Operator auth. Exactly one is required — no default credential ships.
		adminToken = flag.String("admin-token", "", "bearer token mapped to an msoc-admin operator (headless/dev); REQUIRED unless -oidc-issuer is set")
		oidcIssuer = flag.String("oidc-issuer", "", "OIDC issuer URL (Keycloak realm); enables the BFF login flow")
		oidcClient = flag.String("oidc-client-id", "", "OIDC client id")
		oidcSecret = flag.String("oidc-client-secret", "", "OIDC client secret")
		oidcRedir  = flag.String("oidc-redirect-url", "", "OIDC redirect URL (…/auth/callback)")
		appURL     = flag.String("app-url", "/", "where the console lands after login")

		certTTL   = flag.Duration("cert-ttl", 90*24*time.Hour, "issued agent-cert lifetime")
		enrollTTL = flag.Duration("enroll-ttl", 15*time.Minute, "bootstrap-token lifetime")
	)
	flag.Parse()

	log.Printf("[controlplane] %s starting", cpVersion)

	// SECURITY: keep secrets off the command line. /proc/<pid>/cmdline is
	// world-readable, so -admin-token / -pg-dsn / -oidc-client-secret would leak
	// the msoc-admin bearer and the database password to any local user. The
	// environment is the safe channel (/proc/<pid>/environ is owner-only), which
	// is what the systemd unit's EnvironmentFile feeds. Flags still win when set,
	// so dev/CLI usage is unchanged.
	if *adminToken == "" {
		*adminToken = os.Getenv("CP_ADMIN_TOKEN")
	}
	if *pgDSN == "" {
		*pgDSN = os.Getenv("CP_PG_DSN")
	}
	if *oidcSecret == "" {
		*oidcSecret = os.Getenv("CP_OIDC_CLIENT_SECRET")
	}
	if *chDSN == "" {
		*chDSN = os.Getenv("CP_CH_DSN") // ClickHouse firehose DSN carries a password
	}

	// SECURITY fail-fast: refuse to start without an operator-auth mechanism.
	if *adminToken == "" && *oidcIssuer == "" {
		log.Fatalf("auth: no operator authentication configured — set -admin-token (headless) or -oidc-issuer (Keycloak); there is no default")
	}

	// Central store (the Layer-3 backend).
	var store centralstore.TenantStore
	var err error
	switch *storeKind {
	case "postgres":
		if *pgDSN == "" {
			log.Fatalf("store: -store=postgres requires -pg-dsn")
		}
		store, err = centralstore.OpenPostgres(*pgDSN)
	case "clickhouse":
		if *chDSN == "" {
			log.Fatalf("store: -store=clickhouse requires -ch-dsn")
		}
		store, err = centralstore.OpenClickHouse(*chDSN)
	case "sqlite", "":
		store, err = centralstore.Open(*dbPath)
	default:
		log.Fatalf("store: unknown backend %q", *storeKind)
	}
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	log.Printf("[store] %s central store ready", *storeKind)

	// Optional events firehose: when -ch-dsn is given alongside a non-ClickHouse
	// primary store, ingest is mirrored to ClickHouse (retention/analytics) while
	// the primary stays the authoritative operator read source. Best-effort — a
	// firehose outage never blocks ingest.
	var firehose ingest.Sink
	if *chDSN != "" && *storeKind != "clickhouse" {
		ch, chErr := centralstore.OpenClickHouse(*chDSN)
		if chErr != nil {
			log.Fatalf("firehose: clickhouse: %v", chErr)
		}
		defer ch.Close()
		firehose = ch
		log.Printf("[firehose] events mirrored to ClickHouse (primary reads stay on %s)", *storeKind)
	}

	// Self-managed CA (agents pin its bundle) + fleet signing key (agents pin its
	// public key to verify commands + policy bundles). Generated per start here;
	// production loads the CA/key from KMS/Vault so restarts keep the same trust.
	// With -state-dir the CA + fleet signing key persist across restarts, so
	// agents that pinned them keep trusting the same authority. Otherwise they are
	// generated per start. Production keeps these in KMS/Vault (threat-model SC-6).
	var ca *mtls.CA
	var fleetSigner signing.Signer
	if *stateDir != "" {
		if err := os.MkdirAll(*stateDir, 0o700); err != nil {
			log.Fatalf("state-dir: %v", err)
		}
		if ca, err = mtls.LoadOrCreateCA(filepath.Join(*stateDir, "ca.pem"), filepath.Join(*stateDir, "ca.key")); err != nil {
			log.Fatalf("ca: %v", err)
		}
		if fleetSigner, err = signing.LoadOrCreateSigner(filepath.Join(*stateDir, "fleet.key")); err != nil {
			log.Fatalf("fleet key: %v", err)
		}
		log.Printf("[state] CA + fleet key persisted in %s (stable across restarts)", *stateDir)
	} else {
		if ca, err = mtls.NewCA(); err != nil {
			log.Fatalf("ca: %v", err)
		}
		if fleetSigner, _, err = signing.GenerateKey(); err != nil {
			log.Fatalf("fleet key: %v", err)
		}
		log.Printf("[state] ephemeral CA + fleet key (per start) — set -state-dir to persist trust")
	}
	fleetVerifier := fleetSigner.Verifier()
	if *caOut != "" {
		if err := os.WriteFile(*caOut, ca.CertPEM(), 0o644); err != nil {
			log.Fatalf("ca-out: %v", err)
		}
		log.Printf("[ca] bundle written to %s (agents pin this)", *caOut)
	}
	if *fleetPubOut != "" {
		if err := os.WriteFile(*fleetPubOut, []byte(hex.EncodeToString(fleetVerifier.PublicKey())), 0o644); err != nil {
			log.Fatalf("fleet-pubkey-out: %v", err)
		}
		log.Printf("[fleet] signing public key written to %s (agents pin this for -fleet-pubkey)", *fleetPubOut)
	}

	// Optional OIDC/BFF operator login.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var bffH *bff.Handler
	if *oidcIssuer != "" {
		bffH, err = bff.New(ctx, *oidcIssuer, *oidcClient, *oidcSecret, *oidcRedir, *appURL, true)
		if err != nil {
			log.Fatalf("oidc: %v", err)
		}
		log.Printf("[auth] OIDC/BFF login enabled (issuer=%s)", *oidcIssuer)
	} else {
		log.Printf("[auth] headless admin-token auth (single msoc-admin operator)")
	}

	cp, err := controlplane.New(controlplane.Config{
		CA: ca, ServerName: *serverName, FleetSigner: fleetSigner, FleetKeyID: "fleet-1",
		Store: store, Firehose: firehose, CertTTL: *certTTL, EnrollTTL: *enrollTTL,
		UplinkEndpoint: *serverName + *grpcAddr, CommandEndpoint: *serverName + *grpcAddr,
		AdminToken: *adminToken, BFF: bffH, Logf: log.Printf,
	})
	if err != nil {
		log.Fatalf("controlplane: %v", err)
	}

	if err := cp.Serve(ctx, *grpcAddr, *httpAddr); err != nil && err != context.Canceled {
		log.Fatalf("serve: %v", err)
	}
	log.Println("[controlplane] shut down")
}
