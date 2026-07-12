// Command controlplane is the control-plane build target: the central,
// multi-tenant half of the agent / control-plane split (docs/plan/architecture.md
// §3). In Phase 0 it is a deliberately MINIMAL HTTP stub — just enough to prove
// the build target links cleanly against the shared internal/ packages and to
// give Phase 1 a concrete place to grow.
//
// STRANGLER NOTE (Phase 0). Like cmd/agent, this entrypoint is introduced
// alongside cmd/engine without moving any internal/ package. It reuses:
//
//   - internal/store — the future CENTRAL store. Today's dialect-abstracted
//     Store (sqlite | postgres) is the seam that becomes Postgres + ClickHouse
//     in Phase 1 (architecture.md §3.3). Opening it here exercises that seam.
//   - internal/api    — its auth surface (login/whoami/logout). The single-user
//     Auth is a placeholder for the multi-tenant identity/RBAC/SSO service
//     (architecture.md §3.6); mounting it now keeps the crypto path (auth.go,
//     which Phase 0 does NOT touch) in the control-plane build.
//
// What this stub is NOT (all Phase 1): the mTLS ingest collector, the message
// bus, ClickHouse/Postgres schemas, tenant identity/RBAC/SSO, the fleet/command
// service, and the multi-tenant console. It stands up liveness/readiness and a
// login endpoint only. The agent↔control-plane WIRE CONTRACT is the first
// Phase 1 artifact (architecture.md §4) — intentionally absent here.
//
// TENANCY NOTE. There is no tenant scoping yet because there is no ingest or
// central schema yet. The four-layer isolation invariant this service must
// eventually enforce (mTLS identity → ingest stamp → storage filter → API
// scope) is specified in docs/plan/tenant-isolation-invariant.md and is a
// Phase 1 build target. This stub must never be mistaken for a multi-tenant
// surface.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// cpVersion identifies this build target. Matches the engine's base version
// with a "-controlplane" suffix so the three build targets are distinguishable
// during the transition.
const cpVersion = "0.2.0-controlplane"

func main() {
	var (
		httpAddr  = flag.String("http", ":9090", "HTTP listen address (defaults off :8080 so it can run beside a local agent/engine)")
		dbPath    = flag.String("db", "controlplane.db", "SQLite database path (control-plane state; Phase 1 replaces with Postgres + ClickHouse)")
		storeKind = flag.String("store", "sqlite", "storage backend: sqlite | postgres")
		pgDSN     = flag.String("pg-dsn", "", "Postgres DSN; required when -store=postgres")
		authUser  = flag.String("user", "admin", "console username (single-user placeholder for Phase 1 identity/RBAC)")
		// SECURITY (Phase 0, deliverable #3): no plaintext credential default.
		// A control plane in particular must never ship a known credential.
		authPass = flag.String("pass", "", "console password (plaintext; bcrypted at startup). REQUIRED unless -pass-hash supplies one — there is no built-in default")
		authHash = flag.String("pass-hash", "", "bcrypt-hashed console password; takes precedence over -pass when set")
		secret   = flag.String("secret", "", "path to HMAC signing secret for session cookies; auto-generated 0600 if missing")
	)
	flag.Parse()

	log.Printf("[controlplane] %s starting — Phase 0 stub (ingest/bus/data-platform/identity/fleet land in Phase 1)", cpVersion)

	// SECURITY fail-fast (deliverable #3): resolve the credential and refuse to
	// start if none was supplied. Same policy as cmd/agent and cmd/engine — a
	// missing password is a hard error, never a silent known default.
	credential := *authPass
	if *authHash != "" {
		credential = *authHash
	}
	if credential == "" {
		log.Fatalf("auth: no console credential configured — set -pass or -pass-hash; the built-in demo default has been removed so a missing password fails fast instead of shipping a known credential")
	}

	// Central store seam (architecture.md §3.3). Opening it proves the
	// control-plane build target links the dialect-abstracted store.
	var st *store.Store
	switch *storeKind {
	case "postgres":
		if *pgDSN == "" {
			log.Fatalf("store: -store=postgres requires -pg-dsn")
		}
		var err error
		st, err = store.NewPostgres(*pgDSN)
		if err != nil {
			log.Fatalf("store: postgres: %v", err)
		}
		log.Printf("[store] postgres connected")
	case "sqlite", "":
		var err error
		st, err = store.New(*dbPath)
		if err != nil {
			log.Fatalf("store: sqlite: %v", err)
		}
		log.Printf("[store] sqlite at %s", *dbPath)
	default:
		log.Fatalf("store: unknown backend %q (want sqlite or postgres)", *storeKind)
	}
	defer st.Close()

	// Identity placeholder (architecture.md §3.6). Reuses internal/api's Auth
	// so the untouched auth.go crypto path is compiled into the control plane;
	// Phase 1 replaces this with multi-tenant identity/RBAC/SSO.
	auth, err := api.NewAuth(*authUser, credential, *secret)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	mux := http.NewServeMux()

	// Liveness: the process is up. Public by design (no auth) so orchestrators
	// (K8s) can probe it — this is the shape the Phase 3 HA control plane needs.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "version": cpVersion})
	})

	// Readiness: dependencies are usable. Today that is just the store; Phase 1
	// adds the bus, ClickHouse, and Postgres checks here.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if st == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "not-ready", "reason": "store not open"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ready"})
	})

	// Auth surface reused from internal/api (single-user placeholder).
	mux.HandleFunc("/api/login", auth.HandleLogin)
	mux.HandleFunc("/api/whoami", auth.HandleWhoami)
	mux.HandleFunc("/api/logout", auth.HandleLogout)

	// Root banner — makes it unmistakable that this is scaffolding, not the
	// real control plane, if someone opens it in a browser.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("eBPF-SOC control plane — Phase 0 stub.\n" +
			"Real ingest / message bus / data platform / identity+RBAC / fleet-command\n" +
			"services land in Phase 1 (see docs/plan/architecture.md §3-4).\n"))
	})

	srv := &http.Server{
		Addr:              *httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		log.Println("[controlplane] shutting down")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("[controlplane] listening on %s (endpoints: /healthz /readyz /api/login)", *httpAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http: %v", err)
	}
	// os.Exit path parity with the other binaries: a clean shutdown returns 0.
	os.Exit(0)
}
