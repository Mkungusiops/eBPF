package hoststack

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/logging"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// ResolveConsoleCredential picks the credential the local console will
// authenticate against and refuses to return a usable one that nobody set.
//
// SECURITY (Phase 0, deliverable #3). This used to default to a known demo
// string, which meant every deployment that forgot to set a password silently
// shipped the same credential. The default is gone, so a missing password has
// to be a hard startup error instead — auth.go's crypto is untouched, it is
// simply never handed an empty password (bcrypt would happily hash "" and stand
// up a blank-password account).
//
// surface names the thing being protected in the error text — "dashboard" for
// the engine's full console, "console" for the agent's local debug/health
// surface — because that is the word the operator is looking at when they read
// the failure.
//
// Returns an error rather than exiting so the caller owns the exit and this is
// reachable from a test; the caller's log.Fatal reproduces the original text.
func ResolveConsoleCredential(pass, hash, surface string) (string, error) {
	credential := pass
	if hash != "" {
		credential = hash // pre-hashed bcrypt: NewAuth detects $2a$/$2b$/$2y$ prefix
	}
	if credential == "" {
		return "", fmt.Errorf("auth: no %s credential configured — set -pass, -pass-hash, or pass/pass_hash in the config file; the built-in demo default has been removed so a missing password fails fast instead of shipping a known credential", surface)
	}
	// SECURITY: enforce the password policy on plaintext credentials (the same
	// policy the login page displays). Pre-hashed bcrypt values cannot be
	// composition-checked, so they pass through — the operator owns that.
	if !api.IsBcryptHash(credential) {
		if err := api.ValidatePasswordPolicy(credential); err != nil {
			return "", fmt.Errorf("auth: %v — set a compliant -pass/pass, or supply a pre-hashed -pass-hash/pass_hash", err)
		}
	}
	return credential, nil
}

// OpenStore opens the configured storage backend, or exits.
//
// sqliteNote is appended verbatim to the "[store] sqlite at …" startup line.
// The two build targets describe the same file differently — the agent calls it
// an offline buffer, because for the agent that is what it is — and startup log
// text is what operators grep journald for, so it stays a parameter rather than
// being unified into one string.
//
// The DSN never reaches the log unredacted: journald keeps what it is given
// forever, and a Postgres password in it is a credential leak with no expiry.
func OpenStore(s Settings, sqliteNote string) *store.Store {
	switch s.StoreKind {
	case "postgres":
		if s.PgDSN == "" {
			log.Fatalf("store: -store=postgres requires -pg-dsn (e.g. postgres://engine:engine@127.0.0.1:5432/ebpf?sslmode=disable)")
		}
		st, err := store.NewPostgres(s.PgDSN)
		if err != nil {
			log.Fatalf("store: postgres: %v", err)
		}
		log.Printf("[store] postgres connected (%s)", logging.RedactDSN(s.PgDSN))
		return st
	case "sqlite", "":
		st, err := store.New(s.DBPath)
		if err != nil {
			log.Fatalf("store: sqlite: %v", err)
		}
		log.Printf("[store] sqlite at %s%s", s.DBPath, sqliteNote)
		return st
	default:
		log.Fatalf("store: unknown backend %q (want sqlite or postgres)", s.StoreKind)
		return nil
	}
}

// InitMetrics brings up the OTel meter provider and returns the shutdown the
// caller must defer. An empty endpoint disables the SDK entirely: the
// instruments stay nil and the safe* helpers no-op, so metrics are never a
// prerequisite for sensing or enforcing.
func InitMetrics(endpoint, hostname, version string) func() {
	mp, err := metrics.Init(context.Background(), endpoint, hostname, version)
	if err != nil {
		log.Fatalf("metrics: %v", err)
	}
	if endpoint != "" {
		log.Printf("[metrics] otlp endpoint=%s", endpoint)
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mp.Shutdown(ctx)
	}
}

// ConfigureConsoleDirs points the API package at the policy and attack script
// directories and seeds the honeypot decoys.
//
// A honeypot failure is logged and survived, never fatal: decoys are a
// detection aid, and a host that refuses to start because it could not write a
// decoy file is a host that detects nothing at all.
func ConfigureConsoleDirs(policiesDir, attacksDir, honeypotDir string) {
	api.SetPolicyDir(policiesDir)
	api.SetAttackDir(attacksDir)
	if err := api.EnsureHoneypots(honeypotDir); err != nil {
		log.Printf("honeypots: setup failed (%v) — continuing without decoys", err)
	} else {
		log.Printf("honeypots: seeded at %s", honeypotDir)
	}
}

// NotifyShutdown cancels ctx on SIGINT/SIGTERM so the background loops, the
// event stream, and the control-plane client all wind down through the same
// context rather than being killed mid-write.
func NotifyShutdown(cancel context.CancelFunc) {
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigC; log.Println("shutting down"); cancel() }()
}
