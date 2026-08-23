// Package controlplane assembles the proven Phase-1 packages into a running,
// single-node multi-tenant control plane: the agent-facing mTLS gRPC services
// (enrollment, tenant-stamped ingest → central store, command dispatch,
// heartbeat, fleet policy distribution) plus an operator HTTP API (health, a
// tenant-scoped read surface, and enrollment-token minting) gated by authz.
//
// It is the concrete realization of architecture.md §3 — every isolation layer
// is enforced here: tenant is derived from the agent's mTLS cert (Layer 1),
// stamped at ingest (Layer 2), stored tenant-partitioned (Layer 3), and read
// only through an authz decision (Layer 4).
package controlplane

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/bff"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/fleet"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Config wires the control plane. CA, FleetSigner and Store are constructed by
// the caller (cmd/controlplane) so their lifecycle/persistence is its concern.
type Config struct {
	// Assistant configures the optional analyst assistant. Zero value = off,
	// which is the default: a control plane must not acquire an outbound
	// dependency on an inference endpoint because someone upgraded.
	Assistant assistant.Config

	// Chats persists assistant conversations. nil = history disabled, and the
	// chat endpoints answer 503 "not enabled" rather than failing obscurely.
	//
	// Optional on purpose. Chat history is a convenience; detection, response
	// and the read API are not. A deployment whose chat schema will not migrate
	// must still start and still contain threats, so this stays nil in that case
	// instead of aborting startup.
	Chats chatstore.Store

	CA          *mtls.CA
	ServerName  string // gRPC cert SAN — the host/IP agents connect to
	FleetSigner signing.Signer
	FleetKeyID  string
	Store       centralstore.TenantStore // ingest sink + operator read source
	// Firehose, when set, receives a best-effort mirror of every ingested
	// record (e.g. ClickHouse for the high-volume events firehose + retention),
	// while Store stays the authoritative read source. nil = single-store.
	Firehose ingest.Sink

	// IntelDir is the threat-intelligence feed directory. Empty disables
	// indicator matching on this control plane; the sensors still match with
	// their own copy, so this governs the tenant-wide view, not detection.
	IntelDir string
	// IntelRefresh optionally downloads feeds. Off unless it names feeds AND
	// an interval — see internal/intel/refresh.go for why the default is off.
	IntelRefresh intel.RefreshConfig
	// BaselineWarmup gates the per-tenant behavioural profile. Zero uses the
	// package default.
	BaselineWarmup baseline.Warmup
	// BaselineStore persists the per-tenant profiles under RLS. nil keeps them
	// in memory only, so they relearn from scratch on every restart — which is
	// what a non-Postgres deployment gets, and what every test gets.
	BaselineStore *baseline.TenantStore

	CertTTL   time.Duration // issued agent-cert lifetime
	EnrollTTL time.Duration // bootstrap-token lifetime

	UplinkEndpoint  string // advertised to agents in the enroll response
	CommandEndpoint string

	// Operator auth: exactly one path is used. If BFF is set, HTTP identity comes
	// from the OIDC session; otherwise AdminToken (a bearer) maps to an msoc-admin
	// principal for headless/dev use.
	BFF        *bff.Handler
	AdminToken string

	// RequireApproval turns on EN-2 change-control: quarantine/sever and
	// fleet-wide arming are HELD until a second operator approves them.
	//
	// Default OFF, deliberately. Dual control needs two people who can respond,
	// and a tenant with a single on-call operator would otherwise be unable to
	// contain a threat from the console at all — an approval rule that can block
	// containment during an incident is a worse failure than the one it prevents.
	// Deployments with a staffed SOC turn it on; the automatic score-driven
	// enforcement on each agent is never gated either way.
	RequireApproval bool

	// LabMode exposes the demo surfaces — the attack catalogue, the synthetic
	// attack injector and the honeypot panel. Default false: on a customer
	// deployment those endpoints write fabricated findings into the tenant's
	// real evidence store. See labOnly in attacks.go.
	LabMode bool

	Logf func(string, ...any)
}

// Server is an assembled control plane.
type Server struct {
	cfg Config
	// selfAddr is the HTTP address Serve bound to, so the assistant's tools can
	// read this control plane's own endpoints over loopback. Captured rather
	// than taken from a request Host header: the tools run server-side, and a
	// client-supplied origin would turn the ask endpoint into a request
	// forwarder authenticated as the control plane.
	selfAddr string
	// chats persists assistant conversations. nil when the deployment has no
	// chat history configured — every handler reports it unavailable rather
	// than panicking, so the feature is genuinely optional.
	chats      chatstore.Store
	ca         *mtls.CA
	gs         *grpc.Server
	httpH      http.Handler
	tokens     *enrollment.TokenStore
	fleet      *fleet.Service
	registry   *heartbeat.Registry
	dispatcher *command.Dispatcher
	auditor    *authz.MemAuditor
	// owners remembers which agent proved it was running a given target, so a
	// follow-up command on the same process routes straight to it instead of
	// being re-guessed from a PID. See ownerCache in choke.go.
	owners *ownerCache
	// approvals holds destructive actions awaiting a second operator
	// (threat-model EN-2). See internal/approval.
	approvals *approval.Store
	// stats caches computed alert-window aggregates briefly, so N open console
	// tabs do not each trigger the same scan. See alertstats.go.
	stats *statsCache
	// enrich holds the per-tenant behavioural profiles and the indicator set.
	// nil when neither is configured, in which case the enrichment endpoints
	// answer 503 with a reason rather than 404 — "switched off" and "broken"
	// must be distinguishable.
	enrich *tenantEnricher
	// intelRefresh is the optional feed downloader, reported by /api/intel.
	intelRefresh *intel.Refresher
}

// New builds the gRPC + HTTP surfaces. It does not listen; call Serve (or drive
// GRPC()/HTTP() directly, e.g. in tests).
func New(cfg Config) (*Server, error) {
	if cfg.CA == nil {
		return nil, errors.New("controlplane: CA required")
	}
	if cfg.Store == nil {
		return nil, errors.New("controlplane: store required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.CertTTL == 0 {
		cfg.CertTTL = 90 * 24 * time.Hour
	}
	if cfg.EnrollTTL == 0 {
		cfg.EnrollTTL = 15 * time.Minute
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}

	serverCertPEM, serverKeyPEM, err := cfg.CA.IssueServer(cfg.ServerName, cfg.CertTTL)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := mtls.ServerTLSConfigVerifyOptional(serverCertPEM, serverKeyPEM, cfg.CA.Pool())
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:        cfg,
		ca:         cfg.CA,
		tokens:     enrollment.NewTokenStore(),
		fleet:      fleet.NewService(cfg.FleetSigner, cfg.FleetKeyID),
		registry:   heartbeat.NewRegistry(),
		stats:      &statsCache{},
		dispatcher: command.NewDispatcher(cfg.FleetSigner, time.Minute),
		auditor:    authz.NewMemAuditor(),
		owners:     newOwnerCache(),
		approvals:  approval.NewStore(approval.DefaultTTL),
		chats:      cfg.Chats,
	}

	// Per-tenant enrichment. Built before the gRPC server so the ingest sink
	// can be wrapped: the tenant profile is fed FROM the ingest stream, never
	// by querying the telemetry table — that aggregate is the query shape that
	// took this control plane down on 2026-08-05.
	s.enrich = newTenantEnricher(loadIntelSet(cfg.IntelDir, cfg.Logf), cfg.BaselineWarmup)
	s.enrich.store = cfg.BaselineStore
	// Restored HERE, in New, rather than in Serve: ingest can begin the instant
	// the gRPC server starts, and a record arriving before the restore would
	// create an empty profile that Restore then overwrites — losing whatever
	// arrived in between and, worse, making the loss depend on timing.
	s.enrich.restore(cfg.Logf)
	// Same feeds.yaml the sensors read, from the same directory layout, so the
	// control plane's tenant-wide view is matched against the same indicators
	// the sensors scored against. A control plane richer or poorer in intel
	// than its own fleet reports findings the fleet never saw, or misses ones
	// it did.
	if refresh, rerr := intel.LoadRefreshConfig(cfg.IntelDir); rerr != nil {
		cfg.Logf("[intel] feed refresh DISABLED — %v", rerr)
	} else if !cfg.IntelRefresh.Enabled() {
		cfg.IntelRefresh = refresh
	}
	if cfg.IntelRefresh.Dir == "" {
		cfg.IntelRefresh.Dir = cfg.IntelDir
	}
	if cfg.IntelRefresh.Enabled() && s.enrich.set != nil {
		s.intelRefresh = intel.NewRefresher(cfg.IntelRefresh, s.enrich.set)
	}
	if s.enrich.set != nil {
		logEnrichmentStartup(s.enrich.set.Status(), len(s.enrich.tenants()))
	}

	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	ebpfsocv1.RegisterEnrollmentServiceServer(gs, enrollment.NewServer(cfg.CA, s.tokens, cfg.CertTTL, cfg.UplinkEndpoint, cfg.CommandEndpoint))
	// Store satisfies ingest.Sink; when a firehose is configured, fan out to it.
	var telemetrySink ingest.Sink = cfg.Store
	if cfg.Firehose != nil {
		telemetrySink = ingest.NewFanOut(cfg.Store, cfg.Logf, cfg.Firehose)
	}
	// Enrichment sits in FRONT of the store, not behind it: it needs the
	// tenant-stamped record, and it must never be able to stop the store write.
	// See Sink.Put.
	ebpfsocv1.RegisterTelemetryServiceServer(gs, ingest.NewServer(WrapSink(telemetrySink, s.enrich)))
	ebpfsocv1.RegisterCommandServiceServer(gs, s.dispatcher)
	ebpfsocv1.RegisterHeartbeatServiceServer(gs, heartbeat.NewServer(s.registry, 30*time.Second))
	ebpfsocv1.RegisterPolicyServiceServer(gs, fleet.NewPolicyServer(s.fleet))
	s.gs = gs
	s.httpH = s.buildHTTP()
	return s, nil
}

// GRPC is the agent-facing mTLS gRPC server.
func (s *Server) GRPC() *grpc.Server { return s.gs }

// HTTP is the operator HTTP handler.
func (s *Server) HTTP() http.Handler { return s.httpH }

// CABundlePEM is the trust anchor agents pin.
func (s *Server) CABundlePEM() []byte { return s.ca.CertPEM() }

// Tokens is the enrollment token store (operators mint via the HTTP admin API).
func (s *Server) Tokens() *enrollment.TokenStore { return s.tokens }

// Fleet is the policy-bundle / rollout service.
func (s *Server) Fleet() *fleet.Service { return s.fleet }

// Serve listens on grpcAddr (mTLS) and httpAddr and runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, grpcAddr, httpAddr string) error {
	s.selfAddr = httpAddr
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	httpLis, err := net.Listen("tcp", httpAddr)
	if err != nil {
		_ = grpcLis.Close()
		return err
	}
	httpSrv := &http.Server{Handler: s.httpH, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- s.gs.Serve(grpcLis) }()
	go func() { errc <- httpSrv.Serve(httpLis) }()

	// The feed refresher, started HERE rather than in New: New builds a server
	// without owning a lifetime, and a goroutine started there would outlive
	// every test that constructs one. It was constructed and never run for one
	// commit, which is the shape of bug this whole package is written to make
	// visible — /api/intel would have reported refresh enabled while nothing
	// ever fetched.
	if s.intelRefresh != nil {
		go s.intelRefresh.Run(ctx)
	}
	// Per-tenant profile persistence. Started alongside the refresher and for
	// the same reason: New builds a server without owning a lifetime.
	go s.enrich.runFlush(ctx, 5*time.Minute, s.cfg.Logf)
	s.cfg.Logf("[controlplane] gRPC(mTLS)=%s http=%s", grpcLis.Addr(), httpLis.Addr())

	select {
	case <-ctx.Done():
		s.gs.GracefulStop()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return ctx.Err()
	case err := <-errc:
		s.gs.Stop()
		_ = httpSrv.Close()
		return err
	}
}
