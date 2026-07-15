// Package cpclient is the agent's control-plane client: it enrolls once, then
// runs the three agent→CP / CP→agent loops (telemetry drain, heartbeat, command
// stream) over a single mTLS connection until its context is cancelled.
//
// AUTONOMY (architecture.md §6, the moat): every loop here is best-effort and
// isolated from enforcement. Enrollment retries, drains fail soft, and a down
// control plane simply means telemetry buffers locally and no new commands
// arrive — the agent keeps enforcing its last-applied policy regardless. Nothing
// in this package can block or disable in-kernel containment.
package cpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// Config drives a control-plane client. Endpoint + BootstrapToken + CABundlePEM
// are required; the rest have sane defaults.
type Config struct {
	Endpoint       string // control-plane host:port
	ServerName     string // TLS server name (must match the CP cert SAN)
	BootstrapToken string // one-time enrollment token (only needed to first-enroll)
	CABundlePEM    []byte // pinned CA trusted during bootstrap

	// StateDir persists the issued identity (cert/key/CA) so a restart reuses
	// it instead of consuming a fresh one-time bootstrap token. Empty keeps the
	// old behaviour: enroll in-memory every start.
	StateDir string

	AgentInfo *ebpfsocv1.AgentInfo

	// Optional loops — a nil field disables that loop.
	Buffer    *uplink.Buffer                     // telemetry to drain
	Processor *command.Processor                 // applies inbound commands
	Heartbeat func() *ebpfsocv1.HeartbeatRequest // builds each heartbeat

	DrainInterval      time.Duration
	HeartbeatInterval  time.Duration
	RenewCheckInterval time.Duration // how often to check whether the cert needs renewal
	MaxBatch           int
	Backoff            time.Duration

	OnEnrolled func(*enrollment.Enrolled) // optional callback with the identity
	Logf       func(format string, args ...any)
}

func (c *Config) withDefaults() {
	if c.DrainInterval <= 0 {
		c.DrainInterval = 5 * time.Second
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 30 * time.Second
	}
	if c.RenewCheckInterval <= 0 {
		c.RenewCheckInterval = 6 * time.Hour
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = 256
	}
	if c.Backoff <= 0 {
		c.Backoff = 5 * time.Second
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Run enrolls (retrying until success or ctx cancellation), opens the mTLS
// connection, and runs the enabled loops until ctx is done. It returns ctx.Err()
// on shutdown, or an error only if enrollment produced an unusable identity.
func Run(ctx context.Context, cfg Config) error {
	cfg.withDefaults()

	en, reused, err := acquireIdentity(ctx, &cfg)
	if err != nil {
		return err
	}
	if cfg.OnEnrolled != nil {
		cfg.OnEnrolled(en)
	}
	if reused {
		cfg.Logf("[cpclient] reused persisted identity agent_id=%s (no bootstrap token needed)", en.AgentID)
	} else {
		cfg.Logf("[cpclient] enrolled agent_id=%s", en.AgentID)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(en.CABundlePEM) {
		return errors.New("cpclient: enrollment returned an unparseable CA bundle")
	}
	holder, err := newIdentityHolder(en)
	if err != nil {
		return err
	}
	// Dynamic client cert: after renewal the next handshake uses the new cert
	// without rebuilding cc; the live connection is unaffected.
	tlsCfg := mtls.DynamicClientTLSConfig(holder.cert, pool, cfg.ServerName)
	cc, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer cc.Close()

	done := make(chan struct{})
	running := 0
	launch := func(fn func()) {
		running++
		go func() { defer func() { done <- struct{}{} }(); fn() }()
	}

	if cfg.Buffer != nil {
		launch(func() { drainLoop(ctx, ebpfsocv1.NewTelemetryServiceClient(cc), &cfg) })
	}
	if cfg.Heartbeat != nil {
		launch(func() { heartbeatLoop(ctx, ebpfsocv1.NewHeartbeatServiceClient(cc), &cfg) })
	}
	if cfg.Processor != nil {
		launch(func() { commandLoop(ctx, ebpfsocv1.NewCommandServiceClient(cc), &cfg) })
	}
	// Renewal always runs — it keeps the identity valid so the other loops
	// never lose their credential (best-effort, like every loop here).
	launch(func() { renewalLoop(ctx, cc, &cfg, holder) })

	for i := 0; i < running; i++ {
		<-done
	}
	return ctx.Err()
}

// identityHolder holds the agent's current mTLS identity behind a mutex so the
// renewal loop can swap in a fresh cert while GetClientCertificate reads it.
type identityHolder struct {
	mu      sync.RWMutex
	en      *enrollment.Enrolled
	tlsCert *tls.Certificate
}

func newIdentityHolder(en *enrollment.Enrolled) (*identityHolder, error) {
	h := &identityHolder{}
	if err := h.set(en); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *identityHolder) set(en *enrollment.Enrolled) error {
	c, err := tls.X509KeyPair(en.CertPEM, en.KeyPEM)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.en, h.tlsCert = en, &c
	h.mu.Unlock()
	return nil
}

func (h *identityHolder) cert() *tls.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tlsCert
}

func (h *identityHolder) enrolled() *enrollment.Enrolled {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.en
}

// renewalLoop rotates the client cert before it expires. It checks periodically
// and, once the current cert is inside renewWindow of expiry, calls Renew over
// the existing mTLS connection (no bootstrap token), persists the new identity,
// and hands it to the holder so the next handshake uses it. Renewal is
// best-effort: a failure leaves the still-valid cert in place and retries.
func renewalLoop(ctx context.Context, cc *grpc.ClientConn, cfg *Config, holder *identityHolder) {
	t := time.NewTicker(cfg.RenewCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		leaf, err := leafFromPEM(holder.enrolled().CertPEM)
		if err != nil {
			cfg.Logf("[cpclient] renewal: current cert unparseable: %v", err)
			continue
		}
		if time.Until(leaf.NotAfter) > renewWindow {
			continue // still comfortably valid
		}
		renewed, err := enrollment.Renew(ctx, cc, cfg.AgentInfo)
		if err != nil {
			if ctx.Err() == nil {
				cfg.Logf("[cpclient] renewal failed: %v (current cert still valid; will retry)", err)
			}
			continue
		}
		if err := holder.set(renewed); err != nil {
			cfg.Logf("[cpclient] renewal: issued cert unusable: %v", err)
			continue
		}
		if err := SaveIdentity(cfg.StateDir, renewed); err != nil {
			cfg.Logf("[cpclient] renewal: persist failed: %v (rotated in memory only)", err)
		}
		cfg.Logf("[cpclient] renewed certificate agent_id=%s", renewed.AgentID)
	}
}

// acquireIdentity returns a usable mTLS identity and whether it was reused from
// disk. It prefers a valid persisted identity in StateDir (no bootstrap token
// consumed — the restart-safe path); otherwise it enrolls with the one-time
// token and persists the result for next time. A corrupt persisted identity is
// logged and treated as absent so the agent can recover by re-enrolling.
func acquireIdentity(ctx context.Context, cfg *Config) (*enrollment.Enrolled, bool, error) {
	if en, ok, err := LoadIdentity(cfg.StateDir); err != nil {
		cfg.Logf("[cpclient] persisted identity unreadable: %v (will re-enroll)", err)
	} else if ok {
		return en, true, nil
	}
	if cfg.BootstrapToken == "" {
		return nil, false, errors.New("cpclient: no valid persisted identity in state-dir and no bootstrap token to enroll")
	}
	en, err := enrollWithRetry(ctx, cfg)
	if err != nil {
		return nil, false, err
	}
	if err := SaveIdentity(cfg.StateDir, en); err != nil {
		cfg.Logf("[cpclient] warning: could not persist identity: %v (will re-enroll next start)", err)
	}
	return en, false, nil
}

func enrollWithRetry(ctx context.Context, cfg *Config) (*enrollment.Enrolled, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CABundlePEM) {
		return nil, errors.New("cpclient: pinned CA bundle is unparseable")
	}
	boot := credentials.NewTLS(mtls.BootstrapTLSConfig(pool, cfg.ServerName))
	for {
		cc, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(boot))
		if err == nil {
			en, enErr := enrollment.Enroll(ctx, cc, cfg.BootstrapToken, cfg.AgentInfo)
			cc.Close()
			if enErr == nil {
				return en, nil
			}
			err = enErr
		}
		cfg.Logf("[cpclient] enrollment failed: %v (retrying)", err)
		if !sleep(ctx, cfg.Backoff) {
			return nil, ctx.Err()
		}
	}
}

func drainLoop(ctx context.Context, tc ebpfsocv1.TelemetryServiceClient, cfg *Config) {
	t := time.NewTicker(cfg.DrainInterval)
	defer t.Stop()
	for {
		if err := uplink.DrainOnce(ctx, tc, cfg.Buffer, cfg.MaxBatch); err != nil && ctx.Err() == nil {
			cfg.Logf("[cpclient] telemetry drain: %v (buffered; will retry)", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func heartbeatLoop(ctx context.Context, hc ebpfsocv1.HeartbeatServiceClient, cfg *Config) {
	t := time.NewTicker(cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		if _, err := hc.Heartbeat(ctx, cfg.Heartbeat()); err != nil && ctx.Err() == nil {
			cfg.Logf("[cpclient] heartbeat: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func commandLoop(ctx context.Context, cc ebpfsocv1.CommandServiceClient, cfg *Config) {
	for ctx.Err() == nil {
		if err := command.RunCommands(ctx, cc, cfg.Processor); err != nil && ctx.Err() == nil {
			cfg.Logf("[cpclient] command stream: %v (reconnecting)", err)
		}
		if !sleep(ctx, cfg.Backoff) {
			return
		}
	}
}

// sleep waits d or until ctx is done; it returns false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
