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
	"crypto/x509"
	"errors"
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
	BootstrapToken string // one-time enrollment token
	CABundlePEM    []byte // pinned CA trusted during bootstrap

	AgentInfo *ebpfsocv1.AgentInfo

	// Optional loops — a nil field disables that loop.
	Buffer    *uplink.Buffer                     // telemetry to drain
	Processor *command.Processor                 // applies inbound commands
	Heartbeat func() *ebpfsocv1.HeartbeatRequest // builds each heartbeat

	DrainInterval     time.Duration
	HeartbeatInterval time.Duration
	MaxBatch          int
	Backoff           time.Duration

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

	en, err := enrollWithRetry(ctx, &cfg)
	if err != nil {
		return err
	}
	if cfg.OnEnrolled != nil {
		cfg.OnEnrolled(en)
	}
	cfg.Logf("[cpclient] enrolled agent_id=%s", en.AgentID)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(en.CABundlePEM) {
		return errors.New("cpclient: enrollment returned an unparseable CA bundle")
	}
	tlsCfg, err := mtls.ClientTLSConfig(en.CertPEM, en.KeyPEM, pool, cfg.ServerName)
	if err != nil {
		return err
	}
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
	for i := 0; i < running; i++ {
		<-done
	}
	return ctx.Err()
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
