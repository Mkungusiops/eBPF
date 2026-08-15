package main

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/cpclient"
	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// sensorRegistry publishes the Tetragon client to the heartbeat, which asks the
// daemon what TracingPolicies the kernel actually has.
//
// The indirection exists because of ordering: the heartbeat closure is built
// while the control-plane config is assembled, which is before the event stream
// is dialled. The closure only ever reads this after startup, on a timer, from
// another goroutine — hence the lock rather than a plain field.
type sensorRegistry struct {
	mu sync.RWMutex
	c  tetragon.FineGuidanceSensorsClient
}

func (r *sensorRegistry) set(c tetragon.FineGuidanceSensorsClient) {
	r.mu.Lock()
	r.c = c
	r.mu.Unlock()
}

// kernelPolicies reports Tetragon's TracingPolicies as the KERNEL has them, for
// the heartbeat. This exists because the engine's enforcement mode is only half
// of a host's posture: a `Sigkill` in a loaded policy fires regardless of what
// mode the operator set, with no audit row and no way to reverse it, so a
// console rendering only the engine's mode can report "detect-only" while the
// kernel kills processes (threat-model EN-3).
//
// Read from the daemon rather than from the policy files on disk, because those
// disagree in both directions: a file edited but never reloaded still runs its
// old version, and a policy deleted at runtime comes back on the next restart if
// its file remains. Only the daemon knows what is actually loaded.
//
// Never fatal and never blocking: a nil return degrades the console to the old
// engine-only view, which is exactly the behaviour of an agent predating the
// field. Enforcement must not depend on the reporting path.
func (r *sensorRegistry) kernelPolicies(ctx context.Context) []*ebpfsocv1.KernelPolicy {
	r.mu.RLock()
	c := r.c
	r.mu.RUnlock()
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := c.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return nil
	}
	out := make([]*ebpfsocv1.KernelPolicy, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		kp := &ebpfsocv1.KernelPolicy{
			Name:    p.GetName(),
			Mode:    tracingPolicyMode(p.GetMode()),
			Enabled: p.GetState() == tetragon.TracingPolicyState_TP_STATE_ENABLED,
		}
		// Signal and Override are the actions that kill or divert a syscall.
		// Post is reporting and deliberately not counted here — counting it
		// would make every healthy detection look like enforcement.
		if ac := p.GetStats().GetActionCounters(); ac != nil {
			kp.EnforceActions = ac.GetSignal() + ac.GetOverride()
			kp.SuppressedActions = ac.GetMonitorSignal()
		}
		out = append(out, kp)
	}
	return out
}

// startControlPlane brings up the Phase 1 uplink and returns the telemetry
// buffer the sensing path tees into, or nil when the agent is standalone.
//
// Strictly additive: enforcement is already fully wired and running by the time
// this is called. When a control plane is configured the agent enrolls (mTLS)
// and runs the telemetry drain, heartbeat, and command loops in the background.
// A down or slow control plane only means telemetry buffers locally and no new
// commands arrive — the kernel keeps enforcing the last-applied policy. That is
// the autonomy moat, and it is why this returns a buffer instead of becoming a
// step the event path waits on.
func startControlPlane(ctx context.Context, cfg *agentConfig, stack *hoststack.Stack, hostname string, sensors *sensorRegistry) *uplink.Buffer {
	if cfg.controlPlane == "" {
		return nil
	}
	// First enrollment needs a one-time token + the pinned CA. A restart
	// with a persisted identity in -state-dir needs neither (it's reused).
	if cfg.cpStateDir == "" && (cfg.bootstrapToken == "" || cfg.caBundlePath == "") {
		log.Fatalf("controlplane: -controlplane requires -state-dir (persisted identity) or -bootstrap-token + -ca-bundle (first enrollment)")
	}
	var caPEM []byte
	if cfg.caBundlePath != "" {
		b, err := os.ReadFile(cfg.caBundlePath)
		if err != nil {
			log.Fatalf("controlplane: read -ca-bundle: %v", err)
		}
		caPEM = b
	}
	upBuf := uplink.NewBuffer()

	// The command channel activates only with a fleet signing key. Commands
	// are applied through the choke gateway with the SAME local
	// system-critical guardrails as score-driven enforcement, so a remote
	// command can never strip sudo/sshd protection.
	critBins := stack.SystemCriticalBinaries
	var proc *command.Processor
	if cfg.fleetPubKey != "" {
		raw, err := os.ReadFile(cfg.fleetPubKey)
		if err != nil {
			log.Fatalf("controlplane: read -fleet-pubkey: %v", err)
		}
		pub, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			log.Fatalf("controlplane: decode -fleet-pubkey: %v", err)
		}
		verifier, err := signing.VerifierFromPublicKey(pub)
		if err != nil {
			log.Fatalf("controlplane: -fleet-pubkey: %v", err)
		}
		proc = command.NewProcessor(verifier, gatewayApplier{gw: stack.Gateway, devGW: stack.DeviceGateway}, critBins)
		log.Printf("[controlplane] command channel enabled (%d protected binaries guardrail)", len(critBins))
	} else {
		log.Printf("[controlplane] command channel DISABLED (no -fleet-pubkey); telemetry + heartbeat only")
	}

	serverName := cfg.cpServerName
	if serverName == "" {
		serverName = hostOnly(cfg.controlPlane)
	}
	agentInfo := func() *ebpfsocv1.AgentInfo {
		return &ebpfsocv1.AgentInfo{Hostname: hostname, AgentVersion: agentVersion, Arch: runtime.GOARCH}
	}
	clientCfg := cpclient.Config{
		Endpoint:       cfg.controlPlane,
		ServerName:     serverName,
		BootstrapToken: cfg.bootstrapToken,
		CABundlePEM:    caPEM,
		StateDir:       cfg.cpStateDir,
		AgentInfo:      agentInfo(),
		Buffer:         upBuf,
		Processor:      proc,
		Heartbeat: func() *ebpfsocv1.HeartbeatRequest {
			// The uplink buffer sheds its oldest records once the backlog
			// cap is reached (uplink.DefaultMaxRecords). That keeps the
			// agent alive, but it means this host's telemetry has a HOLE,
			// and an operator must be able to find out. Reported every beat
			// while non-zero, not once: a gap that stopped being mentioned
			// reads as a gap that stopped happening.
			if n := upBuf.Dropped(); n > 0 {
				log.Printf("[uplink] TELEMETRY GAP: %d record(s) dropped since start "+
					"(backlog cap %d reached; control plane not acking)", n, uplink.DefaultMaxRecords)
			}
			// Read the kernel's policy set ONCE per heartbeat: the version
			// must fingerprint exactly the set being reported, and a second
			// call could observe a reload in between and disagree with it.
			kpols := sensors.kernelPolicies(ctx)
			return &ebpfsocv1.HeartbeatRequest{
				AgentInfo:            agentInfo(),
				AppliedPolicyVersion: policyVersion(kpols),
				DataPlane: &ebpfsocv1.DataPlaneState{
					Mode: gatewayMode(stack.Gateway),
					// Report the device plane truthfully: the control plane
					// used to assume "active" for any registered agent, which
					// showed a fleet as enforcing on the network plane while
					// every agent was running the noop backend.
					DevicePlane: stack.DeviceGateway.DataPlaneTier(),
					DeviceLinks: int32(stack.DeviceGateway.AttachedLinks()),
					// Real frame count, not a placeholder — see frames_seen
					// in common.proto for why the console needs it.
					FramesSeen:  stack.DeviceGateway.FramesSeen(),
					DevicesSeen: uint32(stack.DeviceGateway.DevicesSeen()),
					DeviceMode:  deviceGatewayMode(stack.DeviceGateway),
					// The other enforcement authority on this host. Without
					// it the console reports the engine's mode as if it were
					// the host's posture — see kernelPolicies.
					KernelPolicies: kpols,
				},
				BufferDepth: uint64(upBuf.PendingDepth()),
				Chokes:      chokeSummaries(stack.Gateway),
				Devices:     deviceSummaries(stack.DeviceGateway),
				// Drill detail for the console's Choke Gateway page. Without
				// these the multi-tenant console renders those panels empty
				// on every tenant, permanently.
				Buckets:   bucketSummaries(stack.Gateway),
				Cgroups:   cgroupSummaries(stack.Gateway),
				Processes: processSummaries(stack.Gateway),
			}
		},

		Logf: log.Printf,
	}
	go func() {
		if err := cpclient.Run(ctx, clientCfg); err != nil && ctx.Err() == nil {
			log.Printf("[controlplane] client stopped: %v", err)
		}
	}()
	log.Printf("[controlplane] uplink enabled → %s (tenant bound at enrollment)", cfg.controlPlane)
	return upBuf
}

// hostOnly returns the host part of a host:port endpoint, used as the default
// TLS server name for control-plane cert verification.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
