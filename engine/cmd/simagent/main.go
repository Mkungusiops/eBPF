// Command simagent is a LOCAL-DEV data generator. It enrolls against the control
// plane like a real agent (mTLS), then streams synthetic telemetry (events /
// alerts / decisions) into the central store and reports synthetic choke/device
// heartbeats into the registry — so the console renders with realistic tenant
// data when there is no live eBPF agent (e.g. the OrbStack local mirror). It is
// NOT built into any production path; it only exercises the real client loop.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/cpclient"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

var (
	binaries = []string{"/usr/bin/curl", "/bin/sh", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/sudo",
		"/usr/bin/wget", "/bin/bash", "/usr/bin/nc", "/usr/local/bin/pg_isready", "/usr/sbin/ip", "/usr/bin/install"}
	policies = []string{"privilege-escalation", "sensitive-file-access", "override-credential-read", "reverse-shell", "container-escape"}
	// MITRE ATT&CK technique + tactic per policy (feeds the coverage panel).
	mitreByPolicy = map[string][2]string{
		"privilege-escalation":     {"T1548", "privilege-escalation"},
		"sensitive-file-access":    {"T1005", "collection"},
		"override-credential-read": {"T1003", "credential-access"},
		"reverse-shell":            {"T1059", "execution"},
		"container-escape":         {"T1611", "privilege-escalation"},
	}
	sevs     = []string{"critical", "high", "medium", "low", "info"}
	sevScore = map[string]int32{"critical": 92, "high": 74, "medium": 45, "low": 18, "info": 5}
	// Every template MUST consume both args (%s binary, %d score): the single
	// Sprintf below always passes two. A template with only %s made Go append
	// "%!(EXTRA int32=45)" to the alert title, which then rendered in the console.
	alertTitle = []string{
		"Suspicious chain: /bin/sh → %s (score %d)",
		"Sensitive file accessed: /etc/shadow by %s (score %d)",
		"Privilege escalation attempt via %s (score %d)",
		"Reverse shell indicators from %s (score %d)",
		"Credential store read by %s (score %d)",
	}
)

func execID(i int) string { return fmt.Sprintf("ZXhlYy0%08d", i) }

func evEvent(seq int) *ebpfsocv1.TelemetryRecord {
	b := binaries[rand.Intn(len(binaries))]
	ev := &ebpfsocv1.ProcessEvent{
		OccurredAt: timestamppb.Now(), EventType: "process_exec",
		Pid: uint32(2000000 + rand.Intn(600000)), ParentPid: uint32(1 + rand.Intn(4000)),
		ExecId: execID(seq), Binary: b, Args: "--sim run", Uid: uint32(rand.Intn(1000)),
		PolicyName: policies[rand.Intn(len(policies))],
	}
	if seq%3 == 0 { // a network-connection event (feeds IOCs + Network panels)
		ev.EventType = "process_kprobe"
		ev.DestIp = fmt.Sprintf("185.%d.%d.%d", rand.Intn(255), rand.Intn(255), 1+rand.Intn(254))
		ev.DestPort = uint32([]int{443, 4444, 8080, 53, 22, 9001}[rand.Intn(6)])
		ev.Proto = "tcp"
		ev.RemoteIp = fmt.Sprintf("10.0.%d.%d", rand.Intn(255), 1+rand.Intn(254))
	}
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("ev-%d-%d", seq, time.Now().UnixNano()),
		Payload:  &ebpfsocv1.TelemetryRecord_Event{Event: ev},
	}
}

func evAlert(seq int) *ebpfsocv1.TelemetryRecord {
	sev := sevs[rand.Intn(len(sevs))]
	b := binaries[rand.Intn(len(binaries))]
	pol := policies[rand.Intn(len(policies))]
	mt := mitreByPolicy[pol]
	title := fmt.Sprintf(alertTitle[rand.Intn(len(alertTitle))], b, sevScore[sev])
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("al-%d-%d", seq, time.Now().UnixNano()),
		Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
			OccurredAt: timestamppb.Now(), Severity: sev, Title: title,
			Description: "Detected by " + pol + " policy on a monitored host.",
			ExecId:      execID(seq), Score: sevScore[sev],
			MitreId: mt[0], Tactic: mt[1],
		}},
	}
}

func evDecision(seq int) *ebpfsocv1.TelemetryRecord {
	acts := []string{"throttle", "tarpit", "quarantine", "sever"}
	a := acts[rand.Intn(len(acts))]
	b := binaries[rand.Intn(len(binaries))]
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("de-%d-%d", seq, time.Now().UnixNano()),
		Payload: &ebpfsocv1.TelemetryRecord_Decision{Decision: &ebpfsocv1.Decision{
			OccurredAt: timestamppb.Now(), Action: a, FromState: "pristine", ToState: a + "d",
			ExecId: execID(seq), Pid: uint32(2000000 + rand.Intn(600000)), Binary: b,
			Score: 40 + int32(rand.Intn(60)), Reason: "score exceeded " + a + " threshold (detect-only audit)",
			DryRun: true, Backend: "cgroup", Outcome: "ok",
		}},
	}
}

func seed(buf *uplink.Buffer) {
	for i := 0; i < 220; i++ {
		buf.Enqueue(evEvent(i))
	}
	for i := 0; i < 80; i++ {
		buf.Enqueue(evAlert(i))
	}
	for i := 0; i < 25; i++ {
		buf.Enqueue(evDecision(i))
	}
}

// trickle keeps enqueuing a light stream so the store grows and the SSE live
// feed shows movement.
func trickle(ctx context.Context, buf *uplink.Buffer) {
	seq := 100000
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			seq++
			buf.Enqueue(evEvent(seq))
			if seq%3 == 0 {
				buf.Enqueue(evAlert(seq))
			}
			if seq%7 == 0 {
				buf.Enqueue(evDecision(seq))
			}
		}
	}
}

// simApplier is the sim-agent's command target. It keeps mutable choke + device
// + mode state so console actions (jail/thaw, device jail/thaw, SetMode) are
// reflected in the next heartbeat — the operator sees the change. Satisfies
// command.Applier.
type simApplier struct {
	mu      sync.Mutex
	chokes  map[string]*ebpfsocv1.ChokeSummary // key = exec_id, else pid:<n>
	devices map[string]string                  // mac -> state
	// The two enforcement planes arm INDEPENDENTLY, so the sim has to model
	// them independently too. Collapsing them into one field is not a harmless
	// simplification: it reproduces the exact defect the real agent had, where
	// arming the device plane silently armed process enforcement instead.
	mode       ebpfsocv1.EnforcementMode
	deviceMode ebpfsocv1.EnforcementMode
	killed     bool
	deviceKill bool
}

func newSimApplier() *simApplier {
	a := &simApplier{
		chokes:     map[string]*ebpfsocv1.ChokeSummary{},
		devices:    map[string]string{},
		mode:       ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY,
		deviceMode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY,
	}
	for i, st := range []string{"severed", "severed", "quarantined", "tarpit", "throttled", "severed", "quarantined"} {
		id := execID(500 + i)
		a.chokes[id] = &ebpfsocv1.ChokeSummary{
			ExecId: id, Pid: uint32(2500000 + i), Binary: binaries[i%len(binaries)], State: st, Score: 40 + int32(i*7),
		}
	}
	for i, m := range []string{"fa:18:7b:2e:19:0d", "42:70:72:90:ae:3c", "ae:8d:d0:89:13:26", "12:34:56:78:9a:bc",
		"d2:68:e2:12:6a:72", "8e:cc:95:df:23:98", "f6:21:5c:41:b6:ba"} {
		st := "pristine"
		if i == 2 {
			st = "throttled"
		}
		a.devices[m] = st
	}
	return a
}

func tierState(tier string) string {
	switch tier {
	case "throttle":
		return "throttled"
	case "tarpit":
		return "tarpit"
	case "quarantine":
		return "quarantined"
	case "sever":
		return "severed"
	}
	return "quarantined"
}

func (a *simApplier) key(execID string, pid uint32) string {
	if execID != "" {
		return execID
	}
	return fmt.Sprintf("pid:%d", pid)
}

func (a *simApplier) Jail(execID string, pid uint32, tier string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac, ok := strings.CutPrefix(execID, "device:"); ok {
		a.devices[mac] = tierState(tier)
		return nil
	}
	a.chokes[a.key(execID, pid)] = &ebpfsocv1.ChokeSummary{
		ExecId: execID, Pid: pid, Binary: "console-jailed", State: tierState(tier), Score: 95,
	}
	return nil
}
func (a *simApplier) Thaw(execID string, pid uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac, ok := strings.CutPrefix(execID, "device:"); ok {
		a.devices[mac] = "pristine"
		return nil
	}
	delete(a.chokes, a.key(execID, pid))
	return nil
}

// PLANE_DEVICE targets the network plane; anything else (including
// UNSPECIFIED, what an older control plane sends) targets the process plane.
func (a *simApplier) SetMode(m ebpfsocv1.EnforcementMode, plane ebpfsocv1.Plane) error {
	a.mu.Lock()
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		a.deviceMode = m
	} else {
		a.mode = m
	}
	a.mu.Unlock()
	return nil
}
func (a *simApplier) KillSwitch(halt bool, _ string, plane ebpfsocv1.Plane) error {
	a.mu.Lock()
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		a.deviceKill = halt
	} else {
		a.killed = halt
	}
	a.mu.Unlock()
	return nil
}
func (a *simApplier) SetThresholds(_, _, _, _ int32) error { return nil }
func (a *simApplier) ApplyPreset(string) error             { return nil }
func (a *simApplier) SetProtectedList(_, _ []string) error { return nil }

// heartbeat is the synthetic data-plane snapshot; choke/device/mode reflect live
// console actions.
func (a *simApplier) heartbeat() *ebpfsocv1.HeartbeatRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	chokes := make([]*ebpfsocv1.ChokeSummary, 0, len(a.chokes))
	for _, c := range a.chokes {
		chokes = append(chokes, c)
	}
	devices := make([]*ebpfsocv1.DeviceSummary, 0, len(a.devices))
	for mac, st := range a.devices {
		devices = append(devices, &ebpfsocv1.DeviceSummary{Mac: mac, State: st})
	}
	return &ebpfsocv1.HeartbeatRequest{
		DataPlane: &ebpfsocv1.DataPlaneState{
			Mode: a.mode,
			// A sim agent has no kernel data plane; say so rather than letting
			// the console infer one from a registered agent.
			DevicePlane: "noop",
			DeviceLinks: 0,
			DeviceMode:  a.deviceMode,
		},
		BufferDepth:          0,
		AppliedPolicyVersion: "pol-sim-1",
		Chokes:               chokes,
		Devices:              devices,
	}
}

func mintToken(cpHTTP, adminToken, tenant string) (string, string) {
	body, _ := json.Marshal(map[string]string{"tenant": tenant})
	req, _ := http.NewRequest("POST", cpHTTP+"/api/admin/enroll-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("mint token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("mint token: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
		CA    string `json:"ca_bundle_pem"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Token, out.CA
}

func main() {
	cpHTTP := flag.String("cp-http", "http://127.0.0.1:9090", "control-plane HTTP")
	cpGRPC := flag.String("cp-grpc", "127.0.0.1:9443", "control-plane mTLS gRPC")
	adminToken := flag.String("admin-token", "", "CP admin bearer (mints the enroll token)")
	tenant := flag.String("tenant", "adanian-internal", "tenant to enroll for")
	serverName := flag.String("server-name", "localhost", "CP TLS server name (cert SAN)")
	stateDir := flag.String("state-dir", "", "persist the enrolled identity here")
	label := flag.String("label", "sim-agent", "agent hostname label")
	fleetPub := flag.String("fleet-pubkey", "", "path to the fleet signing pubkey (hex); enables the command channel so console jail/thaw acks + updates state")
	flag.Parse()

	tok, ca := mintToken(*cpHTTP, *adminToken, *tenant)
	log.Printf("[simagent] minted enroll token for tenant=%s (ca %d bytes)", *tenant, len(ca))

	buf := uplink.NewBuffer()
	seed(buf)
	applier := newSimApplier()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go trickle(ctx, buf)

	cfg := cpclient.Config{
		Endpoint: *cpGRPC, ServerName: *serverName,
		BootstrapToken: tok, CABundlePEM: []byte(ca),
		StateDir: *stateDir,
		AgentInfo: &ebpfsocv1.AgentInfo{
			AgentVersion: "sim-0.1", Kernel: "6.8.0-sim", Hostname: *label, Arch: "amd64", BtfAvailable: true,
		},
		Buffer:            buf,
		Heartbeat:         applier.heartbeat,
		DrainInterval:     2 * time.Second,
		HeartbeatInterval: 5 * time.Second,
		Logf:              log.Printf,
	}
	// Command channel: verify fleet-signed commands, apply to the sim state.
	if *fleetPub != "" {
		if raw, err := os.ReadFile(*fleetPub); err == nil {
			if pub, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil {
				if v, err := signing.VerifierFromPublicKey(pub); err == nil {
					cfg.Processor = command.NewProcessor(v, applier, nil)
					log.Printf("[simagent] command channel enabled (fleet pubkey pinned)")
				}
			}
		} else {
			log.Printf("[simagent] no fleet pubkey at %s yet — command channel disabled", *fleetPub)
		}
	}
	if err := cpclient.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		log.Fatalf("[simagent] %v", err)
	}
	os.Exit(0)
}
