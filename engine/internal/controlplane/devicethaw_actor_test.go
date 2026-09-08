package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// A DEVICE RELEASE THAT RECORDS NEITHER WHO NOR WHY.
//
// handleDeviceThaw decoded the operator's reason into its body struct and never
// touched it again, and — unlike releaseFleet twenty lines up in the same file —
// never stamped cmd.Actor before dispatch. So releasing a LAN device, the action
// that puts a possibly-compromised host back on the network, produced an agent
// audit row with no operator on it (which reads as the platform having acted on
// its own) and no record anywhere of the justification the operator typed.
//
// These tests watch the command as the AGENT receives it, because the actor's
// whole purpose is what the agent writes into its tamper-evident row. Asserting
// it on a struct this package still owns would prove nothing about the wire.

// fakeAgentStream is the agent end of CommandService.Commands: it collects the
// commands the dispatcher sends and answers each one APPLIED, as an agent
// holding the named MAC on its segment would.
type fakeAgentStream struct {
	grpc.ServerStream
	ctx  context.Context
	got  chan *ebpfsocv1.Command
	acks chan *ebpfsocv1.CommandAck
}

func (f *fakeAgentStream) Context() context.Context { return f.ctx }

func (f *fakeAgentStream) Send(c *ebpfsocv1.Command) error {
	f.got <- c
	f.acks <- &ebpfsocv1.CommandAck{
		CommandId: c.GetCommandId(), Status: ebpfsocv1.CommandAck_STATUS_APPLIED,
		TargetMatch: ebpfsocv1.CommandAck_TARGET_MATCH_DEVICE,
		Detail:      "tc rule removed",
	}
	return nil
}

func (f *fakeAgentStream) Recv() (*ebpfsocv1.CommandAck, error) {
	select {
	case a := <-f.acks:
		return a, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("no ack")
	}
}

// connectFakeAgent parks a stream for one agent and returns the channel the
// commands it is sent arrive on. The identity comes from a verified client
// certificate, which is where the dispatcher reads the agent id from — the same
// mTLS boundary the estate uses.
func connectFakeAgent(t *testing.T, s *Server, tenant, agent string) <-chan *ebpfsocv1.Command {
	t.Helper()
	cert := &x509.Certificate{Subject: pkix.Name{Organization: []string{tenant}, CommonName: agent}}
	ctx, cancel := context.WithCancel(peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	}))
	t.Cleanup(cancel)

	stream := &fakeAgentStream{
		ctx:  ctx,
		got:  make(chan *ebpfsocv1.Command, 8),
		acks: make(chan *ebpfsocv1.CommandAck, 8),
	}
	go func() { _ = s.dispatcher.Commands(stream) }()
	return stream.got
}

func awaitCommand(t *testing.T, got <-chan *ebpfsocv1.Command) *ebpfsocv1.Command {
	t.Helper()
	select {
	case c := <-got:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("no command reached the agent")
		return nil
	}
}

// TestDeviceThawStampsTheOperatorOnTheWire is the actor half of the defect.
func TestDeviceThawStampsTheOperatorOnTheWire(t *testing.T) {
	s := targetingServer(t)
	got := connectFakeAgent(t, s, "acme", "agent-a")

	code, body := fleetWrite(t, s, s.handleDeviceThaw, "POST", "/api/choke/device-thaw?tenant=acme",
		map[string]any{"macs": []string{"02:00:00:00:00:10"}, "reason": "IR-4821 closed, device cleared"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}

	cmd := awaitCommand(t, got)
	if cmd.GetThaw().GetExecId() != "device:02:00:00:00:00:10" {
		t.Fatalf("the agent was sent %v, want the device thaw", cmd.GetAction())
	}
	if cmd.GetActor() != "admin" {
		t.Fatalf("actor = %q, want the operator who ordered the release — an unattributed release "+
			"lands in the agent's audit row as the platform acting on its own", cmd.GetActor())
	}
	// The actor is signed over, so a stamped command whose signature does not
	// cover it is attribution anyone on the path could rewrite.
	if len(cmd.GetSignature()) == 0 {
		t.Fatal("the release was dispatched unsigned")
	}
}

// TestDeviceThawRecordsTheOperatorsReason is the reason half.
//
// The Thaw message on the wire carries exec_id and pid and nothing else, so the
// reason CANNOT reach the agent's row — there is no field for it. It is
// recorded where this control plane can hold it instead: the operator trail,
// against the tenant and the operator, and the journal.
func TestDeviceThawRecordsTheOperatorsReason(t *testing.T) {
	s := targetingServer(t)
	aud, ok := s.auditor.(*authz.MemAuditor)
	if !ok {
		t.Fatalf("auditor is %T, want the in-memory one", s.auditor)
	}
	var journal []string
	s.cfg.Logf = func(format string, args ...any) {
		journal = append(journal, strings.TrimSpace(fmt.Sprintf(format, args...)))
	}

	const reason = "IR-4821 closed, device cleared by forensics"
	code, body := fleetWrite(t, s, s.handleDeviceThaw, "POST", "/api/choke/device-thaw?tenant=acme",
		map[string]any{"macs": []string{"02:00:00:00:00:10"}, "reason": reason})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}

	var found *authz.AuditRecord
	for _, rec := range aud.Records() {
		if rec.Action == "device-thaw" {
			r := rec
			found = &r
			break
		}
	}
	if found == nil {
		t.Fatalf("the operator's reason for a device release reached no record at all: %v", aud.Records())
	}
	if !strings.Contains(found.Detail, reason) {
		t.Fatalf("the recorded detail %q does not carry the reason the operator typed", found.Detail)
	}
	if !strings.Contains(found.Detail, "02:00:00:00:00:10") {
		t.Fatalf("the recorded detail %q does not say which device was released", found.Detail)
	}
	if found.Subject != "admin" || found.Tenant != "acme" {
		t.Fatalf("record = %+v, want the operator and the customer named", *found)
	}
	// The journal carries it too, which is the only place it survives for a
	// tenant-bound operator releasing their own devices — the trail elides
	// own-tenant allowed rows by design.
	if !containsSubstring(journal, reason) {
		t.Fatalf("the journal lines %v do not carry the operator's reason", journal)
	}
}

// An ABSENT reason is recorded as absent. The console omits the field entirely
// when the operator clears the box — it used to substitute the literal
// "operator thaw", and a justification nobody typed reads as though someone
// gave it — so the record has to state that none was given rather than invent
// one or say nothing.
func TestDeviceThawWithoutAReasonRecordsItsAbsence(t *testing.T) {
	s := targetingServer(t)
	aud := s.auditor.(*authz.MemAuditor)

	code, body := fleetWrite(t, s, s.handleDeviceThaw, "POST", "/api/choke/device-thaw?tenant=acme",
		map[string]any{"macs": []string{"02:00:00:00:00:10"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	for _, rec := range aud.Records() {
		if rec.Action == "device-thaw" {
			if !strings.Contains(rec.Detail, "(no reason given)") {
				t.Fatalf("detail = %q, want the absence stated", rec.Detail)
			}
			return
		}
	}
	t.Fatal("a reasonless device release was not recorded at all")
}

func containsSubstring(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}
