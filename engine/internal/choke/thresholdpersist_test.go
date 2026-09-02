package choke

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

func persistGateway(t *testing.T, st *store.Store, deployed, start circuit.Config) *Gateway {
	t.Helper()
	return NewGateway(Config{
		Store: st, Enforcer: &enforce.Multi{}, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), Policies: policy.NewSet(),
		Thresholds: start, DeployedThresholds: deployed,
	})
}

func TestARuntimeLadderChangeIsWrittenDown(t *testing.T) {
	// Settings said "Live · not saved" honestly, but the consequence was that
	// an unattended reboot silently restored the deployed ladder.
	st, err := store.New(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	deployed := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	g := persistGateway(t, st, deployed, deployed)

	if _, err := g.SetThresholds(circuit.Config{
		ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40}); err != nil {
		t.Fatal(err)
	}

	rs, err := st.RuntimeSettingFor(ThresholdsKey)
	if err != nil {
		t.Fatalf("the change was applied and not recorded — it reverts on restart: %v", err)
	}
	if rs.Value != "10/20/30/40" {
		t.Fatalf("stored %q, want the new ladder", rs.Value)
	}
	// The deployed value at the moment of the override, so a later deploy can
	// take precedence back.
	if rs.ConfigAtSet != "20/50/120/200" {
		t.Fatalf("config_at_set = %q, want the DEPLOYED ladder, not the running one", rs.ConfigAtSet)
	}
}

func TestASecondOverrideStillRecordsTheDeployedBaseline(t *testing.T) {
	// The trap: if the gateway took its running ladder as the baseline, the
	// second override would record the FIRST override as "what the deploy
	// said", the deploy would look unchanged forever, and it could never take
	// precedence back.
	st, err := store.New(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	deployed := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	// Started from a restored override, which is the real startup shape.
	g := persistGateway(t, st, deployed, circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40})

	if _, err := g.SetThresholds(circuit.Config{
		ThrottleAt: 11, TarpitAt: 21, QuarantineAt: 31, SeverAt: 41}); err != nil {
		t.Fatal(err)
	}
	rs, _ := st.RuntimeSettingFor(ThresholdsKey)
	if rs.ConfigAtSet != "20/50/120/200" {
		t.Fatalf("config_at_set = %q — the running ladder was mistaken for the deployed one", rs.ConfigAtSet)
	}
}

func TestARefusedLadderIsNotPersisted(t *testing.T) {
	st, err := store.New(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	deployed := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	g := persistGateway(t, st, deployed, deployed)

	// Descending: the shape that once zeroed sever_at and severed a fleet.
	if _, err := g.SetThresholds(circuit.Config{ThrottleAt: 200, SeverAt: 20}); err == nil {
		t.Fatal("an invalid ladder was accepted")
	}
	if _, err := st.RuntimeSettingFor(ThresholdsKey); err == nil {
		t.Fatal("a REFUSED ladder was written down and would be restored on the next restart")
	}
}

func TestAStoredLadderIsValidatedOnTheWayBackIn(t *testing.T) {
	// Read at startup with no operator watching. A corrupt row that zeroed
	// sever_at would sever everything this host tracks the moment enforcement
	// armed, so an unparseable or invalid value must be refused, not used.
	for _, bad := range []string{"", "nonsense", "10/20/30", "0/0/0/0", "200/50/120/20", "-1/2/3/4"} {
		if _, ok := ParseThresholds(bad); ok {
			t.Fatalf("ParseThresholds(%q) accepted a ladder that must never be restored", bad)
		}
	}
	if got, ok := ParseThresholds("20/50/120/200"); !ok || got.SeverAt != 200 {
		t.Fatalf("a valid stored ladder was refused: %+v ok=%v", got, ok)
	}
}
