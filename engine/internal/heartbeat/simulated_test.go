package heartbeat

import (
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// cmd/simagent has always identified itself — AgentVersion "sim-0.1", Kernel
// "6.8.0-sim" — and nothing read it. So its telemetry landed in the same
// tenant ledger as real containment: on the live estate, 431 fabricated
// decisions sat beside real ones with nothing to tell them apart. An audit
// trail that cannot separate demo data from evidence is not an audit trail.

func TestASimulatorIsRecognised(t *testing.T) {
	for _, info := range []*ebpfsocv1.AgentInfo{
		{AgentVersion: "sim-0.1", Kernel: "6.8.0-sim"},
		{AgentVersion: "sim-0.2", Kernel: "6.8.0"},         // version bumped
		{AgentVersion: "0.2.0-agent", Kernel: "6.8.0-sim"}, // kernel tells
	} {
		r := Registry{now: time.Now, agents: map[string]Record{}}
		r.Record("acme", "a1", &ebpfsocv1.HeartbeatRequest{AgentInfo: info})
		if !r.IsSimulated("acme", "a1") {
			t.Fatalf("%+v was not recognised as a simulator", info)
		}
	}
}

func TestARealAgentIsNeverMarkedSynthetic(t *testing.T) {
	// The dangerous direction. Mislabelling real containment as demo data
	// would hide evidence from an incident review.
	r := Registry{now: time.Now, agents: map[string]Record{}}
	r.Record("acme", "a1", &ebpfsocv1.HeartbeatRequest{
		AgentInfo: &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent", Kernel: "6.8.0-1032-aws"}})
	if r.IsSimulated("acme", "a1") {
		t.Fatal("a real agent was marked synthetic — its decisions would be filtered out of the audit")
	}
}

func TestAnUnknownAgentIsAssumedReal(t *testing.T) {
	// Before the first heartbeat the registry knows nothing. Assuming "real"
	// is the safe answer: a simulator is mislabelled for seconds, where the
	// reverse would drop a real agent's records out of the ledger.
	r := Registry{now: time.Now, agents: map[string]Record{}}
	if r.IsSimulated("acme", "never-seen") {
		t.Fatal("an unheard-of agent must not be assumed synthetic")
	}
}
