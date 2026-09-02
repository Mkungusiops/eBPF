package uplink

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// dest_ip and dest_port have been on the wire since ProcessEvent shipped, and
// EventRecord never set them. So the control plane received every network
// event with no destination, and the console — which prefers dest_ip and only
// falls back to pattern-matching the args blob — had nothing to read. A panel
// titled "outbound TCP peers seen in the current event window" could therefore
// be empty on an estate that was making connections.

func TestEventRecordCarriesTheDestination(t *testing.T) {
	rec := EventRecord(&store.Event{
		ID: 1, Timestamp: time.Now().UTC(), EventType: "process_kprobe",
		Binary: "/usr/bin/curl", Args: "-s 203.0.113.10:443",
		PeerIP: "203.0.113.10", PeerPort: 443,
	})
	e := rec.GetEvent()
	if e == nil {
		t.Fatal("no event payload")
	}
	if e.GetDestIp() != "203.0.113.10" || e.GetDestPort() != 443 {
		t.Fatalf("destination = %q:%d — the console falls back to regexing args when this is empty",
			e.GetDestIp(), e.GetDestPort())
	}
}

func TestAnEventWithNoPeerCarriesNoDestination(t *testing.T) {
	// An exec has no peer, and inventing 0.0.0.0:0 would put a node on the
	// correlation graph for a connection that never happened.
	e := EventRecord(&store.Event{ID: 2, Timestamp: time.Now().UTC(), EventType: "process_exec"}).GetEvent()
	if e.GetDestIp() != "" || e.GetDestPort() != 0 {
		t.Fatalf("got %q:%d, want no destination", e.GetDestIp(), e.GetDestPort())
	}
}
