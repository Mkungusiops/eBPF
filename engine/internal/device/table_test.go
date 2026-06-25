package device

import (
	"testing"
	"time"
)

func TestTableRecordMergeKeepsEarlierFields(t *testing.T) {
	tbl := NewTable(time.Hour)

	// Passive sighting: MAC + IP only.
	tbl.Record(Device{MAC: "aa:bb:cc:dd:ee:01", LastIP: "10.0.0.2", Source: SourcePassive})
	// DHCP refines with a hostname but carries no IP — must NOT wipe the IP.
	tbl.Record(Device{MAC: "aa:bb:cc:dd:ee:01", Hostname: "laptop", Source: SourceDHCP})

	d, ok := tbl.Lookup("aa:bb:cc:dd:ee:01")
	if !ok {
		t.Fatal("device not found after Record")
	}
	if d.LastIP != "10.0.0.2" {
		t.Fatalf("LastIP = %q, want 10.0.0.2 (must survive the DHCP merge)", d.LastIP)
	}
	if d.Hostname != "laptop" {
		t.Fatalf("Hostname = %q, want laptop", d.Hostname)
	}
	if d.Source != SourceDHCP {
		t.Fatalf("Source = %q, want dhcp (last non-empty wins)", d.Source)
	}
	if d.DeviceID != "dev:aabbccddee01" {
		t.Fatalf("DeviceID = %q, want dev:aabbccddee01", d.DeviceID)
	}
	if d.FirstSeen.IsZero() {
		t.Fatal("FirstSeen should be set on first Record")
	}
}

func TestTableCanonicalizesAndRejectsJunk(t *testing.T) {
	tbl := NewTable(time.Hour)
	tbl.Record(Device{MAC: "AA:BB:CC:DD:EE:02", Source: SourcePassive}) // upper-case
	if _, ok := tbl.Lookup("aa:bb:cc:dd:ee:02"); !ok {
		t.Fatal("lookup by canonical (lowercase) form should succeed")
	}
	tbl.Record(Device{MAC: "not-a-mac"})
	tbl.Record(Device{MAC: ""})
	if tbl.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (junk MACs must be dropped)", tbl.Len())
	}
}

func TestTableSnapshotMostRecentFirst(t *testing.T) {
	tbl := NewTable(time.Hour)
	base := time.Unix(1_700_000_000, 0).UTC()
	tbl.now = func() time.Time { return base }
	tbl.Record(Device{MAC: "aa:bb:cc:dd:ee:0a", Source: SourcePassive})
	tbl.now = func() time.Time { return base.Add(time.Minute) }
	tbl.Record(Device{MAC: "aa:bb:cc:dd:ee:0b", Source: SourcePassive})

	snap := tbl.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if snap[0].MAC != "aa:bb:cc:dd:ee:0b" {
		t.Fatalf("snapshot[0] = %s, want the more recently seen device", snap[0].MAC)
	}
}

func TestTableSweepEvictsIdle(t *testing.T) {
	tbl := NewTable(10 * time.Minute)
	base := time.Unix(1_700_000_000, 0).UTC()
	tbl.now = func() time.Time { return base }
	tbl.Record(Device{MAC: "aa:bb:cc:dd:ee:03", Source: SourcePassive})

	// Within TTL: not evicted.
	tbl.now = func() time.Time { return base.Add(5 * time.Minute) }
	if n := tbl.Sweep(); n != 0 {
		t.Fatalf("Sweep evicted %d within TTL, want 0", n)
	}
	// Past TTL: evicted.
	tbl.now = func() time.Time { return base.Add(20 * time.Minute) }
	if n := tbl.Sweep(); n != 1 {
		t.Fatalf("Sweep evicted %d past TTL, want 1", n)
	}
	if tbl.Len() != 0 {
		t.Fatalf("Len = %d after eviction, want 0", tbl.Len())
	}
}

func TestIPv4BEToString(t *testing.T) {
	// 10.0.1.2 as the data plane stores it: network-order bytes [10,0,1,2]
	// read back as a native little-endian uint32.
	be := uint32(10) | uint32(0)<<8 | uint32(1)<<16 | uint32(2)<<24
	if got := IPv4BEToString(be); got != "10.0.1.2" {
		t.Fatalf("IPv4BEToString = %q, want 10.0.1.2", got)
	}
	if got := IPv4BEToString(0); got != "" {
		t.Fatalf("IPv4BEToString(0) = %q, want empty", got)
	}
}
