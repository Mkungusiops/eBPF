package devbpf

import (
	"encoding/binary"
	"testing"
)

// TestDeviceBucketLayout pins the wire size to 24 bytes. The kernel side
// (struct dev_bucket in devchoke.c) and the process choke (bpfmap.PIDBucket)
// share this exact layout — drift here silently corrupts every map write.
func TestDeviceBucketLayout(t *testing.T) {
	if got := binary.Size(DeviceBucket{}); got != 24 {
		t.Fatalf("DeviceBucket size = %d, want 24 (must match struct dev_bucket / pid_bucket)", got)
	}
}

// TestSeenLayout pins the passive-discovery struct to 24 bytes (matches
// struct seen in devchoke.c, including its trailing pad).
func TestSeenLayout(t *testing.T) {
	if got := binary.Size(Seen{}); got != 24 {
		t.Fatalf("Seen size = %d, want 24 (must match struct seen)", got)
	}
}

// TestDevKeyLayout pins the kernel key to 8 bytes (MAC + 2 pad).
func TestDevKeyLayout(t *testing.T) {
	if got := binary.Size(devKey{}); got != 8 {
		t.Fatalf("devKey size = %d, want 8 (must match struct dev_key)", got)
	}
}

// TestFlowLayout pins the flow map's key/value to 16/24 bytes (must match
// struct flow_key / flow_stat in devchoke.c).
func TestFlowLayout(t *testing.T) {
	if got := binary.Size(FlowKey{}); got != 16 {
		t.Fatalf("FlowKey size = %d, want 16 (must match struct flow_key)", got)
	}
	if got := binary.Size(FlowStat{}); got != 24 {
		t.Fatalf("FlowStat size = %d, want 24 (must match struct flow_stat)", got)
	}
}

func TestFlowKeyFormatting(t *testing.T) {
	// daddr 8.8.8.8 in network order, read back as native-endian uint32.
	be := uint32(8) | uint32(8)<<8 | uint32(8)<<16 | uint32(8)<<24
	// dport 4444 in network order: bytes [0x11,0x5c] -> native LE uint16.
	dport := uint16(0x5c)<<8 | uint16(0x11)
	k := FlowKey{DAddr: be, DPort: dport, Proto: 6}
	if k.DestIP() != "8.8.8.8" {
		t.Fatalf("DestIP = %q, want 8.8.8.8", k.DestIP())
	}
	if k.DestPort() != 4444 {
		t.Fatalf("DestPort = %d, want 4444", k.DestPort())
	}
	if ProtoName(k.Proto) != "tcp" {
		t.Fatalf("ProtoName = %q, want tcp", ProtoName(k.Proto))
	}
}

func TestParseMACAndIdentity(t *testing.T) {
	m, err := ParseMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	if got := m.String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("String() = %q, want lowercased colon form", got)
	}
	if got := m.DeviceID(); got != "dev:aabbccddeeff" {
		t.Fatalf("DeviceID() = %q, want dev:aabbccddeeff", got)
	}
	if _, err := ParseMAC("nope"); err == nil {
		t.Fatal("ParseMAC accepted a non-MAC string")
	}
}

func TestNoopBackendRoundTrip(t *testing.T) {
	b := NewNoopDeviceBackend()
	if err := b.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	if err := b.Update(m, DeviceBucket{RatePerSec: 5, Burst: 10, Flags: FlagTarpit}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	snap, err := b.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := snap[m]; got.Flags != FlagTarpit || got.RatePerSec != 5 {
		t.Fatalf("snapshot bucket = %+v, want tarpit 5/10", got)
	}
	if err := b.Delete(m); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	snap, _ = b.Snapshot()
	if _, ok := snap[m]; ok {
		t.Fatal("bucket still present after Delete")
	}
}
