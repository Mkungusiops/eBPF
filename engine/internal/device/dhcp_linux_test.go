//go:build linux

package device

import (
	"encoding/binary"
	"testing"
)

// buildDHCP synthesizes an Ethernet/IPv4/UDP/BOOTP frame carrying a DHCP
// message with the given client MAC, assigned IP (yiaddr), and hostname
// option. Ports are server(67)->client(68), i.e. an ACK direction.
func buildDHCP(chaddr [6]byte, yiaddr [4]byte, hostname string) []byte {
	p := make([]byte, 320)
	// Ethernet: ethertype IPv4.
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	// IPv4: version 4 / IHL 5 (20 bytes), protocol UDP.
	p[14] = 0x45
	p[14+9] = 17 // IPPROTO_UDP
	// UDP: src 67, dst 68.
	binary.BigEndian.PutUint16(p[34:36], 67)
	binary.BigEndian.PutUint16(p[36:38], 68)
	// BOOTP fixed header starts at 42.
	boot := 42
	copy(p[boot+16:boot+20], yiaddr[:])                 // yiaddr
	copy(p[boot+28:boot+34], chaddr[:])                 // chaddr (client MAC, first 6 bytes)
	copy(p[boot+236:boot+240], []byte{99, 130, 83, 99}) // magic cookie
	// Options at boot+240 = 282.
	o := boot + 240
	p[o], p[o+1], p[o+2] = 53, 1, 5 // option 53: DHCP type = ACK
	o += 3
	p[o], p[o+1] = 12, byte(len(hostname)) // option 12: hostname
	copy(p[o+2:o+2+len(hostname)], hostname)
	o += 2 + len(hostname)
	p[o] = 255 // end
	return p
}

func TestParseDHCPExtractsIdentity(t *testing.T) {
	mac := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x77}
	d, ok := buildAndParse(mac, [4]byte{10, 0, 0, 77}, "laptop")
	if !ok {
		t.Fatal("parseDHCP returned ok=false on a valid DHCP frame")
	}
	if d.MAC != "aa:bb:cc:dd:ee:77" {
		t.Fatalf("MAC = %q, want aa:bb:cc:dd:ee:77", d.MAC)
	}
	if d.LastIP != "10.0.0.77" {
		t.Fatalf("LastIP = %q, want 10.0.0.77 (from yiaddr)", d.LastIP)
	}
	if d.Hostname != "laptop" {
		t.Fatalf("Hostname = %q, want laptop (option 12)", d.Hostname)
	}
	if d.Source != SourceDHCP {
		t.Fatalf("Source = %q, want dhcp", d.Source)
	}
}

func buildAndParse(mac [6]byte, ip [4]byte, host string) (Device, bool) {
	return parseDHCP(buildDHCP(mac, ip, host))
}

func TestParseDHCPRejectsNonDHCP(t *testing.T) {
	// Truncated frame.
	if _, ok := parseDHCP(make([]byte, 60)); ok {
		t.Fatal("parseDHCP accepted a too-short frame")
	}
	// Valid-length frame but not IPv4 (ethertype left as 0x0000).
	p := make([]byte, 320)
	if _, ok := parseDHCP(p); ok {
		t.Fatal("parseDHCP accepted a non-IPv4 frame")
	}
	// IPv4 + UDP but non-DHCP ports.
	q := buildDHCP([6]byte{1, 2, 3, 4, 5, 6}, [4]byte{1, 1, 1, 1}, "x")
	binary.BigEndian.PutUint16(q[34:36], 1234)
	binary.BigEndian.PutUint16(q[36:38], 5678)
	if _, ok := parseDHCP(q); ok {
		t.Fatal("parseDHCP accepted a non-DHCP UDP frame")
	}
}
