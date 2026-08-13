//go:build linux

package device

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// StartDHCPSniffer passively observes DHCP traffic transiting the given
// interfaces (the bridge slaves) and feeds MAC<->IP<->hostname bindings into
// record. Because the gateway box is inline, DHCP REQUEST/ACK frames cross
// the bridge even though the DHCP server lives on the upstream ISP router —
// so we recover identity with no access to any lease file.
//
// Best-effort and non-fatal: opening the AF_PACKET socket needs CAP_NET_RAW;
// if that's missing (or any iface is bad) the sniffer logs and that iface is
// skipped. Enforcement never depends on this — it only enriches the table.
//
// One goroutine per interface; all exit when ctx is cancelled.
func StartDHCPSniffer(ctx context.Context, ifaces []string, record func(Device)) {
	for _, ifn := range ifaces {
		go sniffOne(ctx, ifn, record)
	}
}

func sniffOne(ctx context.Context, ifn string, record func(Device)) {
	iface, err := net.InterfaceByName(ifn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[device/dhcp] interface %q: %v (sniffer skipped)\n", ifn, err)
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[device/dhcp] socket on %s: %v (need CAP_NET_RAW; sniffer disabled)\n", ifn, err)
		return
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[device/dhcp] bind %s: %v (sniffer disabled)\n", ifn, err)
		return
	}
	// 1s receive timeout so we can poll ctx between frames.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: 1})

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return
		}
		if d, ok := parseDHCP(buf[:n]); ok {
			record(d)
		}
	}
}

// htons converts a uint16 to network byte order. Hosts we target (amd64,
// arm64) are little-endian; this is the standard AF_PACKET idiom.
func htons(h uint16) uint16 { return (h << 8) | (h >> 8) }

// parseDHCP extracts a Device from an Ethernet frame carrying a BOOTP/DHCP
// message. Returns ok=false for any non-DHCP or malformed frame. Heavily
// bounds-checked — this reads attacker-influenced bytes off the wire.
func parseDHCP(p []byte) (Device, bool) {
	const ethHdr = 14
	if len(p) < ethHdr+20+8+240 {
		return Device{}, false
	}
	if binary.BigEndian.Uint16(p[12:14]) != 0x0800 { // IPv4 only
		return Device{}, false
	}
	ihl := int(p[ethHdr]&0x0f) * 4
	if ihl < 20 || len(p) < ethHdr+ihl+8 {
		return Device{}, false
	}
	if p[ethHdr+9] != 17 { // UDP
		return Device{}, false
	}
	udp := ethHdr + ihl
	srcPort := binary.BigEndian.Uint16(p[udp : udp+2])
	dstPort := binary.BigEndian.Uint16(p[udp+2 : udp+4])
	if srcPort != 67 && srcPort != 68 && dstPort != 67 && dstPort != 68 {
		return Device{}, false
	}

	boot := udp + 8
	// BOOTP fixed header: yiaddr@16, chaddr@28 (16 bytes), magic cookie@236.
	if len(p) < boot+240 {
		return Device{}, false
	}
	chaddr := p[boot+28 : boot+34] // first 6 bytes of the 16-byte chaddr = client MAC
	mac := net.HardwareAddr(append([]byte(nil), chaddr...)).String()
	if mac == "00:00:00:00:00:00" {
		return Device{}, false
	}
	yiaddr := net.IP(append([]byte(nil), p[boot+16:boot+20]...))

	d := Device{MAC: mac, Source: SourceDHCP}
	if !yiaddr.Equal(net.IPv4zero) && !yiaddr.IsUnspecified() {
		d.LastIP = yiaddr.String()
	}

	// Options start after the 4-byte magic cookie at boot+236.
	opts := p[boot+240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 0 { // pad
			i++
			continue
		}
		if code == 255 { // end
			break
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		val := opts[i+2 : i+2+l]
		switch code {
		case 12: // hostname
			d.Hostname = sanitizeHostname(string(val))
		case 50: // requested IP — use when yiaddr is absent (REQUEST/DISCOVER)
			if d.LastIP == "" && l == 4 {
				d.LastIP = net.IP(append([]byte(nil), val...)).String()
			}
		}
		i += 2 + l
	}
	return d, true
}

// sanitizeHostname strips control characters DHCP clients sometimes send.
func sanitizeHostname(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			out = append(out, r)
		}
	}
	if len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	return string(out)
}
