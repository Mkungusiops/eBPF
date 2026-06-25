//go:build !linux

package device

import "context"

// StartDHCPSniffer is a no-op on non-Linux dev hosts (no AF_PACKET). The
// device table simply won't gain DHCP-sourced hostnames during macOS UI
// iteration; passive + neigh sources still populate it on a real gateway.
func StartDHCPSniffer(ctx context.Context, ifaces []string, record func(Device)) {}
