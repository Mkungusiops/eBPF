package origin

import (
	"regexp"
	"strconv"
	"strings"
)

// sshAcceptedRE matches the two stable forms of OpenSSH's successful-auth
// log line. The format has been steady across OpenSSH 6.x → 9.x:
//
//	Accepted publickey for alice from 1.2.3.4 port 51000 ssh2: ED25519 SHA256:abc123...
//	Accepted password for bob from 5.6.7.8 port 22222 ssh2
//
// We pull (method, user, ip, port, optional key-type, optional fp). The
// fingerprint is whatever follows "ssh2:" — usually "<TYPE> SHA256:<b64>"
// but we capture it verbatim so future variants (RSA SHA512, etc.) keep
// working.
var sshAcceptedRE = regexp.MustCompile(
	`Accepted (\S+) for (\S+) from (\S+) port (\d+) ssh2(?::\s+(.+))?`,
)

// SSHEvent is what the parser produces. PID is filled by the caller from
// the surrounding log envelope (journald's _PID field or syslog tag).
type SSHEvent struct {
	PID         uint32
	Method      string // "publickey", "password", "keyboard-interactive", …
	User        string
	RemoteIP    string
	RemotePort  uint16
	Fingerprint string // empty when method != publickey
}

// ParseSSHAccepted returns the parsed event if the line is an Accepted
// auth record, or (zero, false) otherwise. Whitespace/log-prefix
// tolerance: the caller can pass the full journald line or just the
// MESSAGE portion.
func ParseSSHAccepted(line string) (SSHEvent, bool) {
	m := sshAcceptedRE.FindStringSubmatch(line)
	if m == nil {
		return SSHEvent{}, false
	}
	port, err := strconv.ParseUint(m[4], 10, 16)
	if err != nil {
		return SSHEvent{}, false
	}
	ev := SSHEvent{
		Method:     m[1],
		User:       m[2],
		RemoteIP:   m[3],
		RemotePort: uint16(port),
	}
	if len(m) >= 6 {
		ev.Fingerprint = strings.TrimSpace(m[5])
	}
	return ev, true
}

// sshDisconnectedRE matches the line OpenSSH emits when a session ends.
// We use this to evict stale tracker entries promptly rather than waiting
// for the TTL sweeper.
//
//	Disconnected from user alice 1.2.3.4 port 51000
//	Disconnected from authenticating user alice 1.2.3.4 port 51000 [preauth]
var sshDisconnectedRE = regexp.MustCompile(
	`Disconnected from (?:user |authenticating user )?(?:\S+ )?(\S+) port (\d+)`,
)

// ParseSSHDisconnected returns (remoteIP, remotePort, true) if the line
// records a session disconnect.
func ParseSSHDisconnected(line string) (string, uint16, bool) {
	m := sshDisconnectedRE.FindStringSubmatch(line)
	if m == nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(m[2], 10, 16)
	if err != nil {
		return "", 0, false
	}
	return m[1], uint16(port), true
}
