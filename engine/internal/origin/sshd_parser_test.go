package origin

import "testing"

func TestParseSSHAcceptedPublicKey(t *testing.T) {
	line := `Accepted publickey for ubuntu from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:abcdef0123456789`
	ev, ok := ParseSSHAccepted(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if ev.Method != "publickey" || ev.User != "ubuntu" {
		t.Errorf("method/user wrong: %+v", ev)
	}
	if ev.RemoteIP != "203.0.113.5" || ev.RemotePort != 51234 {
		t.Errorf("remote wrong: %+v", ev)
	}
	if ev.Fingerprint != "ED25519 SHA256:abcdef0123456789" {
		t.Errorf("fingerprint wrong: %q", ev.Fingerprint)
	}
}

func TestParseSSHAcceptedPassword(t *testing.T) {
	line := `Accepted password for bob from 198.51.100.7 port 22222 ssh2`
	ev, ok := ParseSSHAccepted(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if ev.Method != "password" || ev.User != "bob" {
		t.Errorf("method/user wrong: %+v", ev)
	}
	if ev.Fingerprint != "" {
		t.Errorf("password auth should have empty fingerprint: %q", ev.Fingerprint)
	}
}

func TestParseSSHAcceptedJournaldEnvelope(t *testing.T) {
	// Real journald lines come prefixed; the regex anchors on "Accepted"
	// so leading text doesn't break it.
	line := `May 11 13:00:00 host sshd[12345]: Accepted publickey for alice from 10.0.0.1 port 60000 ssh2: RSA SHA256:zzz`
	ev, ok := ParseSSHAccepted(line)
	if !ok {
		t.Fatalf("expected match in journald-envelope line")
	}
	if ev.RemoteIP != "10.0.0.1" || ev.Fingerprint != "RSA SHA256:zzz" {
		t.Errorf("envelope strip failed: %+v", ev)
	}
}

func TestParseSSHAcceptedRejectsNoise(t *testing.T) {
	for _, s := range []string{
		"",
		"Failed publickey for alice from 1.2.3.4 port 51000 ssh2",
		"Accepted publickey for alice from 1.2.3.4 port notanumber ssh2",
		"random log line",
	} {
		if _, ok := ParseSSHAccepted(s); ok {
			t.Errorf("expected miss for %q", s)
		}
	}
}

func TestParseSSHDisconnected(t *testing.T) {
	cases := []struct {
		line     string
		wantIP   string
		wantPort uint16
		wantOK   bool
	}{
		{"Disconnected from user alice 1.2.3.4 port 51000", "1.2.3.4", 51000, true},
		{"Disconnected from authenticating user alice 5.6.7.8 port 22222 [preauth]", "5.6.7.8", 22222, true},
		{"random", "", 0, false},
	}
	for _, c := range cases {
		ip, port, ok := ParseSSHDisconnected(c.line)
		if ok != c.wantOK || ip != c.wantIP || port != c.wantPort {
			t.Errorf("%q: got (%q, %d, %v) want (%q, %d, %v)",
				c.line, ip, port, ok, c.wantIP, c.wantPort, c.wantOK)
		}
	}
}
