package score

import (
	"strings"
)

// Score returns the points to add, the human-readable reason, and a stable
// FINDING class.
//
// The finding exists to deduplicate alerts. The reason embeds a file path, so
// using it as a dedup key makes almost every event unique — measured on the
// live rig, keying on the reason left 63% of alerts critical, because reading
// twenty files looked like twenty distinct findings rather than one. The
// finding is the same string for every path, so a chain reports "credential
// store read" once and the individual paths stay in the event stream, where
// the detail belongs.
func Score(eventType, binary, args, policyName string, uid uint32) (int, string, string) {
	switch eventType {
	case "process_exec":
		return scoreExec(binary, args, uid)
	case "process_kprobe":
		return scoreKprobe(policyName, args)
	}
	return 0, "", ""
}

func scoreExec(binary, args string, uid uint32) (int, string, string) {
	bin := strings.ToLower(binary)

	suspiciousDownloaders := []string{"wget", "curl"}
	for _, s := range suspiciousDownloaders {
		if strings.Contains(bin, s) {
			lower := strings.ToLower(args)
			if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
				strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
				return 25, "Pipe to shell from downloader (curl|sh pattern)", "Pipe to shell from downloader (curl|sh pattern)"
			}
			return 3, "Network downloader executed", "Network downloader executed"
		}
	}

	reverseShellTools := []string{"nc", "ncat", "socat"}
	for _, s := range reverseShellTools {
		if strings.HasSuffix(bin, "/"+s) || bin == s {
			if strings.Contains(args, "-e") || strings.Contains(args, "/bin/") {
				return 20, "Reverse shell tool with -e or shell argument", "Reverse shell tool with -e or shell argument"
			}
			return 5, "Network tool executed", "Network tool executed"
		}
	}

	if strings.Contains(strings.ToLower(args), "base64") &&
		(strings.Contains(args, "-d") || strings.Contains(args, "--decode")) {
		return 15, "Base64 decode in command line", "Base64 decode in command line"
	}

	if (strings.HasSuffix(bin, "/bash") || strings.HasSuffix(bin, "/sh")) &&
		strings.Contains(args, "-c") {
		return 1, "Shell -c invocation", "Shell -c invocation"
	}

	if strings.HasSuffix(bin, "/chmod") && strings.Contains(args, "+x") {
		return 5, "Made file executable", "Made file executable"
	}

	return 0, "", ""
}

// filePath trims a kprobe argument list down to the path.
//
// extractKprobeArgs joins every argument, so a file event arrives as
// "/etc/passwd 4" — the trailing token is the permission mask the policy
// matched on. That mask ended up verbatim in alert descriptions ("Sensitive
// file accessed: /etc/passwd 4"), which is the first thing an analyst reads and
// reads as a corrupted path.
func filePath(args string) string {
	if i := strings.IndexByte(args, ' '); i > 0 {
		return args[:i]
	}
	return args
}

func scoreKprobe(policyName, args string) (int, string, string) {
	path := filePath(args)
	switch policyName {
	case "privilege-escalation":
		return 15, "Privilege escalation: setuid to root", "privilege-escalation"
	case "sensitive-file-access":
		if strings.Contains(path, "/etc/shadow") || strings.Contains(path, "/.ssh/") {
			return 20, "Access to credential file: " + path, "credential-file-access"
		}
		// /etc/passwd IS NOT A SECRET, and scoring it as one drowns everything
		// else this policy catches.
		//
		// It is world-readable by design and holds no credentials — the hashes
		// moved to /etc/shadow in 1988. Practically every process that resolves
		// a username or a uid reads it: the container runtime on each start,
		// systemd applying User=, sshd, login, id, ls -l, ps.
		//
		// Measured on the live engine 2026-08-22, after the fork-child fix made
		// previously-dropped kprobes scorable: 111 of the newest 200 alerts were
		// "/etc/passwd", 80 of them from /usr/bin/runc alone. That is 55% of the
		// alert volume, all of it a container runtime starting containers, and
		// it pushed the executive posture dial to 98/100 "Critical" on an estate
		// with no attacker. The fork-child fix was correct and this is its
		// exposed consequence: those reads were always happening, they were just
		// silently evaporating along with the genuine signal beside them.
		//
		// The T1087 argument does not survive contact with the data. Account
		// discovery is a PATTERN — enumeration, repetition, recon tooling — not
		// a single read of a public file, and the platform still has every one
		// of these events in the store, still shows them in the event stream,
		// and still flags an unusual process lineage reaching them through the
		// behavioural baseline. What is removed is only the claim that one read
		// of a world-readable file is worth 8 points of suspicion.
		//
		// /etc/sudoers stays at 8: it is root-only and it describes who may
		// become root. The honeypot directory stays at 8 too, and deliberately
		// so — those files are decoys that nothing legitimate ever opens, so
		// ANY read of one is a finding.
		if strings.HasSuffix(path, "/etc/passwd") {
			return 0, "", ""
		}
		return 8, "Sensitive file accessed: " + path, "sensitive-file-access"
	case "override-credential-read":
		// This policy had no case at all, so every event it produced scored 0
		// and never raised an alert. It watches paths `sensitive-file-access`
		// does not — /etc/gshadow, and the user's ~/.ssh, ~/.aws, ~/.kube,
		// ~/.gnupg and ~/.netrc — which meant reading cloud, cluster and GPG
		// credentials was silently invisible while /etc/shadow was caught.
		// Verified on the live rig: a read of ~/.aws/credentials produced zero
		// alerts in the same command where /etc/shadow produced four.
		//
		// Every path this policy matches is a credential by construction, so
		// there is no lower tier here. Scored just below the /etc/shadow tier
		// because the two policies overlap on shadow and ~/.ssh, and a read of
		// those already scores 20 from sensitive-file-access — matching that
		// again would double-count the overlap and inflate the chain.
		return 18, "Credential store read: " + path, "credential-store-read"
	case "outbound-connections":
		return 12, "Shell or network tool made outbound connection", "outbound-connection"
	}
	return 0, "", ""
}

// authHelpers are the credential-verification helpers of the host's OWN login
// stack. Reading /etc/shadow is not incidental to these binaries — it is their
// entire function. PAM shells out to unix_chkpwd precisely because the shadow
// file is root-only and the calling process may not be.
//
// Listed in every layout the file might land in, for the reason
// choke.DefaultSystemCriticalBinaries gives: matching is by exact path, a
// redundant entry costs nothing, and a missing one silently does nothing.
var authHelpers = map[string]bool{
	"/usr/sbin/unix_chkpwd": true,
	"/sbin/unix_chkpwd":     true,
	"/usr/bin/unix_chkpwd":  true,
	"/usr/sbin/unix_update": true,
	"/sbin/unix_update":     true,
}

// authInvokers are the binaries whose invocation of an auth helper IS the
// authentication stack running. Anything else calling unix_chkpwd is still
// scored at full weight — that is the case worth alerting on.
var authInvokers = map[string]bool{
	// OpenSSH >= 9.8 splits the daemon; the per-session and per-auth binaries
	// are the ones that actually reach PAM. Same three layouts the choke
	// exemption list carries.
	"/usr/sbin/sshd":                    true,
	"/usr/sbin/sshd-session":            true,
	"/usr/sbin/sshd-auth":               true,
	"/usr/lib/openssh/sshd-session":     true,
	"/usr/lib/openssh/sshd-auth":        true,
	"/usr/libexec/openssh/sshd-session": true,
	"/usr/libexec/openssh/sshd-auth":    true,
	"/usr/bin/sudo":                     true,
	"/bin/sudo":                         true,
	"/usr/bin/su":                       true,
	"/bin/su":                           true,
	"/usr/bin/login":                    true,
	"/bin/login":                        true,
	"/usr/sbin/cron":                    true,
	"/usr/bin/passwd":                   true,
	"/usr/bin/polkit-agent-helper-1":    true,
}

// routinePrivilegeTransitions are binaries whose setuid(0) IS their function:
// the SSH daemon dropping to the session user, PAM's password verifier, cron
// starting a job, systemd's executor applying User=, and the container runtime
// entering a namespace. Every one of them fires on a completely idle host.
//
// This was tried once and REVERTED, and the revert note is preserved in the
// privilege-escalation comment below because the reason matters: suppressing it
// took scripts/e2e/detection.sh from 15/15 to 14/15, since the suite's only
// T1548 evidence was the harness's own ssh login. sudo's setuid never scored,
// so the noise WAS the detection.
//
// The precondition that note named — "fix those and this suppression becomes
// correct and safe to restore" — is now met. eventpipe.HandleKprobe synthesises
// the forked child's tree node, so sudo's setuid(0) lands on its chain and
// alerts on its own merits. Removing this noise no longer removes coverage.
//
// Deliberately absent: sudo, su, pkexec, newgrp. Those ARE the T1548 surface.
var routinePrivilegeTransitions = map[string]bool{
	"/usr/sbin/sshd":                    true,
	"/usr/sbin/sshd-session":            true,
	"/usr/sbin/sshd-auth":               true,
	"/usr/lib/openssh/sshd-session":     true,
	"/usr/lib/openssh/sshd-auth":        true,
	"/usr/libexec/openssh/sshd-session": true,
	"/usr/libexec/openssh/sshd-auth":    true,
	"/usr/sbin/unix_chkpwd":             true,
	"/sbin/unix_chkpwd":                 true,
	"/usr/bin/unix_chkpwd":              true,
	"/usr/sbin/cron":                    true,
	"/usr/lib/systemd/systemd":          true,
	"/usr/lib/systemd/systemd-executor": true,
	"/lib/systemd/systemd-executor":     true,
	"/usr/lib/systemd/systemd-logind":   true,
	// The container runtime. Keeping runc/containerd here is also what stops
	// the newly-synthesised fork children from giving the choke gateway a new
	// enforcement surface over every container start on an enforcing host.
	"/usr/bin/runc":                    true,
	"/usr/sbin/runc":                   true,
	"/usr/bin/containerd-shim-runc-v2": true,
	"/usr/bin/containerd":              true,
	"/usr/bin/dockerd":                 true,
	"/usr/sbin/dockerd":                true,
}

// IsRoutinePrivilegeTransition reports whether a setuid(0) is the host's own
// privilege-separation machinery rather than an escalation worth alerting on.
func IsRoutinePrivilegeTransition(binary, policyName string) bool {
	return policyName == "privilege-escalation" && routinePrivilegeTransitions[binary]
}

// IsAuthStackCredentialRead reports whether a credential-file read is the
// host's own authentication stack doing its job, and therefore carries no
// suspicion.
//
// # Why this exists
//
// Measured on the live engine 2026-08-21: the single largest source of
// CRITICAL alerts on an estate with no attacker was
//
//	/usr/lib/openssh/sshd-session → /usr/sbin/unix_chkpwd   (score 60)
//
// which is what PAM does on every single SSH login. 38 of the newest 300
// alerts were that one chain, and the same pair under sudo produced more. Over
// 24 hours the box raised 6,808 alerts against 109 the day before, and the
// difference was operators logging in. A detection that fires on every
// authentication is not a detection; it is a clock, and it trains the analyst
// to close the queue without reading it.
//
// # Why suppress rather than exempt
//
// The alternative was adding unix_chkpwd to choke.DefaultSystemCriticalBinaries.
// That is worse: the exemption list removes a binary from SCORE-DRIVEN
// containment entirely, so a genuinely malicious unix_chkpwd could never be
// choked. This narrows on the PAIR instead — the helper AND the parent that
// legitimately invokes it. unix_chkpwd run by anything else still scores in
// full, which is the case an analyst actually wants.
//
// # What is NOT lost
//
// The kernel event is still recorded and still reaches the console and the
// event stream; only its contribution to the chain score is dropped. And this
// costs no coverage against real credential theft: unix_chkpwd verifies a
// password the caller already supplied, it does not disclose the file. An
// attacker who wants the hashes reads them directly — `cat /etc/shadow` scores
// exactly as it always did.
func IsAuthStackCredentialRead(binary, parentBinary, policyName string) bool {
	switch policyName {
	case "sensitive-file-access", "override-credential-read":
		// The READER is what matters, and matching on it alone is deliberate.
		//
		// The first version of this required the pair — helper AND a recognised
		// parent — and it only half-worked in production. Two reasons, both
		// measured on the redeploy of 2026-08-21:
		//
		//   1. sshd-session and sshd-auth read /etc/shadow and /etc/passwd
		//      THEMSELVES. PAM runs in-process there, so there is no helper and
		//      no pair to match; those chains kept scoring 108 and 40.
		//   2. The parent is not reliably a path. unix_chkpwd turned up with a
		//      parent of "/proc/self/fd/9" — an fd re-exec — so the lookup
		//      missed and the chain scored 57.
		//
		// Widening to the reader is safe because every binary in the set either
		// cannot disclose the file (unix_chkpwd verifies a password the caller
		// already supplied and answers yes or no) or already runs as root as
		// its whole purpose. An attacker who wants the hashes runs something
		// else, and `cat /etc/shadow` still scores 20 exactly as before.
		//
		// What is NOT lost: an unusual way of REACHING one of these binaries is
		// still caught, by the behavioural baseline rather than by a static
		// rule. The same /proc/self/fd/9 → unix_chkpwd execution that stopped
		// scoring here still raised "process lineage is rare on this host". The
		// rule layer answers "is this read suspicious" (no, it is PAM); the
		// baseline answers "is this lineage suspicious" (that one was). Putting
		// each question at the layer that can actually answer it is the point.
		return authCredentialReaders[binary] || (authHelpers[binary] && authInvokers[parentBinary])

		// The privilege-escalation policy is deliberately NOT handled here, after
		// trying it and reverting.
		//
		// setuid(0) by sshd-session/sshd-auth is the daemon's own privilege
		// separation. It fires on every connection before anyone has authenticated,
		// and on an idle host it accounted for all 26 of the most recent setuid
		// alerts — every one a medium, every one noise. Suppressing it looked
		// obviously right, and shipping it took scripts/e2e/detection.sh from 15/15
		// to 14/15.
		//
		// What that exposed matters more than the fix. The suite's T1548 assertion
		// was PASSING ON THE ARTIFACT: the harness SSHes into the host to launch
		// attacks/04-privilege-escalation.sh, and the assertion was matching THAT
		// LOGIN's sshd-auth setuid — never the `sudo -n true` inside the attack,
		// which raises the kprobe event but whose score never reaches an alert.
		// Remove the login noise and the suite has no T1548 coverage left at all.
		//
		// So the noise stays, because right now it is the only thing standing in
		// for that detection. Two real defects sit behind this and are NOT fixed
		// here: sudo's setuid score does not land on its chain, and the suite
		// cannot distinguish an attack's signal from its own footprint. Fix those
		// and this suppression becomes correct and safe to restore.
	}
	return false
}

// authCredentialReaders are binaries whose access to a credential file is
// definitional rather than suspicious: either they are the PAM helper that
// verifies a password without disclosing the file, or they are the login
// binary that runs PAM in-process.
var authCredentialReaders = map[string]bool{
	"/usr/sbin/unix_chkpwd":             true,
	"/sbin/unix_chkpwd":                 true,
	"/usr/bin/unix_chkpwd":              true,
	"/usr/sbin/unix_update":             true,
	"/sbin/unix_update":                 true,
	"/usr/sbin/sshd":                    true,
	"/usr/sbin/sshd-session":            true,
	"/usr/sbin/sshd-auth":               true,
	"/usr/lib/openssh/sshd-session":     true,
	"/usr/lib/openssh/sshd-auth":        true,
	"/usr/libexec/openssh/sshd-session": true,
	"/usr/libexec/openssh/sshd-auth":    true,
	"/usr/bin/login":                    true,
	"/bin/login":                        true,
	"/usr/bin/su":                       true,
	"/bin/su":                           true,
	"/usr/bin/sudo":                     true,
	"/bin/sudo":                         true,
	"/usr/bin/passwd":                   true,
	"/usr/bin/gpasswd":                  true,
	"/usr/sbin/chpasswd":                true,
	// systemd resolves `User=` in a unit file by reading the account
	// databases, and since v254 it does that in a forked systemd-executor
	// rather than in PID 1. Measured on the live engine after the first two
	// rounds of this fix: systemd-executor was the ONLY remaining source of
	// critical alerts on an idle host, reading /etc/shadow eleven times per
	// unit start for score 109. It is the same class as PAM — identity
	// infrastructure consulting the account database — and it was invisible
	// until the fd re-exec was resolved, because the kernel reported it as
	// "/proc/self/fd/9".
	"/usr/lib/systemd/systemd-executor": true,
	"/lib/systemd/systemd-executor":     true,
	"/usr/lib/systemd/systemd":          true,
	"/usr/lib/systemd/systemd-logind":   true,
	"/usr/lib/systemd/systemd-userdbd":  true,
	"/usr/lib/systemd/systemd-homed":    true,
	"/usr/bin/systemd-run":              true,
	"/usr/sbin/nscd":                    true,
	"/usr/sbin/sssd":                    true,
}

func Severity(score int) string {
	switch {
	case score >= 40:
		return "critical"
	case score >= 20:
		return "high"
	case score >= 10:
		return "medium"
	case score >= 5:
		return "low"
	}
	return "info"
}

// Band is Severity as an ordered number, so callers can compare two severities
// without a string table. info=0 .. critical=4.
//
// Exists because alert severity is derived from the CUMULATIVE chain score,
// which only ever grows: once a chain crosses 40 every later event on it is
// critical too. Measured on the live rig, that made 91 of 100 alerts critical
// (scores 16-179) — the field stopped carrying any triage information. The
// engine now alerts on an INCREASE in band rather than on every event above
// the threshold, which needs an ordering rather than a label.
func Band(score int) int {
	switch {
	case score >= 40:
		return 4
	case score >= 20:
		return 3
	case score >= 10:
		return 2
	case score >= 5:
		return 1
	}
	return 0
}
