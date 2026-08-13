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
