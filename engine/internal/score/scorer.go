package score

import (
	"strings"
)

func Score(eventType, binary, args, policyName string, uid uint32) (int, string) {
	switch eventType {
	case "process_exec":
		return scoreExec(binary, args, uid)
	case "process_kprobe":
		return scoreKprobe(policyName, args)
	}
	return 0, ""
}

func scoreExec(binary, args string, uid uint32) (int, string) {
	bin := strings.ToLower(binary)

	suspiciousDownloaders := []string{"wget", "curl"}
	for _, s := range suspiciousDownloaders {
		if strings.Contains(bin, s) {
			lower := strings.ToLower(args)
			if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
				strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
				return 25, "Pipe to shell from downloader (curl|sh pattern)"
			}
			return 3, "Network downloader executed"
		}
	}

	reverseShellTools := []string{"nc", "ncat", "socat"}
	for _, s := range reverseShellTools {
		if strings.HasSuffix(bin, "/"+s) || bin == s {
			if strings.Contains(args, "-e") || strings.Contains(args, "/bin/") {
				return 20, "Reverse shell tool with -e or shell argument"
			}
			return 5, "Network tool executed"
		}
	}

	if strings.Contains(strings.ToLower(args), "base64") &&
		(strings.Contains(args, "-d") || strings.Contains(args, "--decode")) {
		return 15, "Base64 decode in command line"
	}

	if (strings.HasSuffix(bin, "/bash") || strings.HasSuffix(bin, "/sh")) &&
		strings.Contains(args, "-c") {
		return 1, "Shell -c invocation"
	}

	if strings.HasSuffix(bin, "/chmod") && strings.Contains(args, "+x") {
		return 5, "Made file executable"
	}

	return 0, ""
}

func scoreKprobe(policyName, args string) (int, string) {
	switch policyName {
	case "privilege-escalation":
		return 15, "Privilege escalation: setuid to root"
	case "sensitive-file-access":
		if strings.Contains(args, "/etc/shadow") || strings.Contains(args, "/.ssh/") {
			return 20, "Access to credential file: " + args
		}
		return 8, "Sensitive file accessed: " + args
	case "outbound-connections":
		return 12, "Shell or network tool made outbound connection"
	}
	return 0, ""
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
