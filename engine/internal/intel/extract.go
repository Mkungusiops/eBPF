package intel

import (
	"net/netip"
	"net/url"
	"strings"
)

// Extraction: turning an observed event into candidate indicators.
//
// This is where most of the value and all of the false positives come from, so
// it is deliberately narrow. Every candidate it yields must be something the
// process genuinely referenced — not something that merely looks like an
// indicator when a command line is squinted at.

// Candidate is one extractable observable.
type Candidate struct {
	Value string
	Kind  string // KindIP or KindDomain
	// Where names the field it came from, so an analyst can see whether the
	// match was a real connection or a string in a command line. Those carry
	// very different weight and must not be presented identically.
	Where string
}

// FromKprobe extracts observables from a policy-triggered kernel event.
//
// The outbound-connections policy is the high-value case: tetrabridge renders
// the socket argument as "daddr:dport", so the destination address of a real
// connection is sitting in the args. That is a CONNECTION THAT HAPPENED, which
// is the strongest observable this platform produces — no inference, no parsing
// of user-controlled text.
func FromKprobe(policyName, args string) []Candidate {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	var out []Candidate
	for _, tok := range strings.Fields(args) {
		if host, ok := splitHostPort(tok); ok {
			if a, err := netip.ParseAddr(host); err == nil && isMatchableIP(a) {
				out = append(out, Candidate{Value: a.String(), Kind: KindIP, Where: "connection"})
			}
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil && isMatchableIP(a) {
			out = append(out, Candidate{Value: a.String(), Kind: KindIP, Where: "connection"})
		}
	}
	return out
}

// splitHostPort splits "1.2.3.4:443" and "[2001:db8::1]:443" without pulling in
// net.SplitHostPort, which errors on the bare addresses this also has to see.
func splitHostPort(s string) (string, bool) {
	if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]:"); i > 0 {
			return s[1:i], true
		}
		return "", false
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || strings.Count(s, ":") != 1 {
		return "", false // no port, or a bare IPv6 address
	}
	return s[:i], true
}

// FromCommandLine extracts observables a process was ASKED to contact.
//
// Weaker evidence than a connection — a URL on a command line may never be
// dialled — but it is what catches a downloader before the connection is made,
// and it is the only place a domain name appears at all: the kernel sees
// addresses, not names.
//
// Conservative by construction. It reads URLs and bare hostnames out of
// argument tokens and nothing else. It does NOT scan for dotted-quad-looking
// substrings inside arbitrary text, which is how a version string like
// "1.2.3.4" becomes a critical indicator hit.
func FromCommandLine(binary, args string) []Candidate {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	var out []Candidate
	seen := map[string]bool{}
	add := func(v, k string) {
		key := k + "|" + v
		if v == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Candidate{Value: v, Kind: k, Where: "command line"})
	}

	for _, tok := range strings.Fields(args) {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		// A URL is unambiguous — the scheme says the token is an endpoint.
		if i := strings.Index(tok, "://"); i > 0 {
			if u, err := url.Parse(tok); err == nil && u.Host != "" {
				host := u.Hostname()
				if a, err := netip.ParseAddr(host); err == nil {
					if isMatchableIP(a) {
						add(a.String(), KindIP)
					}
				} else if looksLikeDomain(strings.ToLower(host)) {
					add(strings.ToLower(host), KindDomain)
				}
			}
			continue
		}
		// A bare token that parses cleanly as an address, whole. Requiring the
		// WHOLE token to parse is what keeps "openssl-1.1.1" and "v1.2.3.4"
		// out.
		if a, err := netip.ParseAddr(tok); err == nil {
			if isMatchableIP(a) {
				add(a.String(), KindIP)
			}
			continue
		}
		if host, ok := splitHostPort(tok); ok {
			if a, err := netip.ParseAddr(host); err == nil && isMatchableIP(a) {
				add(a.String(), KindIP)
				continue
			}
		}
		// A bare hostname. Only accepted for binaries whose whole job is to
		// contact one — otherwise every file path with a dot in it becomes a
		// domain candidate.
		if isNetworkClient(binary) && looksLikeDomain(strings.ToLower(tok)) &&
			!strings.HasPrefix(tok, "-") && !strings.Contains(tok, "/") {
			add(strings.ToLower(tok), KindDomain)
		}
	}
	return out
}

// isNetworkClient reports whether a binary's arguments are likely to name a
// remote host. Kept as a short, explicit list rather than a heuristic: the cost
// of being wrong is a false indicator match on a filename.
func isNetworkClient(binary string) bool {
	b := strings.ToLower(binary)
	if i := strings.LastIndexByte(b, '/'); i >= 0 {
		b = b[i+1:]
	}
	switch b {
	case "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
		"telnet", "ftp", "dig", "host", "nslookup", "ping", "openssl", "python",
		"python3", "perl", "ruby", "node":
		return true
	}
	return false
}

// MatchAll runs every candidate against the set and returns the hits, best
// first.
//
// Sorted by points so a caller taking only the top match takes the most
// serious one. Deduplicated on the indicator VALUE, because a command line
// naming the same host three times is one finding, not three — the same
// alert-inflation problem the chain scorer already solved with findings.
func MatchAll(s *Set, cands []Candidate) []Match {
	if s == nil || len(cands) == 0 {
		return nil
	}
	var out []Match
	seen := map[string]bool{}
	for _, c := range cands {
		var (
			m  Match
			ok bool
		)
		switch c.Kind {
		case KindIP:
			m, ok = s.LookupIP(c.Value)
		case KindDomain:
			m, ok = s.LookupDomain(c.Value)
		case KindSHA256:
			m, ok = s.LookupHash(c.Value)
		}
		if !ok || seen[m.Value] {
			continue
		}
		seen[m.Value] = true
		m.Observed = c.Value
		// A string on a command line is an intent; a socket argument is a
		// connection that happened. Scoring them identically would let a
		// grep of a wordlist score the same as an established C2 channel.
		if c.Where == "command line" {
			m.Points = (m.Points + 1) / 2
		}
		out = append(out, m)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Points > out[j-1].Points; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Describe renders a match for an alert description.
func Describe(m Match) string {
	var b strings.Builder
	b.WriteString("threat intel hit: ")
	b.WriteString(m.Observed)
	if m.Value != m.Observed {
		b.WriteString(" (matches ")
		b.WriteString(m.Value)
		b.WriteString(")")
	}
	if m.Category != "" {
		b.WriteString(" — ")
		b.WriteString(m.Category)
	}
	b.WriteString(" [")
	b.WriteString(m.Source)
	b.WriteString(", ")
	b.WriteString(m.Confidence)
	b.WriteString(" confidence]")
	return b.String()
}
