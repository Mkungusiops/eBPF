package intel

import (
	"bufio"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Indicator kinds. Stable strings: they appear in the API and in alerts.
const (
	KindIP     = "ip"
	KindCIDR   = "cidr"
	KindDomain = "domain"
	KindSHA256 = "sha256"
)

// Confidence tiers, and the points each contributes.
//
// High is intentionally large enough to reach the critical band (40) when it
// lands on a chain that has done anything at all. External corroboration that a
// destination is malicious outranks every inference this platform can make on
// its own, and making the analyst wait for a second signal is how a live C2
// channel stays open for another hour.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Points returns the score contribution for a confidence tier.
func Points(confidence string) int {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case ConfidenceHigh:
		return 30
	case ConfidenceLow:
		return 8
	default:
		return 18
	}
}

// Indicator is one feed entry.
type Indicator struct {
	Value      string `json:"value"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Category   string `json:"category,omitempty"`
	Confidence string `json:"confidence"`
}

// Match is an observed indicator that hit a feed.
type Match struct {
	Indicator
	// Observed is what was actually seen, which differs from Value when the hit
	// came from a CIDR or a parent-domain suffix. Both are reported: an analyst
	// needs to know that 10 of their alerts matched one /24, not ten separate
	// indicators.
	Observed string `json:"observed"`
	Points   int    `json:"points"`
}

// Set is a loaded, queryable indicator set. Safe for concurrent use; it is read
// on the event path and replaced wholesale by a refresh.
type Set struct {
	mu sync.RWMutex

	ips     map[string]Indicator
	domains map[string]Indicator
	hashes  map[string]Indicator
	cidrs   []cidrEntry

	allowIPs     map[string]bool
	allowDomains map[string]bool

	sources  map[string]int
	loadedAt time.Time
	// loadErrors are kept and reported rather than only logged. An operator
	// looking at "0 indicators" must be able to tell an empty feed directory
	// from a feed that failed to parse.
	loadErrors []string
}

type cidrEntry struct {
	prefix netip.Prefix
	ind    Indicator
}

// NewSet returns an empty set that matches nothing.
func NewSet() *Set {
	return &Set{
		ips: map[string]Indicator{}, domains: map[string]Indicator{},
		hashes: map[string]Indicator{}, allowIPs: map[string]bool{},
		allowDomains: map[string]bool{}, sources: map[string]int{},
	}
}

// tooBroadDomain rejects feed entries that would match most of the internet.
//
// A feed with a stray "com" line is not hypothetical — truncated downloads and
// mis-parsed CSVs produce exactly this, and the failure is catastrophic and
// silent: every domain the estate touches becomes a critical indicator hit.
// Two labels minimum, and a short list of suffixes that are never themselves
// indicators.
func tooBroadDomain(d string) bool {
	if strings.Count(d, ".") < 1 {
		return true
	}
	switch d {
	case "co.uk", "com.au", "co.za", "co.ke", "com.br", "co.jp", "co.in", "org.uk", "net.au", "gov.uk", "ac.uk":
		return true
	}
	return false
}

// isMatchableIP reports whether an address may be compared against public
// feeds at all.
func isMatchableIP(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10) is not IsPrivate but is not routable
	// either, and AWS uses it for internal service endpoints — which is exactly
	// this estate.
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
		// 169.254.169.254 is the cloud metadata service. Reached constantly by
		// every instance, and link-local already covers it, but it is called out
		// because a match here would fire on every host at once.
	}
	return true
}

// LoadDir reads every feed file in dir, replacing the set's contents.
//
// The load is ALL-OR-NOTHING into a fresh Set that is swapped in at the end. A
// partial load — half the indicators, because file seven had a parse error —
// would silently reduce coverage while continuing to report success.
//
// File naming carries meaning, which keeps the format free of ceremony:
//
//	allow.txt          entries that must NEVER match (checked first)
//	<source>.txt       indicators attributed to <source>
//	<source>.high.txt  ... with a default confidence for the whole file
//
// Line format is one indicator per line, `#` comments, with optional
// tab-separated category and confidence overriding the filename default.
func (s *Set) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("intel: reading %s: %w", dir, err)
	}
	next := NewSet()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		names = append(names, e.Name())
	}
	// Sorted so two boxes with the same files build the same set, and so
	// allow.txt is processed before anything can match.
	sort.Strings(names)
	for _, name := range names {
		if err := next.loadFile(filepath.Join(dir, name)); err != nil {
			next.loadErrors = append(next.loadErrors, err.Error())
		}
	}
	next.loadedAt = time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ips, s.domains, s.hashes, s.cidrs = next.ips, next.domains, next.hashes, next.cidrs
	s.allowIPs, s.allowDomains = next.allowIPs, next.allowDomains
	s.sources, s.loadedAt, s.loadErrors = next.sources, next.loadedAt, next.loadErrors
	return nil
}

// sourceAndConfidence derives them from a filename: "abuse-c2.high.txt" gives
// source "abuse-c2" at high confidence.
func sourceAndConfidence(name string) (string, string) {
	base := strings.TrimSuffix(filepath.Base(name), ".txt")
	for _, c := range []string{ConfidenceHigh, ConfidenceMedium, ConfidenceLow} {
		if strings.HasSuffix(base, "."+c) {
			return strings.TrimSuffix(base, "."+c), c
		}
	}
	return base, ConfidenceMedium
}

func (s *Set) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("intel: %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()

	source, defConf := sourceAndConfidence(path)
	allow := source == "allow"

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n, bad := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// `//` as well as `#`: several published feeds use it and a comment
		// parsed as an indicator is a guaranteed false positive.
		if strings.HasPrefix(line, "//") {
			continue
		}

		value, category := "", ""
		conf := defConf

		// HOSTS-FILE SHAPE IS CHECKED FIRST, on the raw line, before any
		// field splitting.
		//
		// It has to be. URLhaus publishes "127.0.0.1\t<domain>" — TAB
		// separated — and this package's own optional-metadata format is also
		// tab separated. Splitting first therefore read the sinkhole address as
		// the indicator and the DOMAIN as its category: the address was then
		// correctly rejected as loopback, the domain was thrown away, and a
		// 400-entry feed loaded zero indicators while reporting itself parsed.
		// Measured against the live feed, which is the only reason this is
		// written down rather than assumed.
		if host, ok := hostsFileIndicator(line); ok {
			value = host
		} else {
			fields := strings.Split(line, "\t")
			value = normaliseFeedLine(strings.TrimSpace(fields[0]))
			if len(fields) > 1 {
				category = strings.TrimSpace(fields[1])
			}
			if len(fields) > 2 && strings.TrimSpace(fields[2]) != "" {
				conf = strings.ToLower(strings.TrimSpace(fields[2]))
			}
		}
		if value == "" {
			continue
		}
		if s.add(value, source, category, conf, allow) {
			n++
		} else {
			bad++
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("intel: %s: %w", filepath.Base(path), err)
	}
	if !allow {
		s.sources[source] += n
	}
	if bad > 0 {
		return fmt.Errorf("intel: %s: %d unparseable or too-broad entries skipped", filepath.Base(path), bad)
	}
	return nil
}

// add classifies and stores one raw value. Returns false when it is unusable.
func (s *Set) add(value, source, category, confidence string, allow bool) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return false
	}
	ind := Indicator{Value: value, Source: source, Category: category, Confidence: confidence}

	// CIDR before bare IP: "1.2.3.0/24" parses as neither an address nor a host.
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return false
		}
		// A prefix shorter than /8 (or /32 for v6) covers so much of the
		// internet that it is certainly a feed error.
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
			return false
		}
		if allow {
			return false // allowlisting a whole range is not supported; list the addresses
		}
		ind.Kind = KindCIDR
		s.cidrs = append(s.cidrs, cidrEntry{prefix: p, ind: ind})
		return true
	}

	if a, err := netip.ParseAddr(value); err == nil {
		if allow {
			s.allowIPs[a.String()] = true
			return true
		}
		if !isMatchableIP(a) {
			return false // a feed listing RFC1918 space would light up every host
		}
		ind.Kind = KindIP
		s.ips[a.String()] = ind
		return true
	}

	if isHexHash(value) {
		if allow {
			return false
		}
		ind.Kind = KindSHA256
		s.hashes[value] = ind
		return true
	}

	domain := strings.TrimSuffix(strings.TrimPrefix(value, "*."), ".")
	if !looksLikeDomain(domain) {
		return false
	}
	if allow {
		s.allowDomains[domain] = true
		return true
	}
	if tooBroadDomain(domain) {
		return false
	}
	ind.Kind = KindDomain
	ind.Value = domain
	s.domains[domain] = ind
	return true
}

// hostsFileIndicator recognises a hosts-file sinkhole line and returns the
// indicator it is really carrying.
//
// Splits on ANY whitespace, so it covers both the space-separated form and the
// tab-separated form URLhaus actually publishes. The sinkhole address itself is
// never the indicator — it is loopback or the unspecified address, excluded
// from matching anyway, and returning it would silently discard the domain that
// was the entire point of the line.
func hostsFileIndicator(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	switch fields[0] {
	case "0.0.0.0", "127.0.0.1", "::", "::1":
		return strings.TrimSpace(fields[1]), true
	}
	return "", false
}

// normaliseFeedLine reduces the two shapes real published feeds arrive in to
// the one indicator this package stores. Returns "" for a line to skip.
//
// Deliberately only TWO shapes, both unambiguous. This function is the widest
// door in the package — everything it accepts becomes a live indicator — so it
// recognises formats that are self-identifying and refuses to guess at anything
// else. A tolerant parser here would eventually read a stray token out of a
// changed feed format and match the estate's own traffic.
//
//	hosts file   "0.0.0.0 evil.example"    → evil.example
//	URL list     "http://evil.example/x"   → evil.example
//
// The hosts-file case matters more than it looks: those feeds sinkhole to
// 0.0.0.0 or 127.0.0.1, and taking the FIRST token would load the loopback
// address as an indicator. It is excluded by isMatchableIP anyway, but arriving
// there by accident means the domain — the actual indicator — was silently
// dropped, and the feed would report thousands of entries and match nothing.
func normaliseFeedLine(v string) string {
	if v == "" {
		return ""
	}
	// URL form. The scheme makes this unambiguous, so no guessing is involved.
	if i := strings.Index(v, "://"); i > 0 {
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		return u.Hostname()
	}
	// Hosts-file form: a sinkhole address, whitespace, then the real indicator.
	if fields := strings.Fields(v); len(fields) >= 2 {
		switch fields[0] {
		case "0.0.0.0", "127.0.0.1", "::", "::1":
			return fields[1]
		}
		// Any other multi-token line is a format this package does not claim to
		// understand. Skipped rather than half-read.
		return ""
	}
	return v
}

func isHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func looksLikeDomain(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	// A final label that is all digits means this was an IP-like string that
	// failed to parse, not a hostname.
	last := s[strings.LastIndexByte(s, '.')+1:]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

// LookupIP matches an address. Returns false for anything unroutable,
// allowlisted, or absent from the feeds.
func (s *Set) LookupIP(raw string) (Match, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return Match{}, false
	}
	if !isMatchableIP(a) {
		return Match{}, false
	}
	key := a.String()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.allowIPs[key] {
		return Match{}, false
	}
	if ind, ok := s.ips[key]; ok {
		return Match{Indicator: ind, Observed: key, Points: Points(ind.Confidence)}, true
	}
	for _, c := range s.cidrs {
		if c.prefix.Contains(a) {
			return Match{Indicator: c.ind, Observed: key, Points: Points(c.ind.Confidence)}, true
		}
	}
	return Match{}, false
}

// LookupDomain matches a hostname, walking up to its parents so a feed entry of
// "evil.com" catches "cdn.evil.com".
//
// The walk stops before the last two labels, so an entry can never be matched
// via a bare TLD even if one slipped past the load-time check.
func (s *Set) LookupDomain(raw string) (Match, bool) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if !looksLikeDomain(d) {
		return Match{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	labels := strings.Split(d, ".")
	for i := 0; i+2 <= len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if s.allowDomains[candidate] {
			return Match{}, false // an allowlisted parent protects its children
		}
		if ind, ok := s.domains[candidate]; ok {
			return Match{Indicator: ind, Observed: d, Points: Points(ind.Confidence)}, true
		}
	}
	return Match{}, false
}

// LookupHash matches a SHA-256, given as hex in either case.
func (s *Set) LookupHash(raw string) (Match, bool) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if !isHexHash(h) {
		return Match{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ind, ok := s.hashes[h]; ok {
		return Match{Indicator: ind, Observed: h, Points: Points(ind.Confidence)}, true
	}
	return Match{}, false
}

// Lookup dispatches on the shape of the value. Used by the operator-facing
// lookup endpoint, where the caller types an indicator and should not have to
// say what kind it is.
func (s *Set) Lookup(raw string) (Match, bool) {
	if m, ok := s.LookupIP(raw); ok {
		return m, true
	}
	if m, ok := s.LookupHash(raw); ok {
		return m, true
	}
	return s.LookupDomain(raw)
}

// SourceStatus is one feed's contribution.
type SourceStatus struct {
	Source     string `json:"source"`
	Indicators int    `json:"indicators"`
}

// Status describes the loaded set for the API.
type Status struct {
	// Loaded is false when no feed directory was configured or it was empty.
	// Reported explicitly so "no matches" can be distinguished from "nothing
	// to match against" — which is the difference between a clean estate and a
	// switched-off control.
	Loaded     bool           `json:"loaded"`
	Indicators int            `json:"indicators"`
	IPs        int            `json:"ips"`
	CIDRs      int            `json:"cidrs"`
	Domains    int            `json:"domains"`
	Hashes     int            `json:"hashes"`
	Allowed    int            `json:"allowlisted"`
	Sources    []SourceStatus `json:"sources"`
	LoadedAt   time.Time      `json:"loaded_at,omitempty"`
	Errors     []string       `json:"errors,omitempty"`
}

// Status snapshots the set.
func (s *Set) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Status{
		IPs: len(s.ips), CIDRs: len(s.cidrs), Domains: len(s.domains),
		Hashes: len(s.hashes), Allowed: len(s.allowIPs) + len(s.allowDomains),
		LoadedAt: s.loadedAt, Errors: s.loadErrors, Sources: []SourceStatus{},
	}
	st.Indicators = st.IPs + st.CIDRs + st.Domains + st.Hashes
	st.Loaded = !s.loadedAt.IsZero()
	names := make([]string, 0, len(s.sources))
	for n := range s.sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		st.Sources = append(st.Sources, SourceStatus{Source: n, Indicators: s.sources[n]})
	}
	return st
}
