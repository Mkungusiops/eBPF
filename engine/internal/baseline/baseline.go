package baseline

import (
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Facet names. Stable strings: they are persisted and appear in the API.
const (
	FacetBinary  = "binary"
	FacetEdge    = "edge"
	FacetUserBin = "userbin"
	FacetHour    = "hour"
)

// Tunables. Exported so the API can report what the profile is actually using
// rather than the caller guessing.
const (
	// HalfLife is how long an unrepeated observation takes to lose half its
	// weight. Two weeks: long enough that a weekly cron job stays normal,
	// short enough that a decommissioned service stops suppressing alerts
	// within a sprint.
	HalfLife = 14 * 24 * time.Hour

	// MaxEventPoints bounds the anomaly contribution of a SINGLE event.
	//
	// 12 is deliberate and sits just above the medium band (10) and well below
	// high (20). The most novel event this package can describe therefore
	// raises a medium on its own and cannot, by itself, reach the high or
	// critical bands that drive containment. Novelty is evidence; it is not a
	// verdict, and a host that installs new software must not be able to
	// contain itself.
	MaxEventPoints = 12

	// HourMinSpan is how long a profile must have been learning before the
	// time-of-day facet is allowed to score.
	//
	// It exists because the hour facet is the only one whose key space is a
	// CYCLE that wall-clock time has to walk. The other three facets see a
	// genuinely new key the first time a genuinely new thing happens; hour 19
	// is "never seen before" at 19:00 on the first day purely because 19:00 had
	// not happened yet.
	//
	// Measured, and it was shipping: a profile that satisfied the warm-up gate
	// after 40 minutes had observed exactly one hour, so at the next hour
	// boundary the host's MOST ROUTINE activity scored 3 and was flagged novel —
	// every process, every hour, for the first day. The score alone was below
	// the low band, but Novel drives the finding ring and the binary hasher, so
	// the Behaviour panel filled with "never been active at hour 19" and buried
	// the findings it exists to show.
	//
	// Seven days, not 24 hours. After a single day every hour has been seen once
	// and the facet says nothing; after a week an UNSEEN hour is a real
	// statement — this host genuinely does not run at 03:00 — which is the
	// finding worth having. Deliberately not a distinct-key count: a host that
	// is only ever active 09:00-18:00 would never reach 24 distinct hours, so a
	// coverage gate would permanently disable the facet on exactly the hosts
	// where a 03:00 execution matters most.
	HourMinSpan = 7 * 24 * time.Hour

	// maxKeysPerFacet bounds memory. A host that execs a million distinct
	// paths (a build farm) would otherwise grow this map without limit — the
	// same unbounded-map failure this codebase has already fixed in the uplink
	// buffer, the ingest dedup set and the connection pool. When the cap is
	// hit the lowest-weight keys are evicted, which is correct as well as
	// convenient: the rarest keys are the ones decay was about to remove.
	maxKeysPerFacet = 20000

	// evictTo is how far an eviction pass trims, so eviction is amortised
	// rather than running on every insert once the cap is reached.
	evictTo = maxKeysPerFacet * 3 / 4
)

// Warmup is when a profile is allowed to start scoring.
//
// BOTH conditions must hold. Observations alone are not enough: a burst of
// 5,000 execs in one minute says nothing about what a Tuesday looks like.
// Wall-clock alone is not enough either: an idle host that has been up for a
// week has still seen nothing to learn from.
type Warmup struct {
	// MinObservations is how many events the profile must have folded in.
	MinObservations int
	// MinAge is how long it must have been learning, measured from the OLDEST
	// observation it holds — which is what makes PrimeFromHistory count. A
	// profile primed from three weeks of stored events is three weeks old the
	// moment it loads, because it has genuinely seen three weeks of behaviour.
	MinAge time.Duration
}

// DefaultWarmup is tuned for a deployment that primes from stored history.
//
// The numbers are low BECAUSE priming exists: an established host reaches them
// instantly from data it already had, and a genuinely fresh install still has
// to observe real activity for half an hour before it is allowed an opinion.
// Raising these on a quiet estate only ever delays the first true finding; the
// readiness report is what tells an operator which state they are in.
var DefaultWarmup = Warmup{MinObservations: 500, MinAge: 30 * time.Minute}

// Observation is one process execution, reduced to the fields that carry
// behavioural signal. Everything else about an exec — pid, exec id, arguments —
// is either unique per run (and so carries no frequency information at all) or
// is already covered by the rule scorer.
type Observation struct {
	Binary       string
	ParentBinary string
	UID          uint32
	At           time.Time
}

// Assessment is what the profile makes of one observation.
type Assessment struct {
	// Points is the anomaly contribution, always >= 0 and <= MaxEventPoints.
	Points int
	// Reasons are analyst-readable, one per facet that fired. These are what
	// end up in the alert, and they are the whole point: "score 34" tells an
	// analyst nothing, "nginx has never launched sh on this host" ends the
	// triage.
	Reasons []string
	// Novel reports that at least one facet had never seen this key.
	Novel bool
	// Routine reports the opposite — every facet found this ordinary. It
	// carries NO points in either direction; it exists so the console can say
	// "this is what this host always does", which is the fastest false-positive
	// dismissal there is.
	Routine bool
	// Ready is false when the profile is still warming up. Points is 0 then,
	// and a caller that surfaces anomalies must say so rather than reporting
	// "nothing anomalous" — those are different statements.
	Ready bool
}

// entry is one key's decayed frequency.
type entry struct {
	weight    float64
	count     uint64
	firstSeen time.Time
	lastSeen  time.Time
}

// facet is one keyed frequency table plus its running total.
type facet struct {
	keys  map[string]*entry
	total float64
	// totalAt is when total was last decayed, so the denominator ages at the
	// same rate as the numerators. Without it a profile that goes quiet keeps
	// a stale large total and every key looks rarer than it is.
	totalAt time.Time
}

// Profile is a host's learned behaviour. Safe for concurrent use: the event
// pipeline assesses on the stream goroutine while the API reads it.
type Profile struct {
	mu     sync.RWMutex
	facets map[string]*facet
	warmup Warmup

	observations int
	oldest       time.Time // earliest observation time folded in
	newest       time.Time

	// dirty marks unflushed changes, so a periodic flush that has nothing to
	// write does no database work at all on an idle host.
	dirty bool
}

// New returns an empty profile with the given warm-up rule. A zero Warmup gets
// DefaultWarmup — a caller that forgets to configure it must not accidentally
// get a profile that scores immediately.
func New(w Warmup) *Profile {
	if w.MinObservations <= 0 {
		w.MinObservations = DefaultWarmup.MinObservations
	}
	if w.MinAge <= 0 {
		w.MinAge = DefaultWarmup.MinAge
	}
	return &Profile{facets: map[string]*facet{}, warmup: w}
}

// decay returns w aged from `from` to `to`. Time only moves forward here: an
// out-of-order event (a replayed batch, a clock step) must not INFLATE a
// weight, which is what a negative elapsed time would do.
func decay(w float64, from, to time.Time) float64 {
	if w == 0 || from.IsZero() || !to.After(from) {
		return w
	}
	return w * math.Exp2(-to.Sub(from).Hours()/HalfLife.Hours())
}

func (p *Profile) facet(name string) *facet {
	f, ok := p.facets[name]
	if !ok {
		f = &facet{keys: map[string]*entry{}}
		p.facets[name] = f
	}
	return f
}

// keysFor derives the facet keys for an observation. One place, so Assess and
// Observe cannot drift into judging one key and learning another — which would
// make every event permanently novel and would be invisible in any test that
// only checked one of the two paths.
func keysFor(o Observation) map[string]string {
	bin := normaliseBinary(o.Binary)
	keys := map[string]string{}
	if bin == "" {
		// A kernel thread or an empty binary is not an execution. Returning no
		// keys at all — rather than just skipping the binary facet — is what
		// stops it being counted as an observation, which would otherwise let
		// kthreadd churn satisfy the warm-up gate without teaching anything.
		return keys
	}
	keys[FacetBinary] = bin
	keys[FacetUserBin] = strconv.FormatUint(uint64(o.UID), 10) + ":" + bin
	if parent := normaliseBinary(o.ParentBinary); parent != "" {
		keys[FacetEdge] = parent + ">" + bin
	}
	if !o.At.IsZero() {
		keys[FacetHour] = strconv.Itoa(o.At.Hour())
	}
	return keys
}

// normaliseBinary strips the noise that would otherwise make every execution of
// the same program a distinct key.
//
// Kernel threads arrive bracketed ("[kworker/0:2]") and are not executables at
// all; counting them teaches the profile nothing and floods the binary facet.
// Interpreter and container paths carry a pid or a layer hash in the middle
// (/proc/self/exe, /var/lib/docker/overlay2/<64-hex>/...), so the raw path is
// unique per run — the same failure the scorer already hit with kprobe file
// paths, one facet further out.
func normaliseBinary(b string) string {
	b = strings.TrimSpace(b)
	if b == "" {
		return ""
	}
	if strings.HasPrefix(b, "[") && strings.HasSuffix(b, "]") {
		return "" // kernel thread, not an execution
	}
	// A file-descriptor re-exec is keyed by the DIRECTORY, not the basename.
	//
	// The basename of /proc/self/fd/9 is "9" — a file-descriptor number, which
	// is per-run and carries no identity at all. Measured on the live engine:
	// "9" was the fourth most-observed "executable" on the host with 6,116
	// observations, sitting in the binary facet between /usr/bin/cat and
	// /usr/bin/grep, and colliding with every other numeric basename. That is
	// exactly the per-run-uniqueness this function exists to remove, so the
	// general rule below made it worse rather than better.
	//
	// runc and podman both re-exec through /proc/self/fd/<n>, so collapsing the
	// whole family to one stable key is also the honest description: what the
	// profile can actually say is "a container runtime re-exec happened here".
	if i := strings.LastIndexByte(b, '/'); i > 0 && strings.HasPrefix(b, "/proc/") &&
		isAllDigits(b[i+1:]) {
		return b[:i]
	}
	// A path containing a numeric or hex path segment long enough to be an id
	// is collapsed to its basename: the directory is per-run, the program is
	// not.
	if strings.HasPrefix(b, "/proc/") || strings.Contains(b, "/overlay2/") ||
		strings.Contains(b, "/containers/") {
		return path.Base(b)
	}
	// usr-merge: /bin, /sbin and /lib are symlinks into /usr on every distro
	// this ships to, so /bin/bash and /usr/bin/bash are the SAME inode reached
	// by two spellings — and the kernel reports whichever one the caller used.
	//
	// Left unmerged they are two keys, and that produced a self-inflicted
	// critical on the live engine: the host runs /bin/bash constantly (routine,
	// thousands of observations) while sudo execs /usr/bin/bash, which had
	// almost none. So every `sudo bash` was scored "executable is rare on this
	// host: /usr/bin/bash" plus "uid 0 rarely runs /usr/bin/bash", and the
	// most routine administrative action on the box reached score 144.
	//
	// Canonicalising to the /usr form is the direction the symlinks point, so
	// the merged key is the one that already holds the history.
	for _, alias := range [...]struct{ from, to string }{
		{"/bin/", "/usr/bin/"},
		{"/sbin/", "/usr/sbin/"},
		{"/lib/", "/usr/lib/"},
	} {
		if strings.HasPrefix(b, alias.from) {
			return alias.to + b[len(alias.from):]
		}
	}
	return b
}

// isAllDigits reports whether s is a non-empty run of ASCII digits. Used to
// recognise a file-descriptor path segment; strconv.Atoi would also accept a
// sign and silently overflow, neither of which is wanted here.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Assess judges an observation WITHOUT learning from it.
//
// Callers must call this before Observe. Doing it the other way round folds the
// event into the profile first, so it has already made itself normal and the
// assessment is always "routine" — a bug that produces a feature which appears
// to work, reports nothing, and cannot be distinguished from a quiet estate.
func (p *Profile) Assess(o Observation) Assessment {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := Assessment{Ready: p.ready()}
	if !out.Ready {
		return out
	}

	at := o.At
	if at.IsZero() {
		at = time.Now()
	}
	keys := keysFor(o)

	// Weights per facet, in the order they are reported. Deliberately not a map
	// iteration: reason order must be stable, because these strings land in
	// alert descriptions that operators compare between hosts.
	type rule struct {
		facet        string
		unseen, rare int
		// minSpan is how long the profile must have been learning before this
		// facet may score at all. Zero for facets whose keys are meaningful
		// from the first observation; see HourMinSpan for the one that is not.
		minSpan      time.Duration
		unseenReason func(key string) string
		rareReason   func(key string) string
	}
	// Span is measured across what the profile has actually OBSERVED, not since
	// the process started — so a profile primed from three weeks of stored
	// events is three weeks old immediately, exactly as the readiness gate
	// treats it.
	span := p.newest.Sub(p.oldest)
	rules := []rule{
		{
			facet: FacetEdge, unseen: 8, rare: 4,
			unseenReason: func(k string) string {
				return "process lineage never seen on this host: " + strings.ReplaceAll(k, ">", " launched ")
			},
			rareReason: func(k string) string {
				return "process lineage is rare on this host: " + strings.ReplaceAll(k, ">", " launched ")
			},
		},
		{
			facet: FacetBinary, unseen: 6, rare: 3,
			unseenReason: func(k string) string { return "executable never seen on this host: " + k },
			rareReason:   func(k string) string { return "executable is rare on this host: " + k },
		},
		{
			facet: FacetUserBin, unseen: 4, rare: 2,
			unseenReason: func(k string) string {
				uid, bin, _ := strings.Cut(k, ":")
				return "uid " + uid + " has never run " + bin + " on this host"
			},
			rareReason: func(k string) string {
				uid, bin, _ := strings.Cut(k, ":")
				return "uid " + uid + " rarely runs " + bin + " on this host"
			},
		},
		{
			facet: FacetHour, unseen: 3, rare: 0, minSpan: HourMinSpan,
			unseenReason: func(k string) string { return "this host has never been active at hour " + k + " before" },
			rareReason:   func(string) string { return "" },
		},
	}

	seenSomething := false
	for _, r := range rules {
		key, ok := keys[r.facet]
		if !ok {
			continue
		}
		if r.minSpan > 0 && span < r.minSpan {
			// Not yet entitled to an opinion. It keeps LEARNING (Observe is
			// unaffected) — it simply does not score until it has watched long
			// enough for an unseen key to mean something.
			continue
		}
		f, ok := p.facets[r.facet]
		if !ok || f.total <= 0 {
			continue // nothing learned in this facet yet; it gets no opinion
		}
		seenSomething = true
		share := f.share(key, at)
		switch {
		case share == 0:
			out.Points += r.unseen
			out.Reasons = append(out.Reasons, r.unseenReason(key))
			out.Novel = true
		case share < rareShare && r.rare > 0:
			out.Points += r.rare
			out.Reasons = append(out.Reasons, r.rareReason(key))
		}
	}

	if out.Points > MaxEventPoints {
		out.Points = MaxEventPoints
	}
	out.Routine = seenSomething && out.Points == 0
	return out
}

// rareShare is the frequency below which a key counts as rare: less than one in
// two hundred of this facet's decayed observations.
//
// Not a percentile. A percentile over a long tail of one-off build artefacts
// would mark half of a normal host rare, and the point of this facet is to be
// quiet on a normal host.
const rareShare = 0.005

// share returns a key's decayed proportion of its facet, 0 when never seen.
func (f *facet) share(key string, at time.Time) float64 {
	e, ok := f.keys[key]
	if !ok {
		return 0
	}
	total := decay(f.total, f.totalAt, at)
	if total <= 0 {
		return 0
	}
	w := decay(e.weight, e.lastSeen, at)
	if w <= 0 {
		return 0
	}
	return w / total
}

// Observe folds an observation into the profile. Call it AFTER Assess.
func (p *Profile) Observe(o Observation) {
	at := o.At
	if at.IsZero() {
		at = time.Now()
	}
	keys := keysFor(o)
	if len(keys) == 0 {
		return // a kernel thread or an empty binary teaches nothing
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for name, key := range keys {
		f := p.facet(name)
		f.total = decay(f.total, f.totalAt, at) + 1
		f.totalAt = at
		e, ok := f.keys[key]
		if !ok {
			e = &entry{firstSeen: at}
			f.keys[key] = e
		}
		e.weight = decay(e.weight, e.lastSeen, at) + 1
		e.count++
		if at.After(e.lastSeen) {
			e.lastSeen = at
		}
		if at.Before(e.firstSeen) {
			e.firstSeen = at
		}
		// The hour facet has 24 possible keys and can never need eviction;
		// checking it anyway costs a map length read and keeps the rule
		// uniform.
		if len(f.keys) > maxKeysPerFacet {
			f.evict(at)
		}
	}

	p.observations++
	p.dirty = true
	if p.oldest.IsZero() || at.Before(p.oldest) {
		p.oldest = at
	}
	if at.After(p.newest) {
		p.newest = at
	}
}

// evict trims a facet to evictTo entries, dropping the lowest decayed weights.
// The total is deliberately NOT reduced by what was evicted: those observations
// really did happen, and lowering the denominator would make every surviving
// key look more common than it is, which is the direction that hides novelty.
func (f *facet) evict(at time.Time) {
	type kv struct {
		key string
		w   float64
	}
	all := make([]kv, 0, len(f.keys))
	for k, e := range f.keys {
		all = append(all, kv{k, decay(e.weight, e.lastSeen, at)})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].w < all[j].w })
	for i := 0; i < len(all)-evictTo; i++ {
		delete(f.keys, all[i].key)
	}
}

// ready reports whether the profile may score. Caller holds the lock.
func (p *Profile) ready() bool {
	if p.observations < p.warmup.MinObservations {
		return false
	}
	if p.oldest.IsZero() {
		return false
	}
	return p.newest.Sub(p.oldest) >= p.warmup.MinAge
}

// Ready reports whether the profile has learned enough to score.
func (p *Profile) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ready()
}

// Status is the readiness and shape of a profile, for the API and the console.
//
// It reports PROGRESS toward readiness, not just a boolean, because "not ready"
// and "ready and found nothing" produce the same empty anomaly list and mean
// opposite things — the same distinction system_health already draws between a
// quiet feed and a broken one.
type Status struct {
	Ready            bool          `json:"ready"`
	Observations     int           `json:"observations"`
	NeedObservations int           `json:"need_observations"`
	SpanSeconds      int64         `json:"span_seconds"`
	NeedSpanSeconds  int64         `json:"need_span_seconds"`
	Oldest           time.Time     `json:"oldest,omitempty"`
	Newest           time.Time     `json:"newest,omitempty"`
	HalfLifeHours    float64       `json:"half_life_hours"`
	Facets           []FacetStatus `json:"facets"`
}

// FacetStatus is one facet's cardinality and the keys that dominate it.
type FacetStatus struct {
	Facet string   `json:"facet"`
	Keys  int      `json:"keys"`
	Total float64  `json:"total_weight"`
	Top   []TopKey `json:"top"`
}

// TopKey is a frequently-seen key — what "normal" actually looks like here.
type TopKey struct {
	Key   string  `json:"key"`
	Share float64 `json:"share"`
	Count uint64  `json:"count"`
}

// Status snapshots the profile. topN bounds the sample per facet.
func (p *Profile) Status(topN int) Status {
	p.mu.RLock()
	defer p.mu.RUnlock()

	at := p.newest
	if at.IsZero() {
		at = time.Now()
	}
	st := Status{
		Ready:            p.ready(),
		Observations:     p.observations,
		NeedObservations: p.warmup.MinObservations,
		NeedSpanSeconds:  int64(p.warmup.MinAge.Seconds()),
		HalfLifeHours:    HalfLife.Hours(),
		Facets:           []FacetStatus{},
	}
	if !p.oldest.IsZero() {
		st.Oldest, st.Newest = p.oldest, p.newest
		st.SpanSeconds = int64(p.newest.Sub(p.oldest).Seconds())
	}
	// Fixed order so two reads of an unchanged profile are byte-identical —
	// a console that re-renders because a map iterated differently is noise.
	for _, name := range []string{FacetEdge, FacetBinary, FacetUserBin, FacetHour} {
		f, ok := p.facets[name]
		if !ok {
			continue
		}
		fs := FacetStatus{Facet: name, Keys: len(f.keys), Total: decay(f.total, f.totalAt, at), Top: []TopKey{}}
		type kv struct {
			key string
			e   *entry
			w   float64
		}
		all := make([]kv, 0, len(f.keys))
		for k, e := range f.keys {
			all = append(all, kv{k, e, decay(e.weight, e.lastSeen, at)})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].w != all[j].w {
				return all[i].w > all[j].w
			}
			return all[i].key < all[j].key
		})
		for i := 0; i < len(all) && i < topN; i++ {
			share := 0.0
			if fs.Total > 0 {
				share = all[i].w / fs.Total
			}
			fs.Top = append(fs.Top, TopKey{Key: all[i].key, Share: share, Count: all[i].e.count})
		}
		st.Facets = append(st.Facets, fs)
	}
	return st
}
