package hoststack

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/eventpipe"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Startup for the two enrichment layers, shared by cmd/agent and cmd/engine.
//
// It lives here for the reason internal/eventpipe exists at all: this path used
// to be duplicated inside two main() functions, and the copy that did not get a
// fix meant two hosts on the same version disagreed about whether a chain was
// worth containing. Enrichment changes the score, so the same rule applies with
// the same force — an agent that primes its baseline and an engine that does
// not would score identical behaviour differently.

// Enrichment is the wired-up result, ready to be attached to a Pipeline.
type Enrichment struct {
	Baseline *baseline.Profile
	Intel    *intel.Set
	Hasher   *intel.Hasher
	Findings *findings.Ring

	store     *baseline.Store
	refresher *intel.Refresher
}

// EnrichmentSettings configures both layers.
type EnrichmentSettings struct {
	// BaselineEnabled turns behavioural scoring on. Off leaves the profile nil
	// and the pipeline behaves exactly as it did before the feature existed.
	BaselineEnabled bool
	// MinObservations and MinAge are the warm-up gate. Zero uses the defaults.
	MinObservations int
	MinAge          time.Duration
	// PrimeLimit bounds how many stored events are replayed at startup.
	PrimeLimit int
	// FlushInterval is how often the profile is written back to the store.
	FlushInterval time.Duration

	// IntelDir is the indicator feed directory. Empty disables matching.
	IntelDir string
	// Refresh is the optional feed downloader. Disabled unless it has feeds
	// AND an interval — see intel/refresh.go for why the default is off.
	Refresh intel.RefreshConfig
}

// DefaultEnrichment is what a deployment gets without explicit configuration:
// behavioural baselining ON, indicator matching ON if a feed directory exists,
// and no outbound feed fetching.
//
// The asymmetry is deliberate. Baselining is self-contained — it learns from
// data the host already produces and reaches nothing outside the box, so
// enabling it by default costs an operator nothing they have to think about.
// Feed REFRESHING reaches the network, so it stays opt-in on the same principle
// that keeps the assistant off until configured.
func DefaultEnrichment() EnrichmentSettings {
	return EnrichmentSettings{
		BaselineEnabled: true,
		MinObservations: baseline.DefaultWarmup.MinObservations,
		MinAge:          baseline.DefaultWarmup.MinAge,
		PrimeLimit:      200_000,
		FlushInterval:   5 * time.Minute,
		IntelDir:        DefaultIntelDir,
		Refresh:         intel.DefaultRefresh(),
	}
}

// DefaultIntelDir is where an operator drops feed files.
const DefaultIntelDir = "/etc/ebpf-soc/intel"

// primeSource is the narrow read this needs from the store, named as an
// interface so a test can prime from a fixture without a database.
type primeSource interface {
	RecentExecObservations(limit int) ([]store.ExecObservation, error)
}

// NewEnrichment builds both layers, restoring and priming the baseline.
//
// Never fatal. Every failure here degrades to "that layer is off" and is
// logged: a host that will not start because a threat feed had a syntax error
// is a worse outcome than a host running without that feed, and this is the
// sensing path.
func NewEnrichment(s EnrichmentSettings, db *sql.DB, dialect string, src primeSource) *Enrichment {
	e := &Enrichment{Findings: findings.NewRing()}

	if s.BaselineEnabled {
		e.Baseline = baseline.New(baseline.Warmup{
			MinObservations: s.MinObservations,
			MinAge:          s.MinAge,
		})
		e.wireBaselineStore(db, dialect, src, s.PrimeLimit)
	}

	if dir := strings.TrimSpace(s.IntelDir); dir != "" {
		set := intel.NewSet()
		if err := set.LoadDir(dir); err != nil {
			// A missing directory is the normal case on a host where nobody has
			// dropped feeds yet. Logged at info, and the set stays empty and
			// harmless rather than the process refusing to start.
			log.Printf("[intel] no feeds loaded from %s: %v", dir, err)
		}
		st := set.Status()
		log.Printf("[intel] %d indicators from %d sources (%d ip, %d cidr, %d domain, %d hash, %d allowlisted)",
			st.Indicators, len(st.Sources), st.IPs, st.CIDRs, st.Domains, st.Hashes, st.Allowed)
		for _, msg := range st.Errors {
			log.Printf("[intel] %s", msg)
		}
		e.Intel = set
		e.Hasher = intel.NewHasher()
		// The refresher configures itself from feeds.yaml INSIDE the feed
		// directory, so enabling it is a file an operator drops next to the
		// indicators — no flag, no config plumbing through two settings
		// structs, and no way for the engine and the agent to be configured
		// differently for the same estate.
		refresh, err := intel.LoadRefreshConfig(dir)
		if err != nil {
			// Loud, and off. A deployment that believes it is refreshing feeds
			// and is not is the silent-coverage-loss failure this whole package
			// is built to avoid.
			log.Printf("[intel] feed refresh DISABLED — %v", err)
		} else if s.Refresh.Enabled() {
			refresh = s.Refresh // an explicit caller-supplied config still wins
		}
		if refresh.Dir == "" {
			refresh.Dir = dir
		}
		if refresh.Enabled() {
			e.refresher = intel.NewRefresher(refresh, set)
			log.Printf("[intel] feed refresh every %s across %d feeds", refresh.Interval, len(refresh.Feeds))
		}
	}
	return e
}

// wireBaselineStore restores a saved profile, or primes one from stored events.
//
// Restore FIRST, prime only if that produced nothing. A restored profile
// already contains the priming of every previous start, so priming on top of it
// would replay the same executions again and again, inflating every weight a
// little more on each restart until the whole profile said "everything here is
// extremely common" and nothing was ever novel again.
func (e *Enrichment) wireBaselineStore(db *sql.DB, dialect string, src primeSource, limit int) {
	if db == nil {
		return
	}
	bs, err := baseline.NewStore(db, dialect)
	if err != nil {
		log.Printf("[baseline] persistence unavailable, learning in memory only: %v", err)
		return
	}
	e.store = bs

	snap, err := bs.Load()
	if err != nil {
		log.Printf("[baseline] could not load the saved profile: %v", err)
	} else if len(snap.Rows) > 0 {
		e.Baseline.Restore(snap)
		st := e.Baseline.Status(0)
		log.Printf("[baseline] restored %d observations across %d facets (ready=%v)",
			st.Observations, len(st.Facets), st.Ready)
		return
	}

	if src == nil || limit <= 0 {
		return
	}
	rows, err := src.RecentExecObservations(limit)
	if err != nil {
		log.Printf("[baseline] could not prime from history: %v", err)
		return
	}
	obs := make([]baseline.Observation, 0, len(rows))
	for _, r := range rows {
		obs = append(obs, baseline.Observation{
			Binary: r.Binary, ParentBinary: r.ParentBinary, UID: r.UID, At: r.At,
		})
	}
	n := e.Baseline.PrimeFromHistory(obs)
	st := e.Baseline.Status(0)
	log.Printf("[baseline] primed from %d stored executions spanning %s (ready=%v)",
		n, time.Duration(st.SpanSeconds)*time.Second, st.Ready)
}

// Attach wires the enrichment onto a pipeline.
func (e *Enrichment) Attach(p *eventpipe.Pipeline) {
	if e == nil {
		return
	}
	p.Baseline = e.Baseline
	p.Intel = e.Intel
	p.Hasher = e.Hasher
	p.Findings = e.Findings
}

// Start runs the periodic profile flush and the optional feed refresher.
func (e *Enrichment) Start(ctx context.Context, flushEvery time.Duration) {
	if e == nil {
		return
	}
	if e.refresher != nil {
		go e.refresher.Run(ctx)
	}
	if e.Baseline == nil || e.store == nil {
		return
	}
	if flushEvery <= 0 {
		flushEvery = 5 * time.Minute
	}
	go func() {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// Flush on the way out. Without this, everything learned since
				// the last tick is lost on every restart — and a restart is
				// exactly when the warm-up gate makes that loss expensive.
				e.Flush()
				return
			case <-t.C:
				e.Flush()
			}
		}
	}()
}

// Flush persists the profile if it has changed.
func (e *Enrichment) Flush() {
	if e == nil || e.Baseline == nil || e.store == nil || !e.Baseline.Dirty() {
		return
	}
	if err := e.store.Save(e.Baseline.Snapshot()); err != nil {
		log.Printf("[baseline] flush failed: %v", err)
		return
	}
	e.Baseline.MarkClean()
}

// RefreshStatus reports the feed refresher for the API.
func (e *Enrichment) RefreshStatus() intel.RefreshStatus {
	if e == nil {
		return intel.RefreshStatus{}
	}
	return e.refresher.Status()
}

// ── api.EnrichmentSource ───────────────────────────────────────────────────
// Implemented here rather than in internal/api so the API package depends on an
// interface it declares and not on this one's wiring. Every method is nil-safe
// on each layer independently: a deployment running the baseline but no feeds
// answers /api/baseline with data and /api/intel with "not loaded", rather than
// both with an error.

// BaselineStatus reports the profile, and false when baselining is off.
func (e *Enrichment) BaselineStatus(topN int) (baseline.Status, bool) {
	if e == nil || e.Baseline == nil {
		return baseline.Status{}, false
	}
	return e.Baseline.Status(topN), true
}

// IntelStatus reports the indicator set, and false when no feed directory was
// configured.
func (e *Enrichment) IntelStatus() (intel.Status, bool) {
	if e == nil || e.Intel == nil {
		return intel.Status{}, false
	}
	return e.Intel.Status(), true
}

// IntelRefreshStatus reports the optional feed downloader.
func (e *Enrichment) IntelRefreshStatus() intel.RefreshStatus {
	if e == nil {
		return intel.RefreshStatus{}
	}
	return e.refresher.Status()
}

// RecentFindings returns recent enrichment results, newest first.
func (e *Enrichment) RecentFindings(kind string, limit int) []findings.Finding {
	if e == nil {
		return []findings.Finding{}
	}
	return e.Findings.Recent(kind, limit)
}

// FindingTotals returns lifetime counts, which survive the ring wrapping.
func (e *Enrichment) FindingTotals() (uint64, uint64) {
	if e == nil {
		return 0, 0
	}
	return e.Findings.Totals()
}

// LookupIndicator answers the operator-facing "is this known" question.
func (e *Enrichment) LookupIndicator(value string) (intel.Match, bool) {
	if e == nil || e.Intel == nil {
		return intel.Match{}, false
	}
	return e.Intel.Lookup(value)
}
