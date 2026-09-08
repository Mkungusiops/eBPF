package controlplane

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/platformdoc"
)

// Per-TENANT enrichment on the control plane.
//
// # Why this exists in addition to the agent-side layer
//
// The sensors learn a PER-HOST baseline, because that is where scoring happens
// and where the answer has to be available in microseconds. But the agents
// cannot learn a per-tenant one: an agent never knows its own tenant. Tenant
// identity is derived from the mTLS client certificate AT THE COLLECTOR
// (tenant-isolation-invariant.md R1/Layer 2), and that is deliberate — an agent
// that could name its tenant could name someone else's.
//
// So the tenant-wide behavioural profile can only be built here, on the far
// side of that boundary, and it answers a question no single host can:
// "this is normal on the box it ran on, but no other host in this tenant has
// ever done it". A build server compiling code is unremarkable; the same
// activity appearing on a database host is the finding.
//
// It is fed FROM THE INGEST STREAM rather than by querying the telemetry table.
// That is not an optimisation, it is a hard constraint learned on 2026-08-05:
// an aggregate over this tenant's history is exactly the query shape that took
// the control plane down — a 2.8M-row sort per request until the connection
// pool exhausted max_connections. The records are already in hand at ingest;
// folding them into an in-memory profile there costs one map write and touches
// the database not at all.

// maxTenantProfiles bounds how many tenants are profiled at once.
//
// Bounded because tenant_id arrives from a certificate the collector verified,
// but the number of tenants is a business fact, not a constant — and every
// unbounded map in this codebase has had to be bounded after it leaked. When
// the cap is reached, new tenants simply get no profile, which degrades the
// feature rather than the process.
const maxTenantProfiles = 512

// maxTenantFindings bounds one tenant's finding ring; see internal/findings.
const perTenantFindings = 512

// tenantEnricher holds one profile and one finding ring per tenant.
type tenantEnricher struct {
	mu       sync.RWMutex
	profiles map[string]*baseline.Profile
	rings    map[string]*findings.Ring

	set    *intel.Set
	warmup baseline.Warmup
	// store persists the profiles. nil means in-memory only, which is what a
	// non-Postgres deployment and every test get — the feature degrades to its
	// previous behaviour rather than failing.
	store *baseline.TenantStore
}

func newTenantEnricher(set *intel.Set, w baseline.Warmup) *tenantEnricher {
	return &tenantEnricher{
		profiles: map[string]*baseline.Profile{},
		rings:    map[string]*findings.Ring{},
		set:      set, warmup: w,
	}
}

// restore loads every stored tenant profile at startup.
//
// Best-effort, per tenant. A profile that will not load leaves that tenant
// learning from scratch — which is exactly the behaviour before this existed —
// rather than aborting startup for the others.
func (t *tenantEnricher) restore(logf func(string, ...any)) {
	if t.store == nil {
		return
	}
	tenants, err := t.store.Tenants()
	if err != nil {
		logf("[baseline] could not list stored tenant profiles: %v", err)
		return
	}
	for _, tenant := range tenants {
		snap, err := t.store.Load(tenant)
		if err != nil {
			logf("[baseline] tenant %s: profile not restored: %v", tenant, err)
			continue
		}
		if len(snap.Rows) == 0 {
			continue
		}
		p, _ := t.forTenant(tenant)
		if p == nil {
			continue
		}
		p.Restore(snap)
		st := p.Status(0)
		logf("[baseline] tenant %s restored: %d observations spanning %s (ready=%v)",
			tenant, st.Observations, time.Duration(st.SpanSeconds)*time.Second, st.Ready)
	}
}

// flush persists every dirty tenant profile.
func (t *tenantEnricher) flush(logf func(string, ...any)) {
	if t.store == nil {
		return
	}
	t.mu.RLock()
	snapshot := make(map[string]*baseline.Profile, len(t.profiles))
	for k, v := range t.profiles {
		snapshot[k] = v
	}
	t.mu.RUnlock()

	for tenant, p := range snapshot {
		if !p.Dirty() {
			continue
		}
		if err := t.store.Save(tenant, p.Snapshot()); err != nil {
			logf("[baseline] tenant %s: flush failed: %v", tenant, err)
			continue
		}
		p.MarkClean()
	}
}

// runFlush persists profiles periodically and once on the way out.
//
// The shutdown flush is the one that matters: without it everything learned
// since the last tick is lost on every restart, which is the exact loss this
// store was added to prevent.
func (t *tenantEnricher) runFlush(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	if t.store == nil {
		return
	}
	if every <= 0 {
		every = 5 * time.Minute
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.flush(logf)
			return
		case <-tick.C:
			t.flush(logf)
		}
	}
}

// forTenant returns a tenant's profile and ring, creating them under the cap.
func (t *tenantEnricher) forTenant(tenant string) (*baseline.Profile, *findings.Ring) {
	t.mu.RLock()
	p, ring := t.profiles[tenant], t.rings[tenant]
	t.mu.RUnlock()
	if p != nil {
		return p, ring
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.profiles[tenant]; p != nil {
		return p, t.rings[tenant]
	}
	if len(t.profiles) >= maxTenantProfiles {
		return nil, nil
	}
	p = baseline.New(t.warmup)
	ring = findings.NewRingSized(perTenantFindings)
	t.profiles[tenant], t.rings[tenant] = p, ring
	return p, ring
}

// Sink wraps another ingest.Sink, enriching each record on the way past.
//
// Enrichment happens BEFORE the delegate, but its failure can never stop the
// delegate: telemetry storage is the product, and an enrichment bug that
// dropped records would be a data-loss incident wearing a detection feature's
// clothes. Everything here is a map write and a lookup against an in-memory
// set — no I/O, nothing that can block the collector.
type Sink struct {
	next ingest.Sink
	enr  *tenantEnricher
}

// WrapSink returns a Sink that enriches then forwards. A nil enricher returns
// the delegate untouched, so a deployment with no feeds and no baselining has
// exactly the ingest path it had before.
func WrapSink(next ingest.Sink, enr *tenantEnricher) ingest.Sink {
	if enr == nil {
		return next
	}
	return &Sink{next: next, enr: enr}
}

// Put enriches and forwards one stamped record.
func (s *Sink) Put(rec ingest.StampedRecord) error {
	s.enr.observe(rec)
	return s.next.Put(rec)
}

// observe folds one record into its tenant's profile and matches indicators.
func (t *tenantEnricher) observe(rec ingest.StampedRecord) {
	ev := rec.Record.GetEvent()
	if ev == nil {
		return
	}
	at := ev.GetOccurredAt().AsTime()
	if at.IsZero() {
		at = time.Now()
	}

	// Indicator matching first: it is independent of the profile and must
	// happen even for a tenant past the profile cap.
	if t.set != nil {
		var cands []intel.Candidate
		if ip := strings.TrimSpace(ev.GetDestIp()); ip != "" {
			cands = append(cands, intel.Candidate{Value: ip, Kind: intel.KindIP, Where: "connection"})
		}
		switch ev.GetEventType() {
		case "process_kprobe":
			cands = append(cands, intel.FromKprobe(ev.GetPolicyName(), ev.GetArgs())...)
		default:
			cands = append(cands, intel.FromCommandLine(ev.GetBinary(), ev.GetArgs())...)
		}
		if matches := intel.MatchAll(t.set, cands); len(matches) > 0 {
			_, ring := t.forTenant(rec.TenantID)
			for _, m := range matches {
				match := m
				ring.Add(findings.Finding{
					At: at, Kind: "intel", ExecID: ev.GetExecId(), PID: ev.GetPid(),
					Binary: ev.GetBinary(), Points: m.Points, Match: &match,
					Reasons: []string{intel.Describe(m)},
					Agent:   rec.AgentID,
				})
			}
		}
	}

	if ev.GetEventType() != "process_exec" || ev.GetBinary() == "" {
		return
	}
	p, ring := t.forTenant(rec.TenantID)
	if p == nil {
		return
	}
	// The control plane sees the parent PID but not the parent's name — that
	// join lives on the sensor, which has the process tree. The tenant profile
	// therefore learns the binary and user facets across every host, and leaves
	// lineage to the layer that can see it. Reporting only what it can actually
	// observe is the point: a tenant-wide "lineage" built from guessed parents
	// would be confident and wrong.
	o := baseline.Observation{Binary: ev.GetBinary(), UID: ev.GetUid(), At: at}
	a := p.Assess(o)
	p.Observe(o)
	if a.Points > 0 {
		ring.Add(findings.Finding{
			At: at, Kind: "anomaly", ExecID: ev.GetExecId(), PID: ev.GetPid(),
			Binary: ev.GetBinary(), Points: a.Points, Reasons: a.Reasons,
			Agent: rec.AgentID,
		})
	}
}

// status returns one tenant's profile status.
func (t *tenantEnricher) status(tenant string, topN int) (baseline.Status, bool) {
	t.mu.RLock()
	p := t.profiles[tenant]
	t.mu.RUnlock()
	if p == nil {
		return baseline.Status{}, false
	}
	return p.Status(topN), true
}

// recent returns one tenant's findings.
func (t *tenantEnricher) recent(tenant, kind string, limit int) []findings.Finding {
	t.mu.RLock()
	ring := t.rings[tenant]
	t.mu.RUnlock()
	return ring.Recent(kind, limit)
}

func (t *tenantEnricher) totals(tenant string) (uint64, uint64) {
	t.mu.RLock()
	ring := t.rings[tenant]
	t.mu.RUnlock()
	return ring.Totals()
}

// tenants lists the profiled tenants, for the cross-tenant MSOC view.
func (t *tenantEnricher) tenants() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.profiles))
	for k := range t.profiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── HTTP ───────────────────────────────────────────────────────────────────

// WHICH CUSTOMER THESE PANELS ARE ABOUT.
//
// Every enrichment read below goes through authorizeRead, the one gate the rest
// of the read plane uses: the tenant named by ?tenant= when the console names
// one, the tenant stamped on the account when it does not (authz.DefaultTenant,
// the same value whoami publishes as viewing_tenant), and the RBAC grant checked
// either way.
//
// These handlers used to resolve the tenant from the principal alone, through
// the chat scope, and ignored ?tenant= entirely. Two consequences, both silent:
//
//   - a provider operator switching customers in the console kept reading the
//     SAME profile, underneath a banner asserting that every panel on screen is
//     the selected customer's data only. The banner is why an operator believes
//     the panel, so an unscoped panel under it is worse than an unscoped screen.
//   - for a CROSS-TENANT principal the chat scope's answer is not a customer at
//     all — it is the platform pseudo-tenant those operators' chat rows are
//     stamped with, which no agent ever reports under. So the Behaviour & Intel
//     panel was structurally empty for exactly the operators an MSSP staffs.
//
// Nothing is widened by routing through authorizeRead. A tenant-bound operator
// naming another customer is refused with a 404 that does not confirm whether
// that tenant exists (§6 side channels), and a cross-tenant read is recorded in
// operator_audit here exactly as it is on every other read path.

func (s *Server) registerEnrichmentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/baseline", s.handleBaseline)
	mux.HandleFunc("/api/baseline/anomalies", s.handleBaselineAnomalies)
	mux.HandleFunc("/api/intel", s.handleIntel)
	mux.HandleFunc("/api/intel/matches", s.handleIntelMatches)
	mux.HandleFunc("/api/intel/lookup", s.handleIntelLookup)
	mux.HandleFunc("/api/platform-doc", s.handlePlatformDoc)
}

func (s *Server) enrichmentEnabled(w http.ResponseWriter) bool {
	if s.enrich == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "enrichment is not enabled on this deployment",
		})
		return false
	}
	return true
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tenant, ok := s.authorizeRead(w, r)
	if !ok || !s.enrichmentEnabled(w) {
		return
	}
	st, enabled := s.enrich.status(tenant, cpClampInt(r.URL.Query().Get("top"), 10, 1, 50))
	anomalies, _ := s.enrich.totals(tenant)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled, "status": st, "anomalies_total": anomalies,
		// Named so the console cannot present this as if it were the sensor's
		// profile. They answer different questions and an operator comparing
		// them must know which is which.
		"scope": "tenant",
	})
}

func (s *Server) handleBaselineAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tenant, ok := s.authorizeRead(w, r)
	if !ok || !s.enrichmentEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": s.enrich.recent(tenant, "anomaly", cpClampInt(r.URL.Query().Get("limit"), 50, 1, 500)),
	})
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tenant, ok := s.authorizeRead(w, r)
	if !ok || !s.enrichmentEnabled(w) {
		return
	}
	var st intel.Status
	if s.enrich.set != nil {
		st = s.enrich.set.Status()
	}
	_, hits := s.enrich.totals(tenant)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": st, "refresh": s.intelRefresh.Status(), "matches_total": hits,
	})
}

func (s *Server) handleIntelMatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tenant, ok := s.authorizeRead(w, r)
	if !ok || !s.enrichmentEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": s.enrich.recent(tenant, "intel", cpClampInt(r.URL.Query().Get("limit"), 50, 1, 500)),
	})
}

func (s *Server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	if !s.enrichmentEnabled(w) {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q is required (max 256 chars)"})
		return
	}
	out := map[string]any{"query": q, "matched": false}
	if s.enrich.set != nil {
		if m, ok := s.enrich.set.Lookup(q); ok {
			out["matched"], out["match"] = true, m
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func cpClampInt(raw string, def, min, max int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// logEnrichmentStartup records what the control plane loaded, once.
func logEnrichmentStartup(st intel.Status, tenants int) {
	slog.Info("controlplane enrichment ready",
		"indicators", st.Indicators, "sources", len(st.Sources), "tenants_profiled", tenants)
}

// loadIntelSet reads the feed directory, or returns nil when none is
// configured.
//
// A load failure is logged and yields an EMPTY set rather than nil, which
// matters: an empty set reports Loaded=true with zero indicators, so the
// console can say "feeds configured but none parsed" instead of "feeds not
// configured". Those are an operator error and a deployment choice
// respectively, and they need different responses.
func loadIntelSet(dir string, logf func(string, ...any)) *intel.Set {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	set := intel.NewSet()
	if err := set.LoadDir(dir); err != nil && logf != nil {
		logf("[intel] no feeds loaded from %s: %v", dir, err)
	}
	return set
}

// handlePlatformDoc serves the product glossary — the same content the engine
// serves, from the same package, so the two deployments cannot describe their
// own behaviour differently.
//
//	GET /api/platform-doc          every topic
//	GET /api/platform-doc?topic=x  one topic
func (s *Server) handlePlatformDoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := s.principal(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if id := strings.TrimSpace(r.URL.Query().Get("topic")); id != "" {
		if t, ok := platformdoc.Get(id); ok {
			writeJSON(w, http.StatusOK, map[string]any{"matched": true, "topic": t})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"matched": false, "requested": id, "topics": platformdoc.List(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"topics": platformdoc.List()})
}
