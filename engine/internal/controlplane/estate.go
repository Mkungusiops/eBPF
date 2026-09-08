package controlplane

import (
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// The estate-wide view: one number per question, for the provider who runs
// several customers' SOCs at once — and never a number they cannot break down.
//
// # The rule this file exists to enforce
//
// An aggregate that cannot be decomposed is the same defect as a console
// presenting one customer as the whole estate, one level up: the operator sees
// a figure, cannot ask which customer produced it, and has no way to notice
// that it is wrong. So every total here ships with its per-tenant parts, and
// the parts are the primary data — the totals are derived from exactly the
// tenants listed, and the payload says which tenants those were.
//
// # What sums and what does not
//
// Counts and rates sum: alerts, decisions, contained processes, agents, dropped
// records. They are additive and mean the same thing combined.
//
// POSTURE DOES NOT. A mean over tenants hides one customer on fire behind nine
// quiet ones — which is precisely the situation an MSSP console exists to
// surface — so the estate posture is the WORST tenant's score, named, plus how
// many tenants sit at or above the concern threshold. There is no estate
// average anywhere in this payload, deliberately.
//
// # Zero and unknown are different answers
//
// A tenant whose read failed, timed out, or was never attempted contributes
// NOTHING to the totals and appears in the decomposition with status "unread"
// and the reason. It is never folded in as a zero: "no alerts" and "we could
// not look" lead to opposite operator decisions, and an estate view that
// conflates them under-reports an outage as calm.

// estateFanoutBudget bounds the whole endpoint.
//
// The fan-out is one read path per tenant and the central store's API takes no
// context, so a query already in flight CANNOT be cancelled — this budget
// bounds how long the RESPONSE waits, not how long the database works. That is
// the honest limit of what this layer can promise, and it is why a slow tenant
// degrades to "unread" instead of holding the console for every other customer.
const estateFanoutBudget = 8 * time.Second

// estateFanoutConcurrency is how many tenants are read at once. Low on purpose:
// each one costs a database connection for its duration, and the 2026-08-05
// outage was an unbounded Go pool exhausting max_connections. A cross-tenant
// console must not be able to do that to the tenant-facing console.
const estateFanoutConcurrency = 6

// estateMaxTenants bounds how many tenants a single response fans out over.
// Tenants past the bound are listed as unread with that reason rather than
// dropped, so the response cannot silently describe a subset of the estate as
// the estate.
const estateMaxTenants = 25

// estateAlertScanLimit bounds the alert read on a backend that cannot count in
// SQL; estateTechniqueSample bounds it when it can, because then the read is
// only for the technique split and a sample answers a mode.
const (
	estateAlertScanLimit  = 50_000
	estateTechniqueSample = 2_000
)

// Posture maths, mirrored from the console's dial (web/src/features/soc/risk.ts)
// so the two cannot answer differently for the same tenant.
//
// ONE DELIBERATE DIFFERENCE: the console rescales each tenant's dial to that
// tenant's own baseline, which makes a score meaningful within a tenant and
// MEANINGLESS BETWEEN THEM — a chronically noisy customer would read calm
// beside a quiet one having its worst day, and "the worst tenant" would name
// the wrong customer. The estate view therefore scores every tenant on the
// SAME fixed half-scale, and says so in the payload, so the comparison the
// number is used for is a comparison of like with like.
const (
	estateRiskHalfScalePerHour = 200.0 // weighted alerts/hour that reads 50
	estateWeightCritical       = 8
	estateWeightHigh           = 3
	estateWeightMedium         = 1
	// estateConcernScore is the console's "elevated" band boundary — the score
	// at which a customer stops being background and starts being a shift's
	// problem.
	estateConcernScore = 45
)

// estateTenantSummary is one customer's contribution, and the unit the whole
// endpoint is built from: the totals are a fold over these, never a separate
// query, so a total and its parts cannot disagree.
type estateTenantSummary struct {
	Tenant string `json:"tenant"`
	// Status is "read" or "unread". An unread tenant's counters are all zero
	// and MUST NOT be read as zeroes — see UnreadReason.
	Status       string `json:"status"`
	UnreadReason string `json:"unread_reason,omitempty"`

	Alerts           int            `json:"alerts"`
	AlertsBySeverity map[string]int `json:"alerts_by_severity,omitempty"`
	// AlertsExact is false when the count is a floor: the window held more
	// alerts than the scan bound, or the severity backfill has not finished.
	// The same honesty /api/alert-stats already publishes as Truncated.
	AlertsExact bool `json:"alerts_exact"`

	Decisions         int            `json:"decisions"`
	DecisionsByAction map[string]int `json:"decisions_by_action,omitempty"`

	// Contained is processes this tenant's fleet is holding right now (the
	// heartbeat choke snapshot, same source and same predicate as a fleet
	// release). Severed is counted apart because those processes are dead: a
	// release cannot undo them, and adding the two would overstate what is
	// still in hand.
	Contained int `json:"contained_processes"`
	Severed   int `json:"severed_processes"`

	Agents      int `json:"agents"`
	AgentsFresh int `json:"agents_fresh"`
	// DroppedRecords is telemetry these agents lost permanently to their uplink
	// buffer cap — an evidence gap, and the one estate number where a rise
	// means the platform is failing rather than the customer.
	DroppedRecords uint64 `json:"dropped_records"`

	// Posture is this tenant's 0-100 score on the shared fixed scale, higher
	// being worse. WeightedAlertsPerHour is the rate it was computed from,
	// published beside it because a score with its input hidden cannot be
	// checked.
	Posture               int     `json:"posture"`
	WeightedAlertsPerHour float64 `json:"weighted_alerts_per_hour"`

	// Techniques is this tenant's MITRE split — the per-tenant decomposition of
	// the estate's top technique. Sampled says the split came from the newest
	// N alerts in the window rather than all of them.
	Techniques             map[string]int `json:"techniques,omitempty"`
	TechniqueSampled       bool           `json:"techniques_sampled"`
	AlertsWithoutTechnique int            `json:"alerts_without_technique"`
}

// estatePosture is the estate's risk, stated the only way it can be stated
// honestly: by naming the worst customer.
type estatePosture struct {
	// Direction is published because a 0-100 score is ambiguous on sight, and
	// an operator who reads it backwards reads a fire as calm.
	Direction   string `json:"direction"`
	WorstScore  int    `json:"worst_score"`
	WorstTenant string `json:"worst_tenant,omitempty"`

	ConcernThreshold int `json:"concern_threshold"`
	// Both sides of the threshold, so the payload answers "how many customers
	// need attention" and "how many are fine" without the reader having to
	// subtract and get the direction wrong.
	TenantsAtOrAboveConcern int `json:"tenants_at_or_above_concern"`
	TenantsBelowConcern     int `json:"tenants_below_concern"`
	// TenantsUnscored is tenants whose posture is not known because their read
	// failed. They are not "below concern".
	TenantsUnscored int `json:"tenants_unscored"`

	Scale string `json:"scale"`
	Note  string `json:"note"`
}

// estateTechnique is the estate's most-seen ATT&CK technique — the MODE across
// tenants, carrying the split that produced it.
type estateTechnique struct {
	Technique string `json:"technique,omitempty"`
	Count     int    `json:"count"`
	// ByTenant is the decomposition: which customers contributed this
	// technique's count. An estate "top technique" driven entirely by one noisy
	// customer looks identical to a genuine campaign without it.
	ByTenant map[string]int `json:"by_tenant,omitempty"`
	// Sampled is true when any contributing tenant's split came from a sample
	// rather than every alert in the window.
	Sampled bool `json:"sampled"`
	// AlertsWithoutTechnique is how many sampled alerts carried no technique at
	// all, so "top technique" is never read as covering every alert.
	AlertsWithoutTechnique int    `json:"alerts_without_technique"`
	Note                   string `json:"note,omitempty"`
}

type estateTotals struct {
	Alerts            int            `json:"alerts"`
	AlertsBySeverity  severityCounts `json:"alerts_by_severity"`
	AlertsExact       bool           `json:"alerts_exact"`
	Decisions         int            `json:"decisions"`
	DecisionsByAction map[string]int `json:"decisions_by_action"`
	Contained         int            `json:"contained_processes"`
	Severed           int            `json:"severed_processes"`
	Agents            int            `json:"agents"`
	AgentsFresh       int            `json:"agents_fresh"`
	DroppedRecords    uint64         `json:"dropped_records"`
}

type estateSummary struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	WindowMin int       `json:"window_min"`

	TenantsTotal  int `json:"tenants_total"`
	TenantsRead   int `json:"tenants_read"`
	TenantsUnread int `json:"tenants_unread"`

	Totals       estateTotals    `json:"totals"`
	Posture      estatePosture   `json:"posture"`
	Top          estateTechnique `json:"top_technique"`
	RosterSource string          `json:"roster_source"`

	// Tenants is the decomposition every total above folds over, unread ones
	// included. Sorted worst-posture first so the customer that needs
	// attention is the first row, with unread tenants last — they are not
	// "fine", they are unknown, and burying them among the quiet ones is how an
	// outage reads as a calm night.
	Tenants []estateTenantSummary `json:"tenants"`

	// Bounds states what this response could not do, because a bounded answer
	// presented as a complete one is the defect this endpoint is built to
	// avoid.
	Bounds map[string]any `json:"bounds"`
}

func (s *Server) registerEstateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/estate/summary", s.handleEstateSummary)
}

// handleEstateSummary answers "how is the whole book of business doing" for a
// cross-tenant operator.
//
//	?window_min= window length in minutes (default 60, max 7 days)
func (s *Server) handleEstateSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	s.estateSummaryFor(w, r, p)
}

// estateSummaryFor is handleEstateSummary once the operator is known. Split for
// the same reason tenantsFor is — see there.
func (s *Server) estateSummaryFor(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	// Same refusal as every other unauthorized read here: 404, never 403, so a
	// tenant-bound analyst cannot learn that an estate view exists to be denied.
	if !authz.HasCrossTenant(p) {
		http.NotFound(w, r)
		return
	}

	windowMin := intParam(r, "window_min", 60, 60*24*7)
	to := time.Now().UTC()
	span := time.Duration(windowMin) * time.Minute
	from := to.Add(-span)

	roster, rosterSource := s.tenantRoster()

	// AUTHORIZE AND AUDIT EVERY TENANT, ON EVERY REQUEST.
	//
	// An aggregate is not a loophole around the access trail: reading ten
	// customers to build one number is ten cross-tenant accesses, and each is
	// recorded against the customer it names — where that customer can see it,
	// via /api/operator-audit. This loop is deliberately kept out of anything
	// that could later be memoised (see the stats cache in alertstats.go): the
	// figures may one day be reused between requests; the decision and its
	// audit row may not, because an access skipped for being already computed
	// is an access that happened and was never recorded.
	targets := make([]string, 0, len(roster))
	for _, t := range roster {
		if authz.Authorize(p, t.TenantID, authz.ActionRead, s.auditor).Allowed {
			targets = append(targets, t.TenantID)
		}
	}

	// Tenants past the fan-out bound are NAMED, not merely counted. An operator
	// has to be able to see which customers this response says nothing about;
	// "and 12 others" is the same defect as folding them in as zeroes, with the
	// count moved to a different field.
	var overflow []string
	if len(targets) > estateMaxTenants {
		overflow = append(overflow, targets[estateMaxTenants:]...)
		targets = targets[:estateMaxTenants]
	}

	summaries, timedOut := s.fanOutEstate(targets, from, to, span)
	for _, name := range overflow {
		summaries = append(summaries, estateTenantSummary{
			Tenant: name, Status: "unread",
			UnreadReason: "not attempted: this response fans out over at most " +
				strconv.Itoa(estateMaxTenants) + " tenants",
		})
	}

	out := foldEstate(summaries, from, to, windowMin)
	out.RosterSource = rosterSource
	out.Bounds = map[string]any{
		"max_tenants":       estateMaxTenants,
		"concurrency":       estateFanoutConcurrency,
		"budget_seconds":    int(estateFanoutBudget / time.Second),
		"budget_exceeded":   timedOut,
		"alert_scan_limit":  estateAlertScanLimit,
		"technique_sample":  estateTechniqueSample,
		"decision_scan_cap": decisionScanLimit,
		"cancellation": "the central store takes no context, so the budget bounds how long " +
			"this response waits, not how long a slow query runs",
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

// fanOutEstate reads every target tenant, bounded in width and in time.
//
// Bounded in WIDTH by a semaphore, so a large estate cannot open one database
// connection per customer at once. Bounded in TIME by a single budget for the
// whole response: when it expires the tenants still outstanding are reported
// unread rather than waited for, because one wedged customer must not be able
// to take the estate view down for the other twenty-four.
//
// The results channel is buffered to the full width, so a worker that finishes
// after the budget has expired still completes and exits instead of blocking
// forever on a send nobody is receiving.
func (s *Server) fanOutEstate(targets []string, from, to time.Time, span time.Duration) ([]estateTenantSummary, bool) {
	out := make([]estateTenantSummary, len(targets))
	for i, t := range targets {
		out[i] = estateTenantSummary{Tenant: t, Status: "unread", UnreadReason: "read did not finish within the estate budget"}
	}
	if len(targets) == 0 {
		return out, false
	}

	type slot struct {
		i int
		v estateTenantSummary
	}
	done := make(chan slot, len(targets))
	sem := make(chan struct{}, estateFanoutConcurrency)
	for i, tenant := range targets {
		go func(i int, tenant string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			done <- slot{i, s.readEstateTenant(tenant, from, to, span)}
		}(i, tenant)
	}

	deadline := time.NewTimer(estateFanoutBudget)
	defer deadline.Stop()
	for got := 0; got < len(targets); got++ {
		select {
		case r := <-done:
			out[r.i] = r.v
		case <-deadline.C:
			slog.Warn("estate summary budget exceeded; the remaining tenants are reported unread",
				"tenants", len(targets), "read", got, "budget", estateFanoutBudget)
			return out, true
		}
	}
	return out, false
}

// readEstateTenant computes one tenant's contribution.
//
// It goes through the SAME read paths the per-tenant endpoints use rather than
// second copies of their queries: s.sqlAlertStats for the alert counts (the
// exact, in-database path /api/alert-stats prefers), centralstore.RangeQuerier
// with a Scope for the alert and decision windows, the decision scan bound and
// ladder key set from decisionstats.go, and the heartbeat registry for fleet
// state. Nothing here knows any SQL — the Layer-3 discipline is unchanged, and
// on Postgres each read still runs inside its tenant's RLS transaction.
//
// ANY read failure makes the whole tenant unread. A partially-read tenant would
// contribute a total that is quietly short, which is the "unread counted as
// zero" defect wearing a smaller number.
func (s *Server) readEstateTenant(tenant string, from, to time.Time, span time.Duration) estateTenantSummary {
	sum := estateTenantSummary{Tenant: tenant, Status: "read"}

	ranger, canRange := s.cfg.Store.(centralstore.RangeQuerier)
	if !canRange {
		sum.Status = "unread"
		sum.UnreadReason = "this store backend cannot bound a read by time, so a windowed " +
			"estate figure cannot be computed from it"
		return sum
	}

	counter, canCount := s.cfg.Store.(centralstore.SeverityCounter)

	// One alert read. It is the technique split when the counts come from SQL
	// (a sample answers a mode), and it is the counts as well when they cannot.
	alertCap := estateTechniqueSample
	if !canCount {
		alertCap = estateAlertScanLimit
	}
	rows, err := ranger.QueryRange(centralstore.Scope{TenantID: tenant, Kind: "alert"}, from, to, alertCap)
	if err != nil {
		return unreadTenant(tenant, "alerts could not be read: "+err.Error())
	}
	sum.TechniqueSampled = len(rows) >= alertCap
	sum.Techniques = map[string]int{}
	scanned := newSeverityCounts()
	for _, row := range rows {
		a := row.Record.GetAlert()
		if a == nil {
			continue
		}
		scanned.add(a.GetSeverity())
		if id := strings.TrimSpace(a.GetMitreId()); id != "" {
			sum.Techniques[id]++
		} else {
			sum.AlertsWithoutTechnique++
		}
	}

	if canCount {
		stats, err := s.sqlAlertStats(counter, tenant, from, to, span, 1)
		if err != nil {
			return unreadTenant(tenant, "alert counts could not be read: "+err.Error())
		}
		sum.Alerts = stats.Total
		sum.AlertsBySeverity = map[string]int(stats.Counts)
		// alertStats.Truncated means "this is a floor" — an unfinished severity
		// backfill on the SQL path. Carried through under its plainer name
		// rather than dropped, so an estate total inherits the caveat its parts
		// carry instead of laundering it.
		sum.AlertsExact = !stats.Truncated
	} else {
		sum.AlertsBySeverity = map[string]int(scanned)
		for _, n := range scanned {
			sum.Alerts += n
		}
		sum.AlertsExact = len(rows) < alertCap
	}

	drows, err := ranger.QueryRange(centralstore.Scope{TenantID: tenant, Kind: "decision"}, from, to, decisionScanLimit)
	if err != nil {
		return unreadTenant(tenant, "decisions could not be read: "+err.Error())
	}
	sum.DecisionsByAction = newDecisionActions()
	for _, row := range drows {
		d := row.Record.GetDecision()
		if d == nil {
			continue
		}
		at := row.At
		if d.GetOccurredAt() != nil {
			at = d.GetOccurredAt().AsTime()
		}
		if at.Before(from) || !at.Before(to) {
			continue // selected by ingest time, classified by occurrence — see decisionstats.go
		}
		sum.Decisions++
		if a := d.GetAction(); a != "" {
			sum.DecisionsByAction[a]++
		}
	}

	// Fleet state needs no store read: it is the heartbeat snapshot the Fleet
	// and Choke views already render, so this cannot disagree with them.
	for _, rec := range s.registry.ListTenant(tenant) {
		sum.Agents++
		if time.Since(rec.LastSeen) <= agentFreshWindow {
			sum.AgentsFresh++
		}
		sum.DroppedRecords += rec.DroppedRecords
		for _, c := range rec.Chokes {
			switch strings.ToLower(strings.TrimSpace(c.GetState())) {
			case "sever", "severed":
				sum.Severed++
			default:
				if releasableState(c.GetState()) {
					sum.Contained++
				}
			}
		}
	}

	sum.WeightedAlertsPerHour = weightedAlertRate(sum.AlertsBySeverity, span)
	sum.Posture = estateRiskScore(sum.WeightedAlertsPerHour)
	return sum
}

func unreadTenant(tenant, reason string) estateTenantSummary {
	slog.Warn("estate summary: tenant unread", "tenant", tenant, "reason", reason)
	return estateTenantSummary{Tenant: tenant, Status: "unread", UnreadReason: reason}
}

// weightedAlertRate is severity-weighted alerts per hour — the console's
// weighting (critical x8, high x3, medium x1), so the two agree on the input as
// well as the curve.
func weightedAlertRate(bySeverity map[string]int, span time.Duration) float64 {
	if span <= 0 {
		return 0
	}
	weighted := float64(bySeverity["critical"]*estateWeightCritical +
		bySeverity["high"]*estateWeightHigh + bySeverity["medium"]*estateWeightMedium)
	if weighted <= 0 {
		return 0
	}
	return weighted / span.Hours()
}

// estateRiskScore maps a weighted rate onto the 0-100 dial with the same soft
// knee the console uses (r / (r + k)). Asymptotic rather than clamped: a hard
// clamp is why the old gauge read 100/100 for every busy tenant, and on an
// estate view that would make every bad customer look equally bad and the worst
// one unfindable.
func estateRiskScore(perHour float64) int {
	if perHour <= 0 || math.IsNaN(perHour) || math.IsInf(perHour, 0) {
		return 0
	}
	return int(math.Round(100 * perHour / (perHour + estateRiskHalfScalePerHour)))
}

// foldEstate turns the per-tenant parts into the estate totals. It is a pure
// fold over exactly the rows the response publishes, which is what makes every
// total decomposable by construction rather than by convention.
func foldEstate(tenants []estateTenantSummary, from, to time.Time, windowMin int) estateSummary {
	out := estateSummary{
		From: from, To: to, WindowMin: windowMin,
		TenantsTotal: len(tenants),
		Totals: estateTotals{
			AlertsBySeverity:  newSeverityCounts(),
			DecisionsByAction: newDecisionActions(),
			AlertsExact:       true,
		},
		Posture: estatePosture{
			Direction:        "higher is worse",
			ConcernThreshold: estateConcernScore,
			Scale: "every tenant scored against the same fixed half-scale of 200 weighted " +
				"alerts/hour (critical x8, high x3, medium x1), so the scores are comparable " +
				"between customers. A tenant's own dashboard dial rescales to that tenant's " +
				"baseline and will differ.",
			Note: "the worst tenant's score, never an average: a mean hides one customer on " +
				"fire behind nine quiet ones.",
		},
		Top: estateTechnique{ByTenant: map[string]int{}},
	}

	techniques := map[string]int{}
	byTenant := map[string]map[string]int{}
	for _, t := range tenants {
		if t.Status != "read" {
			out.TenantsUnread++
			out.Posture.TenantsUnscored++
			continue
		}
		out.TenantsRead++
		out.Totals.Alerts += t.Alerts
		for sev, n := range t.AlertsBySeverity {
			out.Totals.AlertsBySeverity.addN(sev, n)
		}
		if !t.AlertsExact {
			out.Totals.AlertsExact = false
		}
		out.Totals.Decisions += t.Decisions
		for act, n := range t.DecisionsByAction {
			out.Totals.DecisionsByAction[act] += n
		}
		out.Totals.Contained += t.Contained
		out.Totals.Severed += t.Severed
		out.Totals.Agents += t.Agents
		out.Totals.AgentsFresh += t.AgentsFresh
		out.Totals.DroppedRecords += t.DroppedRecords

		if t.Posture > out.Posture.WorstScore || out.Posture.WorstTenant == "" {
			out.Posture.WorstScore = t.Posture
			out.Posture.WorstTenant = t.Tenant
		}
		if t.Posture >= estateConcernScore {
			out.Posture.TenantsAtOrAboveConcern++
		} else {
			out.Posture.TenantsBelowConcern++
		}

		if t.TechniqueSampled {
			out.Top.Sampled = true
		}
		out.Top.AlertsWithoutTechnique += t.AlertsWithoutTechnique
		for id, n := range t.Techniques {
			techniques[id] += n
			if byTenant[id] == nil {
				byTenant[id] = map[string]int{}
			}
			byTenant[id][t.Tenant] += n
		}
	}

	// A TOTAL THAT IS MISSING A TENANT IS NOT AN EXACT TOTAL, whatever the
	// tenants it did read could promise. Without this the estate could inherit
	// "exact" from two customers while a third went unread — the same defect as
	// counting that third as zero, moved into the caveat.
	if out.TenantsUnread > 0 {
		out.Totals.AlertsExact = false
	}
	if out.TenantsRead == 0 {
		out.Posture.Note = "no tenant could be read, so the estate has no posture — this is not a calm estate, " +
			"it is an unmeasured one"
	}

	// The MODE across tenants. Ties break on the technique id so the same data
	// always names the same technique — a tile that reshuffles between polls
	// reads as movement that did not happen.
	best, bestN := "", 0
	for id, n := range techniques {
		if n > bestN || (n == bestN && id < best) {
			best, bestN = id, n
		}
	}
	if best != "" {
		out.Top.Technique = best
		out.Top.Count = bestN
		out.Top.ByTenant = byTenant[best]
	} else if out.TenantsRead > 0 {
		out.Top.Note = "no alert in this window carried a MITRE technique"
	}
	if out.TenantsUnread > 0 {
		out.Top.Note = strings.TrimSpace(out.Top.Note + " " +
			strconv.Itoa(out.TenantsUnread) + " tenant(s) could not be read and contribute nothing to this split.")
	}

	// Worst first, unread last: an unread tenant is unknown, not calm, and
	// sorting it among the quiet ones is how an outage looks like a good night.
	out.Tenants = append(out.Tenants, tenants...)
	sort.SliceStable(out.Tenants, func(i, j int) bool {
		a, b := out.Tenants[i], out.Tenants[j]
		if (a.Status == "read") != (b.Status == "read") {
			return a.Status == "read"
		}
		if a.Posture != b.Posture {
			return a.Posture > b.Posture
		}
		return a.Tenant < b.Tenant
	})
	return out
}
