package controlplane

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Verifying the tenant's decision chain centrally.
//
// # Why this could not be done before
//
// The control plane received decisions without their actor, and actor is
// chain-hashed. Re-canonicalising without it produced a different hash for
// every operator-initiated decision, so central verification would have
// reported the chain broken on exactly the rows an audit cares about. The
// endpoint honestly answered "not supported" instead. The actor now travels
// with the record, so the recomputation matches.
//
// # Three outcomes, not two
//
// Verifying centrally has a failure mode the agent does not: the control plane
// may simply not have every row. Decisions were not uplinked at all until
// recently, an agent's backlog can be evicted under its cap, and one that was
// offline long enough loses the tail. Every one of those leaves a gap.
//
// A gap breaks LINKAGE while every row still hashes correctly. Reporting that
// as "chain broken" would be a false accusation — and this codebase has
// already learned what a false tamper alarm costs. So the two are separated:
//
//	verified   every row hashes, and each links to the one before it
//	incomplete every row hashes, but records are missing between them
//	broken     a row's content does not match its own hash — tampering
//
// Only the third is an accusation, and it is the only one that names a row.
//
// # Per agent
//
// Each agent keeps its own chain, so linkage is only meaningful within one
// agent's sequence. Walking a tenant's decisions as a single list would
// interleave several chains and report breakage everywhere.
type chainVerdict struct {
	Agent string `json:"agent"`
	// Verified counts rows whose content matched their stored hash.
	Verified int `json:"verified"`
	// Gaps counts places where a row hashes correctly but does not link to
	// the row before it — a missing record, not a modified one.
	Gaps int `json:"gaps"`
	// BadAt names the first row whose CONTENT did not match its hash.
	BadAt  int64  `json:"bad_at,omitempty"`
	Status string `json:"status"` // verified | incomplete | broken
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "decision"}, verifyChainScanLimit)
	if err != nil {
		storeQueryFailed(w, r, tenant, "decision", verifyChainScanLimit, err)
		return
	}

	byAgent := map[string][]*store.Decision{}
	for _, row := range rows {
		d := row.Record.GetDecision()
		if d == nil {
			continue
		}
		byAgent[row.AgentID] = append(byAgent[row.AgentID], decisionFromWire(d))
	}

	verdicts := make([]chainVerdict, 0, len(byAgent))
	total, broken, incomplete := 0, 0, 0
	for agent, ds := range byAgent {
		v := verifyAgentChain(agent, ds)
		total += v.Verified
		switch v.Status {
		case "broken":
			broken++
		case "incomplete":
			incomplete++
		}
		verdicts = append(verdicts, v)
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].Agent < verdicts[j].Agent })

	writeJSON(w, 200, map[string]any{
		"supported": true,
		// ok means NOTHING was tampered with. An incomplete chain is not ok in
		// the sense of "fully attested", but it is not an accusation either,
		// so it is reported separately rather than folded into a single bool.
		"ok":         broken == 0,
		"total":      total,
		"agents":     verdicts,
		"broken":     broken,
		"incomplete": incomplete,
		"scanned":    len(rows),
		"detail": "each agent keeps its own chain, so linkage is checked within one agent's " +
			"records. A gap means this server is missing records the agent holds — decisions were " +
			"not uplinked before 2026-08-24, and an agent's backlog can be evicted under its cap. " +
			"Only 'broken' means a record's content does not match its own hash.",
	})
}

// verifyAgentChain walks one agent's records oldest-first.
func verifyAgentChain(agent string, ds []*store.Decision) chainVerdict {
	sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
	v := chainVerdict{Agent: agent, Status: "verified"}
	prev := ""
	first := true
	for _, d := range ds {
		// CONTENT first. A row that does not hash to its own stored value has
		// been altered, and that is the only finding worth accusing anyone of.
		if !store.VerifyRow(d) {
			v.BadAt = d.ID
			v.Status = "broken"
			return v
		}
		v.Verified++
		// LINKAGE second, and only against a row we actually have. The first
		// row this server holds is almost never the first the agent wrote, so
		// its prev_hash legitimately points at a record we never received.
		if !first && d.PrevHash != prev {
			v.Gaps++
		}
		first = false
		prev = d.Hash
	}
	if v.Gaps > 0 {
		v.Status = "incomplete"
	}
	return v
}

// verifyChainScanLimit bounds the walk. Verification is a read of the whole
// history by nature, so it is capped like every other operator read rather
// than allowed to scan a multi-gigabyte table on request — the shape that took
// this control plane down once already.
const verifyChainScanLimit = 5000

// decisionFromWire rebuilds the record the agent hashed.
//
// Every field the canonical form covers must be carried across. A field missed
// here does not fail loudly — it produces a different hash, and the endpoint
// accuses an untouched record of being tampered with. The round-trip test in
// verifychain_test.go is what stops that: it hashes a record locally, sends it
// through the same conversion the uplink and this function perform, and
// requires the hash to still verify.
func decisionFromWire(d *ebpfsocv1.Decision) *store.Decision {
	return &store.Decision{
		ID:                d.GetId(),
		Timestamp:         d.GetOccurredAt().AsTime(),
		ExecID:            d.GetExecId(),
		PID:               d.GetPid(),
		Binary:            d.GetBinary(),
		Action:            d.GetAction(),
		FromState:         d.GetFromState(),
		ToState:           d.GetToState(),
		Score:             int(d.GetScore()),
		Reason:            d.GetReason(),
		DryRun:            d.GetDryRun(),
		Backend:           d.GetBackend(),
		Outcome:           d.GetOutcome(),
		OriginKind:        d.GetOriginKind(),
		OriginIP:          d.GetOriginIp(),
		OriginPort:        uint16(d.GetOriginPort()),
		OriginUser:        d.GetOriginUser(),
		OriginFingerprint: d.GetOriginFingerprint(),
		DeviceMAC:         d.GetDeviceMac(),
		DeviceID:          d.GetDeviceId(),
		Actor:             d.GetActor(),
		PrevHash:          d.GetPrevHash(),
		Hash:              d.GetHash(),
	}
}

// handleChainRepair asks an agent to re-send decisions so a gap can close.
//
// Deliberately operator-initiated rather than automatic. A replay costs the
// agent's outbound buffer and the control plane's ingest, and a gap is usually
// explained — decisions were not uplinked before 2026-08-24, and an agent that
// was offline past its cap legitimately lost records. Repairing on a schedule
// would have every agent replaying its history forever chasing gaps that
// nothing can close.
func (s *Server) handleChainRepair(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespondMethods(w, r, http.MethodPost)
	if !ok {
		return
	}
	var b struct {
		Agent  string `json:"agent"`
		FromID int64  `json:"from_id"`
		Limit  uint32 `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Agent) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "agent is required; from_id 0 means everything the agent still holds"})
		return
	}
	if b.Limit == 0 || b.Limit > chainRepairMaxBatch {
		b.Limit = chainRepairMaxBatch
	}
	if !s.agentInTenant(tenant, b.Agent) {
		// Refused rather than dispatched: an agent id from a request body is
		// attacker-controlled, and dispatching to one outside the caller's
		// tenant would make this endpoint a cross-tenant command channel.
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "no such agent in this tenant"})
		return
	}
	cmd := &ebpfsocv1.Command{
		Actor: s.subject(r),
		Action: &ebpfsocv1.Command_ResendDecisions{ResendDecisions: &ebpfsocv1.ResendDecisions{
			FromId: b.FromID, Limit: b.Limit}},
	}
	id := s.dispatcher.Enqueue(b.Agent, cmd)
	ackOut, got := s.awaitAck(id)
	writeJSON(w, 200, map[string]any{
		"ok":     got && ackOut.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED,
		"agent":  b.Agent,
		"detail": ackOut.GetDetail(),
		// Replayed records still have to travel and be ingested, so the chain
		// does not close the instant this returns. Re-run verification rather
		// than trusting this response for the outcome.
		"note": "re-queued on the agent; re-run /api/verify-chain once the records have arrived",
	})
}

// chainRepairMaxBatch bounds one replay so a repair cannot flood an agent's
// outbound buffer and evict the live telemetry queued behind it.
const chainRepairMaxBatch = 1000

// agentInTenant reports whether the named agent belongs to the caller's tenant.
func (s *Server) agentInTenant(tenant, agent string) bool {
	for _, rec := range s.registry.ListTenant(tenant) {
		if rec.AgentID == agent {
			return true
		}
	}
	return false
}

// awaitAck waits briefly for one command ack.
func (s *Server) awaitAck(id string) (*ebpfsocv1.CommandAck, bool) {
	deadline := time.Now().Add(ackTimeout)
	for time.Now().Before(deadline) {
		if a, ok := s.dispatcher.Ack(id); ok {
			return a, true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, false
}
