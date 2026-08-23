package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Detection-policy authoring on the SINGLE-TENANT engine.
//
// # Why this exists separately from the control plane's version
//
// The multi-tenant control plane pushes a policy by signing a command and
// dispatching it to every agent it knows about; each agent applies it locally
// and acks. That plane's honesty problem is convergence — it cannot promise a
// fleet is updated, only that N agents acked.
//
// This engine runs ON the monitored host. There is no fleet, no network hop and
// nothing to sign across: the console session is already authenticated on the
// machine whose kernel is about to change, which is the same trust boundary as
// an SSH login to that box. So this applies DIRECTLY, and its honesty problem
// is a different one — see the response note below.
//
// Before this existed, a single-host customer had no way to write a detection
// through the platform at all. The console showed them exactly which policies
// the kernel had, named the gaps, and then offered nothing to do about it
// except log into the machine — which is the workflow the product exists to
// replace.
//
// # What it shares with the control plane, deliberately
//
// The effector is internal/policyapply, the same code the agent runs, so
// delete-then-add, explicit mode setting, and the live-versus-durable
// distinction cannot drift between the two planes. The safety rules below
// (enforce refused, a reason required, removal supported) are re-stated here
// rather than inherited, because they are policy decisions belonging to the
// surface, and a reader of this file should be able to see them.

// sensorsFor supplies the Tetragon client. It is a hook rather than a field so
// main can install it after dialling, and so a deployment with no Tetragon
// (the fake/dev mode) simply reports the capability as absent instead of
// panicking on a nil client.
var (
	sensorsMu  sync.RWMutex
	sensors    policyapply.Client
	durableDir = policyapply.DefaultDurableDir
)

// SetPolicyApplier installs the Tetragon connection the push handler applies
// through. Called from main once the gRPC client is up.
//
// Until it is called, /api/policies/push answers 503 and whoami reports the
// capability as absent, so the console hides the authoring surface rather than
// offering a button that fails.
func SetPolicyApplier(c policyapply.Client, dir string) {
	sensorsMu.Lock()
	defer sensorsMu.Unlock()
	sensors = c
	if dir != "" {
		durableDir = dir
	}
}

// CanPushPolicy reports whether this deployment can change detection policy.
// The console gates its authoring surface on this.
func CanPushPolicy() bool {
	sensorsMu.RLock()
	defer sensorsMu.RUnlock()
	return sensors != nil
}

// currentDurableDir is where a pushed policy's body lives on disk. Read by the
// policy list so an operator's own detection is not shown as body-less.
func currentDurableDir() string {
	sensorsMu.RLock()
	defer sensorsMu.RUnlock()
	return durableDir
}

func currentApplier() (policyapply.Client, string) {
	sensorsMu.RLock()
	defer sensorsMu.RUnlock()
	return sensors, durableDir
}

type enginePolicyPushRequest struct {
	Policies []struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
		Mode string `json:"mode"`
	} `json:"policies"`
	Remove []string `json:"remove"`
	Reason string   `json:"reason"`
}

// maxPolicyBytes bounds one pushed document. The four shipped TracingPolicies
// measure 1.1-9.8 KB, so 256 KB is two orders of magnitude of headroom and
// still small enough that a hostile body cannot wedge the handler.
const maxPolicyBytes = 256 << 10

func (s *Server) handlePolicyPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// serverHostname is resolved lazily and, until tonight, only ever by
	// HandleWhoami — so this response reported host:"" for any caller that had
	// not loaded the console first. The browser always does, which is precisely
	// why the empty field would have survived a UI check and surfaced later as
	// a blank hostname on an audit record. sync.Once-guarded, so this is free.
	resolveServerIdentity()
	client, dir := currentApplier()
	if client == nil {
		// Not an error the operator caused. Say which capability is missing.
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "this engine has no Tetragon connection, so it cannot change detection policy"})
		return
	}

	var b enginePolicyPushRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&b); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}
	// A reason is REQUIRED, exactly as it is on the control plane and for a
	// disruptive containment. Changing what the kernel watches on a production
	// host is a change an auditor will ask about.
	if strings.TrimSpace(b.Reason) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error": "a reason is required to change detection policy on this host"})
		return
	}
	if len(b.Policies) == 0 && len(b.Remove) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "nothing to apply or remove"})
		return
	}

	docs := make([]policyapply.Doc, 0, len(b.Policies))
	for _, p := range b.Policies {
		name := strings.TrimSpace(p.Name)
		if name == "" || strings.TrimSpace(p.YAML) == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{
				"error": "each policy needs a name and a body"})
			return
		}
		if len(p.YAML) > maxPolicyBytes {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("policy %q is %d bytes, over the %d-byte limit", name, len(p.YAML), maxPolicyBytes)})
			return
		}
		// "enforce" is refused here, not merely warned about.
		//
		// An enforcing TracingPolicy kills independently of the choke ladder:
		// no audit row, no reversal, no kill-switch (threat-model EN-3). This
		// project has already lost a host and three hosts' package state to
		// exactly that. Arming one should not be reachable by pasting YAML into
		// a console field.
		mode := strings.TrimSpace(p.Mode)
		switch mode {
		case "", "monitor":
			mode = "monitor"
		case "enforce":
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{
				"error": "enforce mode cannot be pushed from the console: an enforcing TracingPolicy kills " +
					"with no audit row, no reversal and no kill-switch. Load it deliberately on the host."})
			return
		default:
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("unknown mode %q (want monitor)", mode)})
			return
		}
		docs = append(docs, policyapply.Doc{Name: name, YAML: p.YAML, Mode: mode})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	outcome := policyapply.Apply(ctx, client, dir, docs, b.Remove)

	// AUDIT. One hash-chained row per policy, before anything is reported.
	//
	// Changing what the kernel watches is the most consequential action this
	// console offers and it wrote no record at all, while jailing a single
	// process wrote one. An operator could narrow a production host's field of
	// view and leave nothing behind for /api/verify-chain to check — which is
	// precisely the trace an incident review would go looking for.
	//
	// The body is HASHED rather than inlined: a 10 KB YAML in every audit row
	// would bloat the chain, and the hash is what actually answers the question
	// an auditor asks — "is this the same policy that was approved?". The signed
	// command channel hashes policy bodies for the same reason.
	s.auditPolicyChange(docs, b.Remove, strings.TrimSpace(b.Reason), outcome)

	// The single-host equivalent of the control plane's "acked, not converged".
	//
	// Here the change either reached this kernel or it did not, and the applier
	// says which per policy — so unlike the fleet case there is no honest
	// uncertainty about reach. What there IS uncertainty about is DURABILITY: a
	// policy can be live in the kernel and still absent from the load
	// directory, in which case it disappears at the next Tetragon restart. That
	// is the fact this response must not round off, so it is counted
	// separately and never folded into the success total.
	applied, notDurable, failed := 0, 0, 0
	for _, v := range outcome {
		switch {
		case v == policyapply.OK || v == "removed":
			applied++
		case strings.HasPrefix(v, policyapply.NotDurable):
			notDurable++
		default:
			failed++
		}
	}
	resp := map[string]any{
		"ok":      failed == 0,
		"host":    serverHostname,
		"applied": applied,
		"failed":  failed,
		"outcome": outcome,
		"reason":  strings.TrimSpace(b.Reason),
		"scope":   "this host only",
		"durable": notDurable == 0,
	}
	if notDurable > 0 {
		resp["durability_note"] = fmt.Sprintf(
			"%d policy/policies are LIVE but were not written to %s, so they are lost when Tetragon next "+
				"restarts. That directory is bind-mounted by the deploy; if it is missing, redeploy this host.",
			notDurable, dir)
	}
	writeJSONStatus(w, http.StatusOK, resp)
}

// auditPolicyChange writes one tamper-evident row per policy touched.
//
// The outcome recorded is the applier's own verbatim string, including
// "live, but NOT durable". An audit that flattened that to "ok" would assert
// the host is watching something it will stop watching at the next restart.
func (s *Server) auditPolicyChange(docs []policyapply.Doc, remove []string, reason string, outcome map[string]string) {
	if s.store == nil {
		return
	}
	actor := s.auth.Username()
	write := func(name, action, toState string, body string) {
		res := outcome[name]
		if res == "" {
			res = "unknown"
		}
		detail := reason
		if body != "" {
			sum := sha256.Sum256([]byte(body))
			detail = fmt.Sprintf("%s (sha256=%x)", reason, sum[:8])
		}
		rec := &store.Decision{
			Timestamp: time.Now().UTC(),
			// A synthetic key: this action is about a POLICY, not a process,
			// and "*" is already the convention for a non-per-process decision
			// (see the gateway's quarantine thaw).
			ExecID:    "policy:" + name,
			Action:    action,
			FromState: "-",
			ToState:   toState,
			Reason:    detail,
			Backend:   "tetragon",
			Outcome:   res,
			Actor:     actor,
		}
		if _, err := s.store.InsertDecision(rec); err != nil {
			log.Printf("[policy] audit insert for %s: %v", name, err)
		}
		// Same bus the gateway uses, so the decisions feed shows it live.
		s.Broadcast("decision", rec)
	}
	for _, d := range docs {
		write(d.Name, "apply-policy", d.Mode, d.YAML)
	}
	for _, name := range remove {
		write(name, "remove-policy", "absent", "")
	}
}
