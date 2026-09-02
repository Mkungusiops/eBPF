package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The settings surface: what an operator can tune after deployment.
//
// # The rule that decides what belongs here
//
// A setting that can only make the platform act LESS is safe to expose. One
// that can make it act MORE needs validation and, where it changes the meaning
// of stored data, versioning first.
//
// That is why suppressions are here and scoring WEIGHTS are not. A bad
// suppression costs a missed detection — bounded, and it surfaces as a
// coverage gap on the panel next door. A bad weight could push every process
// past the sever threshold, which is the same failure class as the
// unvalidated threshold ladder that could sever an entire fleet from one
// malformed request.
//
// Weights additionally change what STORED alerts mean. Nothing in this build
// records which ruleset produced a score, so an alert of 24 from March and one
// from April would silently be incomparable. The prerequisite is a
// ruleset_version stamped on every alert and decision; until that exists a
// weights control would quietly corrupt the record it is meant to explain.
//
// # Deliberately absent
//
// Anything the deploy rewrites wholesale — engine.yaml, agent.yaml,
// controlplane.env are whole-file heredocs on every run, so a console that
// edited them would be lying by the next deploy. And secrets: a console that
// displays or edits an API key is a new exposure, not a feature.

// SuppressionReloader is how a settings change reaches the running scorer
// without a restart. Satisfied by *eventpipe.Pipeline.
type SuppressionReloader interface {
	SetSuppressions([]store.Suppression)
	SuppressionHits() map[int64]int64
}

var suppressionSink SuppressionReloader

// SetSuppressionReloader wires the live pipeline in, and pushes the stored set
// into it once at startup. Without this a stored suppression would sit in the
// database doing nothing — a setting that saves and has no effect, which is
// the exact defect this codebase keeps producing.
func SetSuppressionReloader(r SuppressionReloader, st *store.Store) {
	suppressionSink = r
	if r == nil || st == nil {
		return
	}
	if rules, err := st.Suppressions(); err == nil {
		r.SetSuppressions(rules)
	}
}

func (s *Server) handleSettingsSuppressions(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "no store on this deployment"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listSuppressions(w)
	case http.MethodPost:
		s.addSuppression(w, r)
	case http.MethodDelete:
		s.deleteSuppression(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listSuppressions(w http.ResponseWriter) {
	rules, err := s.store.Suppressions()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// Fire counts come from the LIVE pipeline, not the database: a rule that
	// has never matched is either a typo or obsolete, and the operator cannot
	// tell those apart from the rule text. Absent when no pipeline is wired —
	// reported as unknown rather than as zero, which would read as "this rule
	// does nothing".
	hits := map[int64]int64{}
	known := false
	if suppressionSink != nil {
		if h := suppressionSink.SuppressionHits(); h != nil {
			hits, known = h, true
		}
	}
	out := make([]map[string]any, 0, len(rules))
	for _, x := range rules {
		row := map[string]any{
			"id": x.ID, "binary": x.Binary, "policy": x.Policy, "parent": x.Parent,
			"reason": x.Reason, "actor": x.Actor, "created_at": x.CreatedAt,
		}
		if known {
			row["hits"] = hits[x.ID]
		}
		out = append(out, row)
	}
	// Candidates: the binaries actually producing this host's findings.
	//
	// A settings page that opens on an empty text field asking for an absolute
	// path is unusable by the person who needs it. An analyst arrives knowing
	// something is noisy, not knowing which path to type. The platform already
	// recorded the answer, so it should offer it.
	// The error is REPORTED, not swallowed. Nilling it out on failure made a
	// broken query render as "nothing noisy on this host" — an absent answer
	// presented as an empty one, on the surface whose whole job is to tell an
	// operator what to look at.
	candidates, cerr := s.store.SuppressionCandidates(time.Now().Add(-7*24*time.Hour), 24)
	candidateErr := ""
	if cerr != nil {
		candidates, candidateErr = nil, cerr.Error()
	}
	candidates = withoutAlreadyHandled(candidates, 8)

	writeJSONStatus(w, 200, map[string]any{
		"suppressions":    out,
		"candidates":      candidates,
		"candidate_error": candidateErr,
		"window":          "7d",
		"hits_known":      known,
		"effect": "a suppression withholds the SCORE only. The event is still recorded, the chain is still " +
			"in the process tree, and the binary can still be contained by hand — the score is what drives " +
			"automatic action, and that is the only thing being stopped.",
	})
}

func (s *Server) addSuppression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Binary string `json:"binary"`
		Policy string `json:"policy"`
		Parent string `json:"parent"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}
	resolveServerIdentity()
	sup := &store.Suppression{
		Binary: strings.TrimSpace(body.Binary), Policy: strings.TrimSpace(body.Policy),
		Parent: strings.TrimSpace(body.Parent), Reason: strings.TrimSpace(body.Reason),
		Actor: s.auth.Username(), CreatedAt: time.Now().UTC(),
	}
	if _, err := s.store.AddSuppression(sup); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.auditSuppression("suppression-add", sup)
	s.reloadSuppressions()
	writeJSONStatus(w, 200, map[string]any{
		"ok": true, "suppression": sup,
		"note": "in effect now — no restart needed. It withholds the score for this pattern and nothing else.",
	})
}

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
		return
	}
	// Read it first so the audit row can name what was removed. A row saying
	// only "suppression 7 deleted" is useless six months later.
	var removed store.Suppression
	if all, err := s.store.Suppressions(); err == nil {
		for _, x := range all {
			if x.ID == id {
				removed = x
			}
		}
	}
	gone, err := s.store.DeleteSuppression(id)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if !gone {
		// Not an error, but not a success either: saying "removed" about a
		// rule that was never there is the small lie that makes an operator
		// stop trusting the surface.
		writeJSONStatus(w, 404, map[string]any{"error": "no suppression with that id"})
		return
	}
	resolveServerIdentity()
	removed.Actor = s.auth.Username()
	s.auditSuppression("suppression-remove", &removed)
	s.reloadSuppressions()
	writeJSONStatus(w, 200, map[string]any{"ok": true, "removed": id,
		"note": "detection for this pattern resumes immediately."})
}

// reloadSuppressions pushes the stored set into the running scorer.
//
// Without this the setting would persist and do nothing until a restart — a
// settings page whose changes are invisible until someone reboots the host is
// worse than no settings page, because it looks like it worked.
func (s *Server) reloadSuppressions() {
	if suppressionSink == nil || s.store == nil {
		return
	}
	if rules, err := s.store.Suppressions(); err == nil {
		suppressionSink.SetSuppressions(rules)
	}
}

// auditSuppression records the change in the hash-chained decision log.
//
// Narrowing what the platform detects is exactly the kind of act an incident
// review asks about, and it is a change an attacker with console access would
// want to make quietly. It belongs in the same tamper-evident chain as a
// containment decision, not in a log line.
func (s *Server) auditSuppression(action string, sup *store.Suppression) {
	if s.store == nil || sup == nil {
		return
	}
	target := sup.Binary
	if sup.Policy != "" {
		target += " [" + sup.Policy + "]"
	}
	rec := &store.Decision{
		Timestamp: time.Now().UTC(),
		ExecID:    "settings:suppression",
		Action:    action,
		FromState: "-",
		ToState:   target,
		Reason:    sup.Reason,
		Backend:   "settings",
		Outcome:   "ok",
		Actor:     sup.Actor,
	}
	if _, err := s.store.InsertDecision(rec); err == nil {
		s.Broadcast("decision", rec)
	}
}

// withoutAlreadyHandled drops candidates whose score the engine ALREADY
// withholds, and trims to the top n.
//
// Measured on the live estate, the raw volume ranking was:
//
//	/usr/lib/openssh/sshd-session   64,612
//	/usr/bin/sudo                   38,301
//	/usr/sbin/unix_chkpwd           11,726
//
// — the auth stack, every one of which score.IsAuthStackCredentialRead and
// score.IsRoutinePrivilegeTransition already suppress. Offering them is worse
// than useless: the operator gains nothing (the score is withheld either way)
// and is invited to write a broad rule on sshd, which reads like disabling
// detection on the login path even though it changes nothing.
//
// The rule is simply: if the scorer already ignores it, do not ask the operator
// about it. Same predicates the scorer uses, so the two cannot disagree.
func withoutAlreadyHandled(in []store.SuppressionCandidate, n int) []store.SuppressionCandidate {
	out := make([]store.SuppressionCandidate, 0, len(in))
	for _, c := range in {
		// Parent is unknown in an aggregate, and the predicate matches on the
		// READER alone for exactly the cases that matter here — sshd-session
		// and unix_chkpwd read the files themselves, with no helper pair.
		if score.IsAuthStackCredentialRead(c.Binary, "", c.Policy) ||
			score.IsRoutinePrivilegeTransition(c.Binary, c.Policy) {
			continue
		}
		if !suppressablePath(c.Binary) {
			continue
		}
		out = append(out, c)
		if len(out) == n {
			break
		}
	}
	return out
}

// suppressablePath rejects paths that could never work as an exact-match rule.
//
// Two turn up on a real host and both are artefacts rather than programs:
//
//	/proc/self/fd/9                             an fd re-exec — the number is
//	                                            per-process and never repeats
//	/usr/lib/systemd/systemd-logind (deleted)   the kernel's suffix for a
//	                                            binary replaced under a running
//	                                            process, e.g. after an upgrade
//
// Matching is exact, so a rule on either would fire once and then never again
// — the worst outcome for a suppression, because it looks like it worked. The
// validator already refuses a non-absolute path for the same reason; this
// holds what the platform SUGGESTS to the same standard, rather than letting
// the page propose something its own validator would sensibly reject.
func suppressablePath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.HasSuffix(p, " (deleted)") {
		return false
	}
	if strings.HasPrefix(p, "/proc/") {
		return false
	}
	return true
}

// Guardrails: the protected lists.
//
// This is threat-model EN-1 made operable. Both underlying setters are
// deliberately asymmetric and the console has to say so rather than present a
// symmetrical-looking form:
//
//   - Binaries: Gateway.SetSystemCritical REPLACES the additions but always
//     unions DefaultSystemCriticalBinaries back in, so the login path can be
//     widened and cannot be removed.
//   - MACs: DeviceGateway.SetProtectedMACs is ADD-ONLY. Removing the uplink
//     from the allow-list would be the one edit that can blackhole the path
//     you would use to undo it, so it is a local decision made with a shell.
//
// The read is the live gateway state, not an echo of the last write.
func (s *Server) handleSettingsProtected(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.readProtected(w)
	case http.MethodPut, http.MethodPost:
		s.writeProtected(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) readProtected(w http.ResponseWriter) {
	floor := append([]string(nil), choke.DefaultSystemCriticalBinaries()...)
	sort.Strings(floor)
	out := map[string]any{
		"floor":             floor,
		"binaries":          []string{},
		"macs":              []string{},
		"process_plane":     s.gateway != nil,
		"device_plane":      s.deviceGW != nil,
		"macs_are_add_only": true,
		// This read is the LIVE gateway, not an echo of the last write. The
		// control plane's identical endpoint can only report desired state,
		// and flags itself accordingly; the console renders the difference.
		"desired_only": false,
	}
	if s.gateway != nil {
		// Additions only. SystemCriticalList returns floor ∪ additions, and
		// showing the union in the editable field would invite an operator to
		// "remove" a floor entry that comes straight back on the next apply —
		// a control that appears not to work. The floor is rendered
		// separately, as the fixed thing it is, and both planes therefore mean
		// the same thing by "binaries".
		out["binaries"] = withoutFloor(s.gateway.SystemCriticalList(), floor)
	}
	if s.deviceGW != nil {
		if m := s.deviceGW.ProtectedMACs(); m != nil {
			out["macs"] = m
		}
	}
	writeJSONStatus(w, 200, out)
}

// withoutFloor subtracts the compiled-in minimum from an effective list.
func withoutFloor(effective, floor []string) []string {
	fixed := make(map[string]bool, len(floor))
	for _, f := range floor {
		fixed[f] = true
	}
	out := []string{}
	for _, b := range effective {
		if !fixed[b] {
			out = append(out, b)
		}
	}
	return out
}

func (s *Server) writeProtected(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Binaries []string `json:"binaries"`
		MACs     []string `json:"macs"`
		Reason   string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error": "a reason is required: widening or narrowing what containment refuses to touch is an audited change"})
		return
	}
	if s.gateway == nil && s.deviceGW == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "no choke gateway on this host, so there is nothing to protect from"})
		return
	}

	// Reject paths that cannot match. isSystemCritical is an EXACT string
	// compare against the event's binary field, so a bare name or a relative
	// path silently protects nothing — the same class of quiet no-op that
	// suppressions already reject.
	var bad []string
	for _, b := range body.Binaries {
		if b = strings.TrimSpace(b); b == "" {
			continue
		}
		if !strings.HasPrefix(b, "/") {
			bad = append(bad, b)
		}
	}
	if len(bad) > 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error": "protection is matched on the absolute binary path; these would never match: " + strings.Join(bad, ", ")})
		return
	}

	floor := append([]string(nil), choke.DefaultSystemCriticalBinaries()...)
	sort.Strings(floor)
	out := map[string]any{"ok": true, "floor": floor}
	if s.gateway != nil {
		prev := s.gateway.SystemCriticalList()
		effective := s.gateway.SetSystemCritical(body.Binaries)
		// Additions, not the union — the same thing GET returns and the same
		// thing the control plane returns. Echoing the union here would make
		// one field name mean two things across two verbs on one endpoint,
		// which is how a client ends up rendering sshd as removable.
		out["binaries"] = withoutFloor(effective, floor)
		// The AUDIT keeps the effective lists, because what an incident review
		// needs is what actually took effect, not what was typed.
		s.auditProtected("protect-binaries", strings.Join(prev, " "), strings.Join(effective, " "), reason)
	}
	if s.deviceGW != nil && len(body.MACs) > 0 {
		prev := s.deviceGW.ProtectedMACs()
		added, skipped := s.deviceGW.SetProtectedMACs(body.MACs)
		out["macs"] = s.deviceGW.ProtectedMACs()
		out["added"] = added
		if len(skipped) > 0 {
			// Reported, never swallowed: a MAC the operator believes is
			// protected but which never parsed is the gap that gets a
			// default gateway severed.
			out["skipped"] = skipped
			out["warning"] = fmt.Sprintf("%d address(es) did not parse and are NOT protected: %s",
				len(skipped), strings.Join(skipped, ", "))
		}
		s.auditProtected("protect-macs", strings.Join(prev, " "), strings.Join(added, " "), reason)
	} else if s.deviceGW == nil && len(body.MACs) > 0 {
		out["warning"] = "the device plane is not attached on this host, so the addresses were not applied"
	}
	writeJSONStatus(w, 200, out)
}

// auditProtected records a guardrail change in the same hash-chained ledger as
// a containment decision. Narrowing what the platform refuses to touch is
// precisely the edit an attacker with console access would make before acting,
// and precisely what an incident review asks about afterwards.
func (s *Server) auditProtected(action, from, to, reason string) {
	if s.store == nil {
		return
	}
	rec := &store.Decision{
		Timestamp: time.Now().UTC(),
		ExecID:    "settings:guardrail",
		Action:    action,
		FromState: from,
		ToState:   to,
		Reason:    reason,
		Backend:   "settings",
		Outcome:   "ok",
		Actor:     s.auth.Username(),
	}
	if _, err := s.store.InsertDecision(rec); err == nil {
		s.Broadcast("decision", rec)
	}
}
