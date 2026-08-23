package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// Detection-policy distribution over the SIGNED COMMAND channel.
//
// # Why this channel and not the policy-bundle channel
//
// The bundle channel (PolicyService/GetBundle, internal/fleet) is real code
// that nothing can put a policy into: fleet.Service.Publish has no non-test
// caller, bundles live in an in-memory map a restart forgets, PolicyBundle
// content has no defined format, and internal/policypull is not compiled into
// the shipped agent at all. Finishing it means a content format, a persistence
// layer, a producer and an agent pull loop.
//
// The command channel is the one that already works: the agent dials out (so it
// traverses customer NAT with no inbound rule), every command is Ed25519-signed
// and verified before the agent acts, local guardrails override remote intent,
// and each agent acks individually. SetThresholds and UpdateProtectedList
// already mutate agent CONFIGURATION over it, which is the precedent this
// follows almost line for line.
//
// # What this deliberately does NOT claim
//
// This PUSHES. It does not converge. An agent offline at dispatch does not get
// the policy and will not be retried, so the response reports what each agent
// ACKED and names the ones that did not — it never reports a fleet as updated.
// Convergence needs a persisted desired state and a reconcile loop; until those
// exist, saying "3 of 4 applied, 1 did not respond" is the whole truth and
// "updated" would be a lie. The heartbeat's policy fingerprint is what the
// console uses to show, on the next beat, which hosts actually carry it.
type policyPushRequest struct {
	Policies []struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
		Mode string `json:"mode"`
	} `json:"policies"`
	Remove []string `json:"remove"`
	Reason string   `json:"reason"`
}

// maxPolicyBytes bounds one pushed document. Measured on the estate, the four
// shipped TracingPolicies are 1.1-9.8 KB; 256 KB is two orders of magnitude of
// headroom and still far below the gRPC message limit, so a malformed or
// hostile payload cannot be used to wedge the dispatcher.
const maxPolicyBytes = 256 << 10

func (s *Server) handlePolicyPush(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b policyPushRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}

	// A reason is REQUIRED, exactly as it is for a disruptive containment.
	// Changing what the kernel watches on a production estate is a change an
	// auditor will ask about, and the ack is the only place it gets recorded
	// until the durable command audit exists.
	if strings.TrimSpace(b.Reason) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "a reason is required to change detection policy on a fleet"})
		return
	}
	if len(b.Policies) == 0 && len(b.Remove) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "nothing to apply or remove"})
		return
	}

	docs := make([]*ebpfsocv1.PolicyDoc, 0, len(b.Policies))
	for _, p := range b.Policies {
		name := strings.TrimSpace(p.Name)
		if name == "" || strings.TrimSpace(p.YAML) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "each policy needs a name and a body"})
			return
		}
		if len(p.YAML) > maxPolicyBytes {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("policy %q is %d bytes, over the %d-byte limit", name, len(p.YAML), maxPolicyBytes)})
			return
		}
		// "enforce" is refused here, not merely warned about.
		//
		// An enforcing TracingPolicy kills independently of the choke ladder:
		// no audit row, no reversal, no kill-switch (threat-model EN-3). This
		// project has already lost a host and three hosts' package state to
		// exactly that. Arming one is a deliberate act that should not be
		// reachable by pasting YAML into a console field, so the push path
		// accepts monitor only until there is an approval gate in front of it.
		mode := strings.TrimSpace(p.Mode)
		switch mode {
		case "", "monitor":
			mode = "monitor"
		case "enforce":
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "enforce mode cannot be pushed from the console: an enforcing TracingPolicy kills " +
					"with no audit row, no reversal and no kill-switch. Load it deliberately on the host."})
			return
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("unknown mode %q (want monitor)", mode)})
			return
		}
		docs = append(docs, &ebpfsocv1.PolicyDoc{Name: name, Yaml: p.YAML, Mode: mode})
	}

	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_ApplyPolicy{ApplyPolicy: &ebpfsocv1.ApplyPolicy{
			Policies: docs, Remove: b.Remove, Reason: b.Reason}}})

	// "dispatched" and "acked", never "updated". total is the agents the
	// control plane KNOWS about — the heartbeat registry, which is in-memory
	// and forgets the fleet on restart — so even total is a floor. Saying so
	// here costs one field and prevents the reading that matters.
	writeJSON(w, 200, map[string]any{
		"ok":            applied > 0,
		"acked":         applied,
		"dispatched_to": total,
		"detail":        detail,
		"converged":     false,
		"convergence_note": "this push is not retried: an agent offline now will not receive it, and the " +
			"count above is over agents the control plane currently knows about. Check the reported " +
			"policy set on the next heartbeat to see which hosts actually carry it.",
	})
}
