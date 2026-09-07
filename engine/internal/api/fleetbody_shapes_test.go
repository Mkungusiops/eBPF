package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A fleet WRITE whose body is not a JSON object cannot be checked for a target
// set, and the old default for "no target set" was EVERY peer in the hosts
// file. TestFleetWriteRejectsUnreadableBodyWithoutDispatching covered the three
// shapes that fail to unmarshal (a truncated object, an array, a bare string)
// and left the shapes that unmarshal *successfully into nothing* undiscriminated:
//
//	`null`   — json.Unmarshal into map[string]json.RawMessage returns a NIL map
//	           with a NIL error, so "targets" read as absent and the write fanned
//	           out estate-wide. On the peer it is worse still: handleChokeKillSwitch
//	           decodes `null` into its body struct with no error and all zero
//	           values, so POST /api/fleet/kill-switch with `null` called
//	           SetKillSwitch(false) on every host, with an empty audit reason,
//	           from a body that says nothing.
//	``       — an empty body took the len==0 short-circuit straight to "all peers".
//	`   `    — whitespace only, same short-circuit, and mentioned in neither the
//	           doc comment nor the published spec.
//
// This table is the whole class, so no shape in it is left to the reader's
// imagination: every body that is not a JSON object is refused 400 and nothing
// is dispatched to any peer.
func TestFleetWriteRefusesEveryNonObjectBodyShape(t *testing.T) {
	bodies := map[string]string{
		"literal null":     `null`,
		"empty body":       ``,
		"whitespace only":  "  \n\t ",
		"truncated object": `{"name":"containment",`,
		"json array":       `["bravo"]`,
		"bare string":      `"containment"`,
		"number":           `7`,
		"bool":             `false`,
	}
	for _, route := range fleetWriteRoutes() {
		for label, body := range bodies {
			t.Run(route.name+"/"+label, func(t *testing.T) {
				s, peers := newFleetServer(t)

				rec := callFleet(t, s, route, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 for a body that is not a JSON object; got %s",
						rec.Code, rec.Body.String())
				}
				var out struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Error == "" {
					t.Errorf("400 body %q is not the documented {error} shape", rec.Body.String())
				}
				// The refusal has to happen before the first peer call. There is
				// no unwinding a kill-switch that already landed on three boxes.
				for name, p := range peers {
					if got := p.writes(); len(got) != 0 {
						t.Errorf("%s took a write whose body could not be checked for targets: %+v", name, got)
					}
				}
			})
		}
	}
}

// resolveTargets is the unit under the handlers; pinning it directly keeps the
// distinction between "not an object" and "an object with no targets key"
// visible even if a handler stops calling it.
func TestResolveTargetsSeparatesNonObjectsFromAnAbsentTargetSet(t *testing.T) {
	peers := []FleetPeer{{Name: "alpha"}, {Name: "bravo"}}

	for _, body := range []string{`null`, ``, "   ", `[]`, `"x"`, `3`} {
		sel, terr := resolveTargets(peers, []byte(body))
		if terr == nil {
			t.Errorf("resolveTargets(%q) allowed a write to %d peer(s); a body that is "+
				"not a JSON object must be refused, not widened to the estate", body, len(sel.Peers))
			continue
		}
		if terr.Message == "" {
			t.Errorf("resolveTargets(%q) refused with an empty message; the console "+
				"renders this text and would show a blank failure", body)
		}
	}

	// The one shape that legitimately means "every host": a real object that
	// simply does not scope itself. This must keep working, or "All hosts" —
	// and every integrator's unscoped write — breaks.
	sel, terr := resolveTargets(peers, []byte(`{"on":true}`))
	if terr != nil {
		t.Fatalf("an object with no targets key was refused (%s); absent targets is the estate-wide write", terr.Message)
	}
	if len(sel.Peers) != len(peers) {
		t.Fatalf("absent targets reached %d peers, want all %d", len(sel.Peers), len(peers))
	}

	// And explicit null targets INSIDE an object stays estate-wide: that is what
	// the console sends for "All hosts", so refusing a `null` body must not have
	// caught this too.
	sel, terr = resolveTargets(peers, []byte(`{"on":true,"targets":null}`))
	if terr != nil {
		t.Fatalf(`{"targets":null} was refused (%s); it is the console's "All hosts" write`, terr.Message)
	}
	if len(sel.Peers) != len(peers) {
		t.Fatalf(`"targets":null reached %d peers, want all %d`, len(sel.Peers), len(peers))
	}
}
