package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/mitre"
)

// Sensor health for a SINGLE host.
//
// # Why the engine needs its own
//
// /api/sensor-health was registered only on the control plane, so on a
// single-tenant deployment the panel rendered "not served by this deployment"
// permanently. That message is honest and it is also useless: a customer
// running one engine got nothing at all from the surface that answers the most
// important question a security platform can be asked — "can I trust what you
// are telling me right now?".
//
// # What it deliberately does NOT report
//
// The control plane's version carries dropped_records, buffer depth and agent
// freshness, all sourced from the heartbeat every agent sends it. The engine
// has no equivalent counter today, and this omits those fields rather than
// sending zeros. A zero here would read as "no evidence has been lost", which
// is a claim this build cannot support — and inventing a reassuring number on
// the trust surface would be the worst possible place to do it.
//
// Freshness is likewise omitted rather than faked: the engine IS the host, so
// "is it reporting" is answered by the page having loaded at all. Reporting
// 1/1 with a computed age would be theatre.
// issue is one finding with a machine-readable kind, so the console can pair it
// with a remedy instead of leaving the operator to infer one.
type issue struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// The closed set of issue kinds. Shared verbatim with the control plane so one
// console maps both planes.
const (
	issueKernelUnreadable = "kernel-unreadable"
	issuePoliciesMissing  = "policies-missing"
	issueNoTetragon       = "no-tetragon"
	issuePolicyEnforcing  = "policy-enforcing"
	issueStaleHeartbeat   = "stale-heartbeat"
	issueEvidenceLost     = "evidence-lost"

	// Enforcement findings. These lower status: each is something that failed,
	// or a posture armed against the operator.
	issueEnforcementDegraded  = "enforcement-degraded"
	issueNoProcessContainment = "no-process-containment"
	issueDevicePlaneDetached  = "device-plane-detached"
	issueContainmentShadowed  = "containment-shadowed"
	issueKillSwitched         = "kill-switched"

	// Notes. True, worth stating, NOT faults — a mechanism absent by
	// deployment is not a defect, and alarming on it trains operators to
	// ignore the panel.
	noteManualOnly     = "containment-manual-only"
	noteNoNetworkChoke = "no-kernel-network-choke"
	noteNoDevicePlane  = "no-device-plane"
)

var _ = issueStaleHeartbeat // control-plane only; declared here so the set is one list
var _ = issueEvidenceLost

func (s *Server) handleSensorHealth(w http.ResponseWriter, r *http.Request) {
	// Same reason as the push handler: agent_id is serverHostname, and a panel
	// that identifies the host as "" is worse than useless on a trust surface.
	resolveServerIdentity()
	now := time.Now().UTC()

	// Kernel truth, from the same source the Detections surface uses.
	loaded := map[string]policyStat{}
	kernelObservable := false
	// Recognised, not merely exited-0. This is the trust surface: an output
	// this build cannot parse must read as "I cannot tell you", never as "all
	// four of your detections are missing".
	stats, ok, via := kernelPolicies(r.Context())
	for _, st := range stats {
		loaded[st.Name] = st
	}
	kernelObservable = ok

	var enforcing int
	for _, st := range loaded {
		if strings.EqualFold(st.Mode, "enforce") {
			enforcing++
		}
	}

	// A gap is an EXPECTED policy the kernel does not have. Only computable
	// when the kernel could be read at all: with no reading, "missing" and
	// "unknown" are different answers and only one of them is true.
	missing := []string{}
	expected := mitre.Policies()
	if kernelObservable {
		for _, name := range expected {
			if st, ok := loaded[name]; !ok || !strings.EqualFold(st.State, "enabled") {
				missing = append(missing, name)
			}
		}
	}
	sort.Strings(missing)

	sysInfoMu.RLock()
	info := sysInfo
	sysInfoMu.RUnlock()

	processPlane := info.BPFBackend
	if processPlane == "" {
		processPlane = "unknown"
	}
	processLinks := 0
	if info.BPFLinks != nil {
		processLinks = info.BPFLinks()
	}
	tetragonUp := info.TetragonConnected != nil && info.TetragonConnected()

	// Issues carry a CODE, not just prose.
	//
	// This surface named problems and offered nothing to do about them — a wall
	// of numbers behind a READ-ONLY badge. An operator reading "expected
	// detections not loaded" had to know, unaided, that the fix lives on a
	// different panel. The code lets the console attach the remedy to the
	// finding: a button where the platform can actually fix it, and a plain
	// instruction where it cannot.
	//
	// Codes are a closed set (see issueCode* below) so the console's mapping
	// cannot silently miss one; a code it does not recognise still renders its
	// detail, just without a remedy.
	issues := []issue{}
	status := "ok"
	if !kernelObservable {
		issues = append(issues, issue{Code: issueKernelUnreadable,
			Detail: "cannot read kernel policy state, so detection coverage on this host is unknown"})
		status = "unknown"
	}
	if len(missing) > 0 {
		issues = append(issues, issue{Code: issuePoliciesMissing,
			Detail: "expected detections not loaded: " + strings.Join(missing, ", ")})
		status = "degraded"
	}
	if !tetragonUp {
		issues = append(issues, issue{Code: issueNoTetragon,
			Detail: "no Tetragon connection — this host is not receiving kernel events"})
		status = "degraded"
	}
	if enforcing > 0 {
		issues = append(issues, issue{Code: issuePolicyEnforcing,
			Detail: "a policy is in ENFORCE mode, which kills with no audit row and no kill-switch"})
		status = "degraded"
	}

	// ENFORCEMENT. Graded mechanisms plus the two-channel split: faults lower
	// the status, deployment facts do not.
	cont, contIssues, notes := assessContainment(info)
	issues = append(issues, contIssues...)
	if len(contIssues) > 0 {
		status = "degraded"
	}

	agent := map[string]any{
		"containment":       cont,
		"notes":             notes,
		"agent_id":          serverHostname,
		"status":            status,
		"issues":            issues,
		"policies_loaded":   len(loaded),
		"policies_enforce":  enforcing,
		"missing_policies":  missing,
		"kernel_observable": kernelObservable,
		// Which mechanism answered: "grpc" (the connection this process already
		// holds), "cli" (the docker-exec scrape), "unparsed" or "unavailable".
		// Surfaced rather than hidden — a silent fallback means nobody notices
		// the fragile path is the one in use.
		"kernel_read_via": via,
		"process_plane":   processPlane,
		"process_links":   processLinks,
		"tetragon":        tetragonUp,
		"last_seen":       now,
	}

	writeJSONStatus(w, 200, map[string]any{
		"agents": []any{agent},
		// This console is the host. There is no enrolment to be incomplete
		// about and no second host to be missing, so 1/1 is a fact here rather
		// than the coverage estimate the same numbers represent on the control
		// plane.
		"agents_total": 1,
		"agents_fresh": 1,
		"agents_losing": func() int {
			if status == "ok" {
				return 0
			}
			return 1
		}(),
		"expected_policies": expected,
		"coverage_caveat": "this console reads ONE host — its own. It says nothing about any other machine, " +
			"and a host with no engine on it is invisible here.",
		// dropped_records is deliberately absent: this build has no evidence-loss
		// counter, and a zero would assert that nothing has been lost.
		"evidence_loss_known": false,
		"generated_at":        now,
	})
}
