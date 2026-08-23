package api

import (
	"reflect"
	"testing"
)

// The engine's policy list iterated the shipped MITRE catalogue and nothing
// else. That was right only while detections could not be authored: once an
// operator can write one, the catalogue does not contain it, so they push a
// policy, are told "applied", hit refresh, and see nothing new — the feature
// looks broken at the exact moment it worked.
func TestPolicyListIncludesAPolicyTheOperatorWrote(t *testing.T) {
	catalogue := []string{"sensitive-file-access", "privilege-escalation"}
	kernel := map[string]policyStat{
		"sensitive-file-access": {Name: "sensitive-file-access", State: "enabled"},
		// Not in any catalogue — somebody wrote it in the console.
		"acme-billing-watch": {Name: "acme-billing-watch", State: "enabled"},
	}

	got := unionPolicyNames(catalogue, kernel)

	want := []string{"acme-billing-watch", "privilege-escalation", "sensitive-file-access"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("union = %v, want %v", got, want)
	}
}

// A catalogue policy the kernel does NOT have must survive the union: its
// absence is the coverage gap the surface exists to report, and dropping it
// would silently turn a missing detection into no row at all.
func TestPolicyListKeepsACataloguePolicyTheKernelLacks(t *testing.T) {
	got := unionPolicyNames([]string{"outbound-connections"}, map[string]policyStat{})
	if len(got) != 1 || got[0] != "outbound-connections" {
		t.Fatalf("union = %v, want the missing catalogue policy retained", got)
	}
}

func TestPolicyListDoesNotDuplicateOrEmit(t *testing.T) {
	got := unionPolicyNames(
		[]string{"p", "p", ""},
		map[string]policyStat{"p": {Name: "p"}, "": {}},
	)
	if !reflect.DeepEqual(got, []string{"p"}) {
		t.Fatalf("union = %v, want exactly [p]", got)
	}
}

// An unreadable kernel leaves the catalogue intact rather than emptying the
// list — "we could not ask" must not render as "no detections exist".
func TestPolicyListSurvivesAnUnreadableKernel(t *testing.T) {
	got := unionPolicyNames([]string{"a", "b"}, nil)
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("union = %v, want the catalogue unchanged", got)
	}
}
