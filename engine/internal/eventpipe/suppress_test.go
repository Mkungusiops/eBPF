package eventpipe

import (
	"path/filepath"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

func storeForTest(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A suppression is a deliberate reduction in what the platform detects. Every
// property below is a safety property, not a convenience.

func TestSuppressionMatchesExactlyAndNarrowsOptionally(t *testing.T) {
	s := newSuppressor()
	s.Reload([]store.Suppression{
		{ID: 1, Binary: "/opt/backup/agent", Reason: "our backup agent reads credential paths"},
		{ID: 2, Binary: "/usr/bin/cfgmgr", Policy: "privilege-escalation", Reason: "scheduled setuid"},
	})

	if _, ok := s.Suppressed("/opt/backup/agent", "sensitive-file-access", "/usr/bin/systemd"); !ok {
		t.Error("a binary-only rule should match regardless of policy or parent")
	}
	// Narrowing by policy must actually narrow.
	if _, ok := s.Suppressed("/usr/bin/cfgmgr", "privilege-escalation", ""); !ok {
		t.Error("policy-narrowed rule should match its policy")
	}
	if _, ok := s.Suppressed("/usr/bin/cfgmgr", "sensitive-file-access", ""); ok {
		t.Error("a policy-narrowed rule must NOT match a different policy — that would silence more than asked")
	}
}

func TestBinaryMatchingIsExactNotAPrefix(t *testing.T) {
	// A prefix or glob is how one typo silences half an estate. The blast
	// radius of a mistaken suppression has to stay small.
	s := newSuppressor()
	s.Reload([]store.Suppression{{ID: 1, Binary: "/usr/bin/curl", Reason: "expected"}})

	for _, notCovered := range []string{"/usr/bin/curl-wrapper", "/usr/local/bin/curl", "/usr/bin/cur"} {
		if _, ok := s.Suppressed(notCovered, "", ""); ok {
			t.Errorf("%q was suppressed by a rule for /usr/bin/curl — matching must be exact", notCovered)
		}
	}
}

func TestAnUnconfiguredSuppressorSuppressesNothing(t *testing.T) {
	// Fail OPEN. If rules cannot be loaded the platform is noisy, not blind.
	// The opposite default would silently disable detection.
	s := newSuppressor()
	if _, ok := s.Suppressed("/anything", "any-policy", "any-parent"); ok {
		t.Fatal("an empty suppressor must suppress nothing")
	}
}

func TestHitsCountSoADeadRuleIsVisible(t *testing.T) {
	// A rule that never fires is a typo or an obsolete entry, and an operator
	// cannot tell which from the rule text. Without counts, a settings page
	// accumulates dead rules nobody dares delete.
	s := newSuppressor()
	s.Reload([]store.Suppression{
		{ID: 1, Binary: "/opt/backup/agent", Reason: "fires"},
		{ID: 2, Binary: "/opt/never/runs", Reason: "does not fire"},
	})
	s.Suppressed("/opt/backup/agent", "", "")
	s.Suppressed("/opt/backup/agent", "", "")

	h := s.Hits()
	if h[1] != 2 {
		t.Errorf("rule 1 hits = %d, want 2", h[1])
	}
	if h[2] != 0 {
		t.Errorf("rule 2 never matched but reports %d hits", h[2])
	}
}

func TestValidationRefusesRulesThatCannotWork(t *testing.T) {
	st := storeForTest(t)

	// A bare name can never match — matching is on absolute paths — so it
	// would sit in the list looking like a working rule forever.
	if _, err := st.AddSuppression(&store.Suppression{Binary: "curl", Reason: "bare name"}); err == nil {
		t.Error("a non-absolute binary must be refused")
	}
	// A suppression reduces detection; it needs a justification.
	if _, err := st.AddSuppression(&store.Suppression{Binary: "/usr/bin/curl", Reason: ""}); err == nil {
		t.Error("a suppression without a reason must be refused")
	}
	if _, err := st.AddSuppression(&store.Suppression{Binary: "/usr/bin/curl", Reason: "legitimate use by our tooling"}); err != nil {
		t.Errorf("a well-formed suppression was refused: %v", err)
	}
}
