package eventpipe

import (
	"strings"
	"sync"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The operator's own suppressions, applied to scoring.
//
// # Why a cache rather than a query per event
//
// This runs on every scored event — thousands per host per hour. A database
// round trip there would put the store on the hot path of the thing that has
// to keep up with the kernel. The set is small (an operator writes a handful),
// changes rarely, and is reloaded explicitly when one is added or removed.
//
// # Fail OPEN, deliberately
//
// If the suppression set cannot be loaded, scoring proceeds unsuppressed. The
// failure mode is noise, not blindness. The opposite choice — treating a load
// error as "suppress everything" — would silently disable detection, which is
// the one outcome this platform must never reach by accident.
type suppressor struct {
	mu    sync.RWMutex
	rules []store.Suppression
	hits  map[int64]int64
}

func newSuppressor() *suppressor {
	return &suppressor{hits: map[int64]int64{}}
}

// Reload replaces the set. Called at startup and after a settings change.
func (s *suppressor) Reload(rules []store.Suppression) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
}

// Suppressed reports whether an observation matches an operator rule, and
// which one, so the caller can say WHY a score was withheld rather than
// silently dropping it.
//
// A suppressed observation is still recorded as an event and still appears in
// the process tree. Only the SCORE is withheld — the score is what drives
// automatic containment, and that is the only thing an operator is asking to
// stop.
func (s *suppressor) Suppressed(binary, policy, parent string) (store.Suppression, bool) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()
	for _, r := range rules {
		if r.Match(binary, policy, parent) {
			s.mu.Lock()
			s.hits[r.ID]++
			s.mu.Unlock()
			return r, true
		}
	}
	return store.Suppression{}, false
}

// Hits returns the per-rule fire counts.
//
// A rule that has never fired is either wrong — a typo'd path that will never
// match — or obsolete. An operator cannot tell those apart from the rule text
// alone, and a settings page that lists rules without saying which ones do
// anything accumulates dead entries nobody dares delete.
func (s *suppressor) Hits() map[int64]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[int64]int64, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// suppressionReason renders the withheld-score note that lands on the event,
// so the timeline shows the suppression rather than an unexplained absence.
func suppressionReason(r store.Suppression) string {
	var b strings.Builder
	b.WriteString("score withheld by an operator suppression: ")
	b.WriteString(r.Reason)
	if r.Policy != "" {
		b.WriteString(" [policy " + r.Policy + "]")
	}
	return b.String()
}
