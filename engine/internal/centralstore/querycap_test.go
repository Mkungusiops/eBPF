package centralstore

import "testing"

// An unbounded read is how this platform went down on 2026-08-05: a missing
// index met a caller-supplied limit, 2.8M-row sorts exhausted the connection
// pool, every read endpoint 500'd and the disk filled with sort spill. The
// index was added. The unbounded read was not — five control-plane handlers
// still pass ?limit through untouched and one multiplies it by four, so the
// same outage needs only read privilege and a large number.
//
// The cap lives at the store boundary because that is the one place all of them
// funnel through. This test pins the constant so a handler-side "optimisation"
// cannot quietly reintroduce the shape.
func TestMaxQueryRowsIsBoundedAndSane(t *testing.T) {
	if MaxQueryRows <= 0 {
		t.Fatal("a non-positive cap disables the protection entirely")
	}
	// Generous enough for a real console page, far below the millions that
	// caused the outage.
	if MaxQueryRows > 100000 {
		t.Fatalf("MaxQueryRows = %d — large enough to reproduce the 2026-08-05 sort spill", MaxQueryRows)
	}
	// The fleet endpoint multiplies a caller's limit by four before it reaches
	// the store, so the cap must hold against an already-multiplied number.
	if got := clampRows(1000000 * 4); got != MaxQueryRows {
		t.Fatalf("a four-million-row request clamped to %d, want %d", got, MaxQueryRows)
	}
	if got := clampRows(0); got != 1000 {
		t.Fatalf("an unset limit should take the 1000 default, got %d", got)
	}
	if got := clampRows(50); got != 50 {
		t.Fatalf("a modest limit must pass through unchanged, got %d", got)
	}
}
