package sysproc

import "testing"

func TestDescendantsBFS(t *testing.T) {
	all := []Entry{
		{PID: 1, PPID: 0},
		{PID: 100, PPID: 1},
		{PID: 200, PPID: 1},
		{PID: 101, PPID: 100}, // child of 100
		{PID: 102, PPID: 100}, // child of 100
		{PID: 1010, PPID: 101}, // grandchild
	}
	got := Descendants(all, 100, false)
	want := []uint32{101, 102, 1010}
	if !equalU32(got, want) {
		t.Errorf("Descendants(100) = %v, want %v", got, want)
	}

	got = Descendants(all, 100, true)
	want = []uint32{100, 101, 102, 1010}
	if !equalU32(got, want) {
		t.Errorf("Descendants(100, includeRoot) = %v, want %v", got, want)
	}

	if got := Descendants(all, 999, false); len(got) != 0 {
		t.Errorf("Descendants(999)=%v, want empty", got)
	}
}

func TestDescendantsCycleSafe(t *testing.T) {
	// Pathological loop: 50→60, 60→50. BFS must terminate.
	all := []Entry{
		{PID: 50, PPID: 60},
		{PID: 60, PPID: 50},
		{PID: 70, PPID: 50},
	}
	got := Descendants(all, 50, false)
	// Must not loop forever; must include 60 (and via 60, no new visit of 50)
	// and 70 since 70's ppid is 50.
	if len(got) == 0 {
		t.Fatalf("expected some descendants, got empty (cycle?)")
	}
	for _, p := range got {
		if p == 50 {
			t.Errorf("root must not appear when includeRoot=false")
		}
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
