package baseline

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var base = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

// warm returns a profile that has genuinely learned a boring host: sshd
// launching bash, bash launching ls, over two days.
func warm(t *testing.T) *Profile {
	t.Helper()
	p := New(Warmup{MinObservations: 100, MinAge: time.Hour})
	at := base
	for i := 0; i < 400; i++ {
		at = at.Add(5 * time.Minute)
		p.Observe(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: at})
		p.Observe(Observation{Binary: "/bin/ls", ParentBinary: "/bin/bash", UID: 1000, At: at})
	}
	if !p.Ready() {
		t.Fatal("fixture profile should be ready")
	}
	return p
}

func TestUnreadyProfileScoresNothing(t *testing.T) {
	p := New(Warmup{MinObservations: 100, MinAge: time.Hour})
	p.Observe(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", At: base})

	got := p.Assess(Observation{Binary: "/tmp/evil", ParentBinary: "/usr/sbin/nginx", At: base})
	if got.Ready {
		t.Fatal("profile with one observation must not report ready")
	}
	if got.Points != 0 {
		t.Fatalf("an unready profile must score 0, got %d", got.Points)
	}
	// The distinction that matters: it is not saying "nothing anomalous", it is
	// saying "I do not know yet", and the caller has to be able to tell.
	if len(got.Reasons) != 0 {
		t.Fatalf("an unready profile must not offer reasons, got %v", got.Reasons)
	}
}

func TestNovelLineageScoresHigherThanNovelBinaryAlone(t *testing.T) {
	p := warm(t)
	at := base.Add(50 * time.Hour)

	// A binary this host knows, launched by a parent that has never launched it.
	// This is the signal a rule table cannot express and the reason the edge
	// facet is weighted highest.
	lineage := p.Assess(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/nginx", UID: 1000, At: at})
	if !lineage.Novel {
		t.Fatal("nginx launching bash must read as novel on a host where only sshd does")
	}
	found := false
	for _, r := range lineage.Reasons {
		if strings.Contains(r, "lineage") && strings.Contains(r, "nginx") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a lineage reason naming nginx, got %v", lineage.Reasons)
	}
}

func TestRoutineActivityScoresZeroAndSaysSo(t *testing.T) {
	p := warm(t)
	got := p.Assess(Observation{
		Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000,
		At: base.Add(30 * time.Hour),
	})
	if got.Points != 0 {
		t.Fatalf("the host's most common activity must score 0, got %d (%v)", got.Points, got.Reasons)
	}
	if !got.Routine {
		t.Fatal("the host's most common activity must be reported Routine")
	}
	if got.Novel {
		t.Fatal("the host's most common activity must not be Novel")
	}
}

// Assess must never subtract. Chain scores are cumulative and drive
// containment; a negative contribution would let an attacker pad a chain with
// routine activity to drag it back under the throttle threshold.
func TestAssessNeverReturnsNegativePoints(t *testing.T) {
	p := warm(t)
	for i := 0; i < 200; i++ {
		got := p.Assess(Observation{
			Binary:       "/bin/bash",
			ParentBinary: "/usr/sbin/sshd",
			UID:          uint32(i),
			At:           base.Add(time.Duration(i) * time.Hour),
		})
		if got.Points < 0 {
			t.Fatalf("points must never be negative, got %d", got.Points)
		}
	}
}

func TestPointsAreCappedPerEvent(t *testing.T) {
	p := warm(t)
	// Novel on every single facet at once.
	got := p.Assess(Observation{
		Binary: "/tmp/.x", ParentBinary: "/usr/sbin/nginx", UID: 31337,
		At: base.Add(37 * time.Hour), // an hour never observed
	})
	if got.Points > MaxEventPoints {
		t.Fatalf("points must be capped at %d, got %d", MaxEventPoints, got.Points)
	}
	// And the cap must sit below the high band, so novelty alone can never
	// justify containment.
	if MaxEventPoints >= 20 {
		t.Fatalf("MaxEventPoints (%d) must stay below the high band (20)", MaxEventPoints)
	}
}

// The single most important ordering contract in this package.
func TestAssessBeforeObserveIsTheCallersContract(t *testing.T) {
	p := warm(t)
	at := base.Add(60 * time.Hour)
	o := Observation{Binary: "/tmp/dropper", ParentBinary: "/usr/sbin/nginx", UID: 0, At: at}

	first := p.Assess(o)
	if !first.Novel {
		t.Fatal("a never-seen binary must assess as novel")
	}
	p.Observe(o)

	// Observing it teaches the profile. Asking again is now a different
	// question and a lower score — which is correct, and is exactly why the
	// caller must assess first.
	second := p.Assess(o)
	if second.Points >= first.Points {
		t.Fatalf("after Observe the same event must score lower: first=%d second=%d", first.Points, second.Points)
	}
}

func TestKernelThreadsAreNotLearned(t *testing.T) {
	p := New(DefaultWarmup)
	p.Observe(Observation{Binary: "[kworker/0:2]", ParentBinary: "[kthreadd]", At: base})
	if p.Status(5).Observations != 0 {
		t.Fatal("bracketed kernel threads are not executions and must not be counted")
	}
}

func TestDecayNeverInflatesOnAnOutOfOrderEvent(t *testing.T) {
	// A replayed batch or a clock step can deliver an older timestamp. Applying
	// a negative elapsed time to the exponential would MULTIPLY the weight.
	if got := decay(1, base, base.Add(-100*time.Hour)); got != 1 {
		t.Fatalf("a backwards timestamp must leave weight unchanged, got %v", got)
	}
	if got := decay(1, base, base.Add(HalfLife)); got > 0.51 || got < 0.49 {
		t.Fatalf("one half-life should halve the weight, got %v", got)
	}
}

func TestFacetEvictionIsBoundedAndKeepsTheCommonKeys(t *testing.T) {
	p := New(Warmup{MinObservations: 1, MinAge: time.Nanosecond})
	at := base
	// One key observed constantly, plus more unique keys than the cap.
	for i := 0; i < maxKeysPerFacet+2000; i++ {
		at = at.Add(time.Second)
		p.Observe(Observation{Binary: "/tmp/u" + strconv.Itoa(i), ParentBinary: "/bin/sh", At: at})
		if i%10 == 0 {
			p.Observe(Observation{Binary: "/bin/common", ParentBinary: "/bin/sh", At: at})
		}
	}
	st := p.Status(3)
	for _, f := range st.Facets {
		if f.Keys > maxKeysPerFacet {
			t.Fatalf("facet %s holds %d keys, above the %d cap", f.Facet, f.Keys, maxKeysPerFacet)
		}
	}
	// Eviction must drop the rare tail, not the thing the host actually does.
	if got := p.Assess(Observation{Binary: "/bin/common", ParentBinary: "/bin/sh", At: at}); got.Novel {
		t.Fatal("eviction dropped the most common key; it must evict the rarest")
	}
}

func TestPrimingMakesAnEstablishedHostReadyImmediately(t *testing.T) {
	p := New(DefaultWarmup)
	history := make([]Observation, 0, 600)
	at := base
	for i := 0; i < 600; i++ {
		at = at.Add(time.Minute)
		history = append(history, Observation{
			Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: at,
		})
	}
	if n := p.PrimeFromHistory(history); n != 600 {
		t.Fatalf("primed %d of 600", n)
	}
	if !p.Ready() {
		t.Fatal("a profile primed from ten hours of real history must be ready at once")
	}
}

func TestSnapshotRoundTripsThroughSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st, err := NewStore(db, "sqlite")
	if err != nil {
		t.Fatal(err)
	}

	p := warm(t)
	before := p.Assess(Observation{Binary: "/tmp/evil", ParentBinary: "/usr/sbin/nginx", UID: 0, At: base.Add(40 * time.Hour)})
	if err := st.Save(p.Snapshot()); err != nil {
		t.Fatal(err)
	}

	restored := New(Warmup{MinObservations: 100, MinAge: time.Hour})
	snap, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	restored.Restore(snap)

	if !restored.Ready() {
		t.Fatal("a restored profile must still be ready — otherwise every restart blinds the host")
	}
	after := restored.Assess(Observation{Binary: "/tmp/evil", ParentBinary: "/usr/sbin/nginx", UID: 0, At: base.Add(40 * time.Hour)})
	if after.Points != before.Points {
		t.Fatalf("restored profile scores differently: before=%d after=%d", before.Points, after.Points)
	}
}

func TestSaveReplacesRatherThanAccumulating(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st, err := NewStore(db, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	p := warm(t)
	if err := st.Save(p.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(p.Snapshot()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM baseline_counts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(p.Snapshot().Rows) {
		t.Fatalf("two saves left %d rows for a %d-row profile — evicted keys would live forever on disk",
			n, len(p.Snapshot().Rows))
	}
}

func TestStatusReportsProgressNotJustABoolean(t *testing.T) {
	p := New(Warmup{MinObservations: 1000, MinAge: time.Hour})
	at := base
	for i := 0; i < 50; i++ {
		at = at.Add(time.Minute)
		p.Observe(Observation{Binary: "/bin/ls", ParentBinary: "/bin/bash", At: at})
	}
	st := p.Status(3)
	if st.Ready {
		t.Fatal("50 observations must not satisfy a 1000-observation warm-up")
	}
	// "Not ready" and "ready, found nothing" produce the same empty anomaly
	// list. The console can only tell them apart if the numbers are here.
	if st.Observations != 50 || st.NeedObservations != 1000 {
		t.Fatalf("progress must be reported: %+v", st)
	}
	if st.SpanSeconds <= 0 || st.NeedSpanSeconds <= 0 {
		t.Fatalf("age progress must be reported: %+v", st)
	}
}

// The hour facet must not score before it has watched long enough for an
// unseen hour to MEAN something.
//
// This shipped, and it was the worst kind of defect: quiet, systematic, and
// aimed squarely at the panel that exists to show findings. A profile satisfied
// the warm-up gate after 40 minutes having observed one hour of the day, so at
// the next hour boundary the host's most routine activity scored 3 and was
// flagged Novel — every process, every hour, for the first day.
func TestHourFacetIsSilentUntilItHasWatchedLongEnough(t *testing.T) {
	p := New(DefaultWarmup)
	at := base
	for i := 0; i < 600; i++ {
		p.Observe(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: at})
		at = at.Add(4 * time.Second)
	}
	if !p.Ready() {
		t.Fatal("fixture should satisfy the warm-up gate")
	}

	// The SAME routine activity, at an hour the profile has never observed.
	got := p.Assess(Observation{
		Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000,
		At: base.Add(90 * time.Minute),
	})
	if got.Points != 0 {
		t.Fatalf("routine activity at a new hour scored %d (%v) — every process would be flagged hourly",
			got.Points, got.Reasons)
	}
	if got.Novel {
		t.Fatal("routine activity was flagged Novel purely because the clock moved on")
	}
}

// ...and it must still work once the profile has genuinely watched a week.
func TestHourFacetScoresOnceItHasAWeekOfEvidence(t *testing.T) {
	p := New(DefaultWarmup)
	// Eight days of activity confined to working hours. Built with time.Date
	// rather than by adding offsets to `base`, because `base` is midday and
	// adding "9 hours" lands on 21:00 — the fixture would then be asserting
	// something other than what it reads as.
	day0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for day := 0; day < 8; day++ {
		for hour := 9; hour < 18; hour++ {
			ts := day0.AddDate(0, 0, day).Add(time.Duration(hour) * time.Hour)
			for i := 0; i < 10; i++ {
				p.Observe(Observation{
					Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000,
					At: ts.Add(time.Duration(i) * time.Minute),
				})
			}
		}
	}
	if !p.Ready() {
		t.Fatal("eight days of activity should be ready")
	}

	// 03:00 on a host that has never run at 03:00 in eight days is a real
	// statement, and the facet must now make it.
	night := day0.AddDate(0, 0, 8).Add(3 * time.Hour)
	got := p.Assess(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: night})
	found := false
	for _, r := range got.Reasons {
		if strings.Contains(r, "hour 3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("after a week, activity at a never-seen hour must be reported: %v", got.Reasons)
	}

	// And a working hour on the same profile must stay silent.
	day := day0.AddDate(0, 0, 8).Add(11 * time.Hour)
	if q := p.Assess(Observation{Binary: "/bin/bash", ParentBinary: "/usr/sbin/sshd", UID: 1000, At: day}); q.Points != 0 {
		t.Fatalf("a normal working hour scored %d (%v)", q.Points, q.Reasons)
	}
}

// The gate must stop the facet SCORING, never stop it LEARNING — otherwise it
// would never accumulate the week of evidence that unlocks it.
func TestHourFacetKeepsLearningWhileItIsGated(t *testing.T) {
	p := New(DefaultWarmup)
	at := base
	for i := 0; i < 600; i++ {
		p.Observe(Observation{Binary: "/bin/ls", ParentBinary: "/bin/bash", At: at})
		at = at.Add(4 * time.Second)
	}
	var hourKeys int
	for _, f := range p.Status(5).Facets {
		if f.Facet == FacetHour {
			hourKeys = f.Keys
		}
	}
	if hourKeys == 0 {
		t.Fatal("the hour facet stopped learning while gated; it would never unlock")
	}
}

// Both of these were measured on the live engine on 2026-08-21, and both made
// the profile call the host's most routine activity novel.

// TestUsrMergeAliasesCollapseToOneKey: /bin/bash and /usr/bin/bash are the same
// inode via the usr-merge symlink. Kept apart, the host's constant /bin/bash
// made /usr/bin/bash look rare, and every `sudo bash` scored as novel twice.
func TestUsrMergeAliasesCollapseToOneKey(t *testing.T) {
	cases := [][2]string{
		{"/bin/bash", "/usr/bin/bash"},
		{"/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd"},
		{"/lib/systemd/systemd", "/usr/lib/systemd/systemd"},
	}
	for _, tc := range cases {
		if got, want := normaliseBinary(tc[0]), tc[1]; got != want {
			t.Errorf("normaliseBinary(%q) = %q, want %q — usr-merge aliases must share one key", tc[0], got, want)
		}
		if got := normaliseBinary(tc[1]); got != tc[1] {
			t.Errorf("normaliseBinary(%q) = %q, want it unchanged", tc[1], got)
		}
	}
}

// TestUsrMergeDoesNotMergeDistinctDirectories: /usr/bin and /usr/sbin are real,
// separate directories. Collapsing them would merge different programs.
func TestUsrMergeDoesNotMergeDistinctDirectories(t *testing.T) {
	if normaliseBinary("/usr/sbin/ip") == normaliseBinary("/usr/bin/ip") {
		t.Fatal("/usr/sbin/ip and /usr/bin/ip are different paths and must stay different keys")
	}
}

// TestFdReexecIsNotKeyedByFileDescriptor: the basename of /proc/self/fd/9 is
// the fd number — per-run, meaningless, and colliding with every other numeric
// basename. It reached 6,116 observations as the "executable" named `9`.
func TestFdReexecIsNotKeyedByFileDescriptor(t *testing.T) {
	for _, fd := range []string{"/proc/self/fd/9", "/proc/self/fd/6", "/proc/self/fd/14"} {
		got := normaliseBinary(fd)
		if got == "9" || got == "6" || got == "14" {
			t.Fatalf("normaliseBinary(%q) = %q — a file-descriptor number is not an identity", fd, got)
		}
		if got != "/proc/self/fd" {
			t.Errorf("normaliseBinary(%q) = %q, want %q", fd, got, "/proc/self/fd")
		}
	}
	// Every fd re-exec must land on the SAME key, or the facet still fills
	// with per-run noise.
	if normaliseBinary("/proc/self/fd/9") != normaliseBinary("/proc/self/fd/6") {
		t.Fatal("fd re-execs must collapse to one stable key")
	}
}

// TestProcSelfExeStillCollapsesToBasename: the original rule still applies to
// the non-numeric /proc paths it was written for.
func TestProcSelfExeStillCollapsesToBasename(t *testing.T) {
	if got := normaliseBinary("/proc/self/exe"); got != "exe" {
		t.Fatalf("normaliseBinary(/proc/self/exe) = %q, want %q", got, "exe")
	}
}
