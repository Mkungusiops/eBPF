package baseline

import (
	"database/sql"
	"time"
)

// Persistence and history priming.
//
// # Why both exist
//
// A profile held only in memory is relearned from nothing after every restart,
// and a restart is exactly when an operator most wants the detection working.
// Worse, the warm-up gate means a freshly restarted agent is BLIND for its
// MinAge window — so "deploy the new build" and "switch the anomaly detection
// off for half an hour, fleet-wide" would be the same action.
//
// Priming solves the other half. A host that has been running for weeks already
// has the evidence needed to know what is normal, sitting in its own events
// table. Replaying it means an established deployment is warm the moment the
// process starts, rather than spending its first day calling everything novel.
// The events are replayed WITH THEIR ORIGINAL TIMESTAMPS, so decay applies as
// if they had been observed live and a three-week-old exec carries three weeks
// of decay rather than arriving as fresh evidence.

// Snapshot is the serialisable form of a profile. Flat rather than nested so
// the SQL is one table and a partial write cannot produce an unreadable tree.
type Snapshot struct {
	Observations int
	Oldest       time.Time
	Newest       time.Time
	Rows         []SnapshotRow
}

// SnapshotRow is one facet key.
type SnapshotRow struct {
	Facet     string
	Key       string
	Weight    float64
	Count     uint64
	FirstSeen time.Time
	LastSeen  time.Time
	// Total is carried on every row of a facet rather than in its own table.
	// Denormalised deliberately: one table means loading is one query and a
	// half-written flush loses keys but can never leave a facet with a total
	// that does not correspond to any of its keys — which would silently
	// distort every share calculation afterwards.
	Total   float64
	TotalAt time.Time
}

// Snapshot captures the profile for persistence.
func (p *Profile) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	snap := Snapshot{Observations: p.observations, Oldest: p.oldest, Newest: p.newest}
	for name, f := range p.facets {
		for k, e := range f.keys {
			snap.Rows = append(snap.Rows, SnapshotRow{
				Facet: name, Key: k, Weight: e.weight, Count: e.count,
				FirstSeen: e.firstSeen, LastSeen: e.lastSeen,
				Total: f.total, TotalAt: f.totalAt,
			})
		}
	}
	return snap
}

// Restore replaces the profile's contents with a snapshot. Used at startup.
func (p *Profile) Restore(snap Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.facets = map[string]*facet{}
	p.observations = snap.Observations
	p.oldest, p.newest = snap.Oldest, snap.Newest
	for _, r := range snap.Rows {
		f := p.facet(r.Facet)
		f.total, f.totalAt = r.Total, r.TotalAt
		f.keys[r.Key] = &entry{
			weight: r.Weight, count: r.Count,
			firstSeen: r.FirstSeen, lastSeen: r.LastSeen,
		}
	}
	p.dirty = false
}

// Dirty reports whether there are unflushed observations, so a periodic flush
// on an idle host does no database work at all.
func (p *Profile) Dirty() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dirty
}

// MarkClean is called by the persister after a successful flush.
func (p *Profile) MarkClean() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dirty = false
}

// PrimeFromHistory folds already-stored executions into the profile.
//
// `rows` yields (binary, parentBinary, uid, at) oldest-first. Ordering matters:
// decay is applied forward from each entry's last-seen time, so replaying
// newest-first would age every subsequent observation against a future
// timestamp and flatten every weight to near zero.
//
// It does NOT assess anything. Priming is learning, and an event that has
// already happened cannot be alerted on retroactively — the alert, if it was
// warranted, was raised at the time by the rules.
func (p *Profile) PrimeFromHistory(rows []Observation) int {
	n := 0
	for _, o := range rows {
		if o.Binary == "" {
			continue
		}
		p.Observe(o)
		n++
	}
	return n
}

// ── SQLite/Postgres persistence ────────────────────────────────────────────

const baselineSchema = `
CREATE TABLE IF NOT EXISTS baseline_counts (
	facet      TEXT NOT NULL,
	key        TEXT NOT NULL,
	weight     REAL NOT NULL,
	count      BIGINT NOT NULL,
	first_seen TIMESTAMP NOT NULL,
	last_seen  TIMESTAMP NOT NULL,
	total      REAL NOT NULL,
	total_at   TIMESTAMP NOT NULL,
	PRIMARY KEY (facet, key)
);
CREATE TABLE IF NOT EXISTS baseline_meta (
	id           INTEGER PRIMARY KEY,
	observations BIGINT NOT NULL,
	oldest       TIMESTAMP,
	newest       TIMESTAMP
);
`

// Store persists a profile in the host's existing database.
//
// It takes a *sql.DB rather than the internal/store type so this package does
// not import the store (which imports the metrics and the decision chain), and
// so a test can hand it a bare in-memory database.
type Store struct {
	db      *sql.DB
	dialect string
}

// NewStore prepares the tables. dialect is "sqlite" or "postgres".
func NewStore(db *sql.DB, dialect string) (*Store, error) {
	s := &Store{db: db, dialect: dialect}
	schema := baselineSchema
	if dialect == "postgres" {
		// Postgres rejects SQLite's bare INTEGER PRIMARY KEY-as-rowid idiom for
		// a singleton table's id column only in that it will not auto-populate
		// it; the value is written explicitly below, so the type is all that
		// needs changing.
		schema = replaceAll(schema, "TIMESTAMP", "TIMESTAMPTZ")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return s, nil
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (s *Store) ph(n int) string {
	if s.dialect != "postgres" {
		return "?"
	}
	return "$" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Save writes the snapshot, replacing what was there.
//
// One transaction, DELETE then INSERT. An UPSERT-per-key would leave keys that
// eviction dropped in the database forever, and a profile that reloads keys it
// deliberately evicted is unbounded on disk even though it is bounded in
// memory — which is the same leak, one layer down.
func (s *Store) Save(snap Snapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM baseline_counts`); err != nil {
		return err
	}
	stmt := `INSERT INTO baseline_counts (facet, key, weight, count, first_seen, last_seen, total, total_at)
		VALUES (` + s.ph(1) + `,` + s.ph(2) + `,` + s.ph(3) + `,` + s.ph(4) + `,` + s.ph(5) + `,` + s.ph(6) + `,` + s.ph(7) + `,` + s.ph(8) + `)`
	ins, err := tx.Prepare(stmt)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	for _, r := range snap.Rows {
		if _, err := ins.Exec(r.Facet, r.Key, r.Weight, r.Count, r.FirstSeen, r.LastSeen, r.Total, r.TotalAt); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM baseline_meta`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO baseline_meta (id, observations, oldest, newest) VALUES (1,`+
		s.ph(1)+`,`+s.ph(2)+`,`+s.ph(3)+`)`, snap.Observations, snap.Oldest, snap.Newest); err != nil {
		return err
	}
	return tx.Commit()
}

// Load reads a saved snapshot. A missing or empty table is not an error: it is
// a first run, and the caller primes from history instead.
func (s *Store) Load() (Snapshot, error) {
	var snap Snapshot
	row := s.db.QueryRow(`SELECT observations, oldest, newest FROM baseline_meta WHERE id = 1`)
	var oldest, newest sql.NullTime
	if err := row.Scan(&snap.Observations, &oldest, &newest); err != nil {
		if err == sql.ErrNoRows {
			return snap, nil
		}
		return snap, err
	}
	snap.Oldest, snap.Newest = oldest.Time, newest.Time

	rows, err := s.db.Query(`SELECT facet, key, weight, count, first_seen, last_seen, total, total_at FROM baseline_counts`)
	if err != nil {
		return snap, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r SnapshotRow
		if err := rows.Scan(&r.Facet, &r.Key, &r.Weight, &r.Count, &r.FirstSeen, &r.LastSeen, &r.Total, &r.TotalAt); err != nil {
			return snap, err
		}
		snap.Rows = append(snap.Rows, r)
	}
	// A partial result set must not read as "the profile is this small" — that
	// silently narrows what the host considers normal and makes routine
	// activity look novel.
	return snap, rows.Err()
}
