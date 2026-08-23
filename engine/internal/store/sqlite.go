package store

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	_ "modernc.org/sqlite"

	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
)

type Event struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	PID        uint32    `json:"pid"`
	ParentPID  uint32    `json:"parent_pid"`
	ExecID     string    `json:"exec_id"`
	Binary     string    `json:"binary"`
	Args       string    `json:"args"`
	UID        uint32    `json:"uid"`
	PolicyName string    `json:"policy_name"`
	RawJSON    string    `json:"raw_json,omitempty"`
}

type Alert struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	ExecID      string    `json:"exec_id"`
	Score       int       `json:"score"`
	EventIDs    []int64   `json:"event_ids"`
}

type Store struct {
	db      *sql.DB
	dialect string // "sqlite" or "postgres" — drives placeholder + auto-id syntax
	*decisionStore
}

// New opens a SQLite store at path. Default for the single-host PoC path.
func New(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	return wireStore(db, "sqlite")
}

// NewPostgres opens a Postgres store at the given DSN
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=disable"). Used
// for the Postgres-backed deployment that's a foundation for multi-host
// fan-in (one Postgres, eventually multiple engines / a collector).
func NewPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return wireStore(db, "postgres")
}

func wireStore(db *sql.DB, dialect string) (*Store, error) {
	s := &Store{db: db, dialect: dialect}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	ds := newDecisionStore(db, dialect)
	if err := ds.migrate(); err != nil {
		return nil, err
	}
	if err := ds.loadLastHash(); err != nil {
		return nil, err
	}
	s.decisionStore = ds
	return s, nil
}

// rewriteParams takes a `?`-placeholder SQL string and rewrites it for
// Postgres ($1, $2, ...) when dialect=="postgres". Sqlite keeps the
// original. Lets us write SQL once.
func rewriteParams(dialect, q string) string {
	if dialect != "postgres" {
		return q
	}
	out := make([]byte, 0, len(q))
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, '$')
			out = append(out, []byte(strconvItoa(n))...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// strconvItoa avoids pulling strconv into this small helper.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// insertReturningID runs INSERT and returns the generated ID. SQLite uses
// LastInsertId(); Postgres requires "RETURNING id".
func (s *Store) insertReturningID(query string, args ...interface{}) (int64, error) {
	q := rewriteParams(s.dialect, query)
	if s.dialect == "postgres" {
		var id int64
		if err := s.db.QueryRow(q+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Dialect returns "sqlite" or "postgres". Used by the system-health
// handler so the dashboard can show which backend is actually running.
func (s *Store) Dialect() string { return s.dialect }

// DB exposes the underlying handle so a sibling package can own its own tables
// in the same database.
//
// Deliberately narrow in intent: it exists for internal/baseline, which needs
// to persist a learned profile beside the events it learned from, and which
// must NOT import this package (this one imports metrics and the decision
// chain; the baseline is a leaf that a test hands an in-memory database to).
// Sharing the handle rather than the Store keeps that dependency pointing one
// way, and keeps the profile in the same file the operator already backs up.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	idCol := "INTEGER PRIMARY KEY AUTOINCREMENT"
	tsCol := "DATETIME"
	if s.dialect == "postgres" {
		idCol = "BIGSERIAL PRIMARY KEY"
		tsCol = "TIMESTAMPTZ"
	}
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id ` + idCol + `,
		timestamp ` + tsCol + ` NOT NULL,
		event_type TEXT NOT NULL,
		pid BIGINT,
		parent_pid BIGINT,
		exec_id TEXT,
		"binary" TEXT,
		args TEXT,
		uid BIGINT,
		policy_name TEXT,
		raw_json TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_exec_id ON events(exec_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);

	CREATE TABLE IF NOT EXISTS alerts (
		id ` + idCol + `,
		timestamp ` + tsCol + ` NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		exec_id TEXT,
		score INTEGER,
		event_ids TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) InsertEvent(e *Event) (int64, error) {
	start := time.Now()
	id, err := s.insertReturningID(`
		INSERT INTO events
		(timestamp, event_type, pid, parent_pid, exec_id, "binary", args, uid, policy_name, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.EventType, e.PID, e.ParentPID, e.ExecID,
		e.Binary, e.Args, e.UID, e.PolicyName, e.RawJSON)
	metrics.ObserveStoreInsert(time.Since(start).Seconds(), "event")
	return id, err
}

func (s *Store) InsertAlert(a *Alert) (int64, error) {
	idsJSON, _ := json.Marshal(a.EventIDs)
	start := time.Now()
	id, err := s.insertReturningID(`
		INSERT INTO alerts (timestamp, severity, title, description, exec_id, score, event_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.Severity, a.Title, a.Description, a.ExecID, a.Score, string(idsJSON))
	metrics.ObserveStoreInsert(time.Since(start).Seconds(), "alert")
	return id, err
}

func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, "binary", args, uid, policy_name
		FROM events ORDER BY id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.PID, &e.ParentPID,
			&e.ExecID, &e.Binary, &e.Args, &e.UID, &e.PolicyName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	// A partial result set from an interrupted query must not read as "no more
	// rows" — that silently under-reports events on a security console.
	return out, rows.Err()
}

func (s *Store) RecentAlerts(limit int) ([]Alert, error) {
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT id, timestamp, severity, title, description, exec_id, score, event_ids
		FROM alerts ORDER BY id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Alert, 0)
	for rows.Next() {
		var a Alert
		var idsJSON string
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Severity, &a.Title, &a.Description,
			&a.ExecID, &a.Score, &idsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &a.EventIDs)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) EventsByExecID(execID string) ([]Event, error) {
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, "binary", args, uid, policy_name
		FROM events WHERE exec_id = ? ORDER BY id ASC`), execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.PID, &e.ParentPID,
			&e.ExecID, &e.Binary, &e.Args, &e.UID, &e.PolicyName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExecObservation is one historical execution, reduced to the fields the
// behavioural baseline learns from.
type ExecObservation struct {
	Binary       string
	ParentBinary string
	UID          uint32
	At           time.Time
}

// RecentExecObservations returns stored executions OLDEST-FIRST, for priming
// the behavioural baseline at startup.
//
// # Why oldest-first, and why the self-join
//
// Ordering is not cosmetic. The baseline decays every weight forward from the
// last time it saw a key, so replaying newest-first ages each successive
// observation against a timestamp in its own past — which the decay function
// clamps, flattening the profile into "everything happened at once". Oldest
// first reproduces the real history.
//
// The self-join recovers the PARENT BINARY, which is the single most
// discriminating fact the baseline learns (nginx launching sh is the finding;
// sh existing is not). The events table stores parent_pid but not the parent's
// name, so it is matched back to the most recent earlier exec of that pid. That
// is an approximation — pids are reused — but it is bounded to the join window
// and it is only ever used to LEARN what is normal, never to justify an alert
// on its own. A wrong parent teaches the profile one edge that did not happen;
// it cannot fabricate a finding, because findings are assessed live against the
// parent Tetragon actually reported.
//
// LIMIT is applied to the newest rows and the result is then reversed, so a
// bounded prime takes the most RECENT window of history rather than the oldest
// rows in the table — a profile primed from last March describes a host that no
// longer exists.
//
// Cost is bounded by the LIMIT rather than by the table: the outer scan walks
// the primary-key index backwards and stops, and each subquery is a seek on
// idx_events_pid. Measured at 1.27s for 200k rows against a 500k-row table,
// which is a one-time startup cost paid after the HTTP listener is already
// serving. Worth knowing before raising the limit: it is linear in it.
func (s *Store) RecentExecObservations(limit int) ([]ExecObservation, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT e.timestamp, e."binary", e.uid,
		       COALESCE((SELECT p."binary" FROM events p
		                  WHERE p.pid = e.parent_pid
		                    AND p.event_type = 'process_exec'
		                    AND p.id < e.id
		                  ORDER BY p.id DESC LIMIT 1), '')
		FROM events e
		WHERE e.event_type = 'process_exec' AND e."binary" <> ''
		ORDER BY e.id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ExecObservation, 0, limit)
	for rows.Next() {
		var o ExecObservation
		if err := rows.Scan(&o.At, &o.Binary, &o.UID, &o.ParentBinary); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse into chronological order for the replay.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
