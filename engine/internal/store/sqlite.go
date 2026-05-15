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
	return out, nil
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
	return out, nil
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
	return out, nil
}
