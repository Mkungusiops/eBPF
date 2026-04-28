package store

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
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
	db *sql.DB
}

func New(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		event_type TEXT NOT NULL,
		pid INTEGER,
		parent_pid INTEGER,
		exec_id TEXT,
		binary TEXT,
		args TEXT,
		uid INTEGER,
		policy_name TEXT,
		raw_json TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_exec_id ON events(exec_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);

	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
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
	res, err := s.db.Exec(`
		INSERT INTO events
		(timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.EventType, e.PID, e.ParentPID, e.ExecID,
		e.Binary, e.Args, e.UID, e.PolicyName, e.RawJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) InsertAlert(a *Alert) (int64, error) {
	idsJSON, _ := json.Marshal(a.EventIDs)
	res, err := s.db.Exec(`
		INSERT INTO alerts (timestamp, severity, title, description, exec_id, score, event_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.Severity, a.Title, a.Description, a.ExecID, a.Score, string(idsJSON))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name
		FROM events ORDER BY id DESC LIMIT ?`, limit)
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
	rows, err := s.db.Query(`
		SELECT id, timestamp, severity, title, description, exec_id, score, event_ids
		FROM alerts ORDER BY id DESC LIMIT ?`, limit)
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
	rows, err := s.db.Query(`
		SELECT id, timestamp, event_type, pid, parent_pid, exec_id, binary, args, uid, policy_name
		FROM events WHERE exec_id = ? ORDER BY id ASC`, execID)
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
