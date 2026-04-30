package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Decision is one row in the tamper-evident enforcement audit log.
//
// Each row's Hash is sha256(prev_hash || canonical_row). Verifying the chain
// later (or remotely, after exporting) makes silent tampering — including
// "an operator quietly disabled enforcement and removed the decision" —
// detectable. Recompute every Hash; any mismatch flags the row, and any
// row whose Hash != next row's PrevHash flags that boundary.
type Decision struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ExecID    string    `json:"exec_id"`
	PID       uint32    `json:"pid"`
	Binary    string    `json:"binary"`
	Action    string    `json:"action"`
	FromState string    `json:"from_state"`
	ToState   string    `json:"to_state"`
	Score     int       `json:"score"`
	Reason    string    `json:"reason"`
	DryRun    bool      `json:"dry_run"`
	Backend   string    `json:"backend"`
	Outcome   string    `json:"outcome"` // "ok" or error message
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// canonical builds a stable string representation used for hashing. Field
// order matters; do not reorder without bumping a schema version.
func (d *Decision) canonical() string {
	return d.Timestamp.UTC().Format(time.RFC3339Nano) + "|" +
		d.ExecID + "|" +
		strconv.FormatUint(uint64(d.PID), 10) + "|" +
		d.Binary + "|" +
		d.Action + "|" +
		d.FromState + "|" +
		d.ToState + "|" +
		strconv.Itoa(d.Score) + "|" +
		d.Reason + "|" +
		strconv.FormatBool(d.DryRun) + "|" +
		d.Backend + "|" +
		d.Outcome
}

func computeHash(prev, canonical string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// decisionStore is mixed into Store via composition (see sqlite.go) but
// kept here so the audit-chain code lives in one file. The store mutex
// serialises Hash chain updates so concurrent inserts produce a strictly
// linear chain.
type decisionStore struct {
	db   *sql.DB
	mu   sync.Mutex
	last string // most recent Hash, cached so we don't re-read on every insert
}

func newDecisionStore(db *sql.DB) *decisionStore {
	ds := &decisionStore{db: db}
	_ = ds.loadLastHash() // best effort; an error just means we start a new chain
	return ds
}

func (ds *decisionStore) migrate() error {
	_, err := ds.db.Exec(`
	CREATE TABLE IF NOT EXISTS decisions (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp   DATETIME NOT NULL,
		exec_id     TEXT NOT NULL,
		pid         INTEGER NOT NULL,
		binary      TEXT,
		action      TEXT NOT NULL,
		from_state  TEXT NOT NULL,
		to_state    TEXT NOT NULL,
		score       INTEGER NOT NULL,
		reason      TEXT,
		dry_run     INTEGER NOT NULL DEFAULT 0,
		backend     TEXT,
		outcome     TEXT,
		prev_hash   TEXT NOT NULL,
		hash        TEXT NOT NULL UNIQUE
	);
	CREATE INDEX IF NOT EXISTS idx_decisions_exec_id   ON decisions(exec_id);
	CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_decisions_action    ON decisions(action);
	`)
	return err
}

func (ds *decisionStore) loadLastHash() error {
	row := ds.db.QueryRow(`SELECT hash FROM decisions ORDER BY id DESC LIMIT 1`)
	var h string
	if err := row.Scan(&h); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ds.last = ""
			return nil
		}
		return err
	}
	ds.last = h
	return nil
}

// InsertDecision appends a Decision to the audit chain. The PrevHash and
// Hash fields on d are populated in-place; ID is set on success.
func (ds *decisionStore) InsertDecision(d *Decision) (int64, error) {
	if d == nil {
		return 0, errors.New("nil decision")
	}
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now().UTC()
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	d.PrevHash = ds.last
	d.Hash = computeHash(d.PrevHash, d.canonical())

	res, err := ds.db.Exec(`
		INSERT INTO decisions
		(timestamp, exec_id, pid, binary, action, from_state, to_state, score,
		 reason, dry_run, backend, outcome, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Timestamp, d.ExecID, d.PID, d.Binary, d.Action, d.FromState, d.ToState,
		d.Score, d.Reason, boolToInt(d.DryRun), d.Backend, d.Outcome,
		d.PrevHash, d.Hash)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	d.ID = id
	ds.last = d.Hash
	return id, nil
}

// RecentDecisions returns the most recent decisions, newest first.
func (ds *decisionStore) RecentDecisions(limit int) ([]Decision, error) {
	rows, err := ds.db.Query(`
		SELECT id, timestamp, exec_id, pid, binary, action, from_state, to_state,
		       score, reason, dry_run, backend, outcome, prev_hash, hash
		FROM decisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Decision, 0)
	for rows.Next() {
		var d Decision
		var dr int
		if err := rows.Scan(&d.ID, &d.Timestamp, &d.ExecID, &d.PID, &d.Binary,
			&d.Action, &d.FromState, &d.ToState, &d.Score, &d.Reason,
			&dr, &d.Backend, &d.Outcome, &d.PrevHash, &d.Hash); err != nil {
			return nil, err
		}
		d.DryRun = dr != 0
		out = append(out, d)
	}
	return out, nil
}

// VerifyChainResult reports the outcome of walking the decision audit chain.
// BadAt is the first decision ID where the chain breaks (0 if intact).
type VerifyChainResult struct {
	Total    int    `json:"total"`
	OK       bool   `json:"ok"`
	BadAt    int64  `json:"bad_at,omitempty"`
	BadField string `json:"bad_field,omitempty"`
}

// VerifyDecisionChain re-walks the entire decisions table from oldest to
// newest, recomputing each hash and validating the prev_hash linkage. Use
// this from a CLI or admin endpoint to detect tampering.
func (ds *decisionStore) VerifyDecisionChain() (VerifyChainResult, error) {
	rows, err := ds.db.Query(`
		SELECT id, timestamp, exec_id, pid, binary, action, from_state, to_state,
		       score, reason, dry_run, backend, outcome, prev_hash, hash
		FROM decisions ORDER BY id ASC`)
	if err != nil {
		return VerifyChainResult{}, err
	}
	defer rows.Close()

	var prev string
	res := VerifyChainResult{OK: true}
	for rows.Next() {
		var d Decision
		var dr int
		if err := rows.Scan(&d.ID, &d.Timestamp, &d.ExecID, &d.PID, &d.Binary,
			&d.Action, &d.FromState, &d.ToState, &d.Score, &d.Reason,
			&dr, &d.Backend, &d.Outcome, &d.PrevHash, &d.Hash); err != nil {
			return res, err
		}
		d.DryRun = dr != 0
		res.Total++
		if d.PrevHash != prev {
			res.OK = false
			res.BadAt = d.ID
			res.BadField = "prev_hash"
			return res, nil
		}
		want := computeHash(d.PrevHash, d.canonical())
		if want != d.Hash {
			res.OK = false
			res.BadAt = d.ID
			res.BadField = "hash"
			return res, nil
		}
		prev = d.Hash
	}
	return res, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// formatDecisionRow keeps a stable rendering for log lines and tests.
func formatDecisionRow(d *Decision) string {
	return fmt.Sprintf("decision id=%d ts=%s action=%s %s→%s exec_id=%s pid=%d score=%d dry_run=%v",
		d.ID, d.Timestamp.UTC().Format(time.RFC3339), d.Action,
		d.FromState, d.ToState, d.ExecID, d.PID, d.Score, d.DryRun)
}
