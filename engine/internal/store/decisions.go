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

	// Origin attributes the originating remote client (the operator's
	// view of "who triggered this"). Populated by the origin tracker;
	// any field can be empty when attribution wasn't available.
	OriginKind        string `json:"origin_kind,omitempty"`
	OriginIP          string `json:"origin_ip,omitempty"`
	OriginPort        uint16 `json:"origin_port,omitempty"`
	OriginUser        string `json:"origin_user,omitempty"`
	OriginFingerprint string `json:"origin_fingerprint,omitempty"`

	// Device attributes a network-choke decision to the LAN device it
	// acted on (the network-gateway analog of Origin). Empty for the
	// per-process choke path. ExecID carries "device:<mac>" for these rows.
	DeviceMAC string `json:"device_mac,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// hasOrigin reports whether any origin field is set. Used by canonical()
// to keep pre-origin audit rows hash-stable: rows written before the
// feature shipped have empty origin and produce the legacy canonical
// string, so VerifyDecisionChain keeps passing on old databases.
func (d *Decision) hasOrigin() bool {
	return d.OriginKind != "" || d.OriginIP != "" || d.OriginPort != 0 ||
		d.OriginUser != "" || d.OriginFingerprint != ""
}

// hasDevice reports whether the row carries network-device attribution.
// Like hasOrigin, this keeps pre-device audit rows hash-stable: rows
// written before the network choke shipped produce their original
// canonical string and continue to verify on old databases.
func (d *Decision) hasDevice() bool {
	return d.DeviceMAC != "" || d.DeviceID != ""
}

func (d *Decision) deviceTail() string {
	return "|" + d.DeviceMAC + "|" + d.DeviceID
}

// canonical builds a stable string representation used for hashing. Field
// order matters; do not reorder without bumping a schema version.
//
// Timestamp is truncated to microsecond precision before formatting:
// Postgres TIMESTAMPTZ has 6 fractional digits, Go's time.Time has 9.
// Without truncation, the write-path hashes nanos but verify reads back
// microseconds, the canonical strings differ, and the chain reports
// broken-at-id-1 even when nothing was actually tampered with. SQLite
// preserves nanos so truncating is harmless there — keeps the two
// dialects in lockstep.
func (d *Decision) canonical() string {
	base := d.Timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) + "|" +
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
	// Trailers append to the end so old rows (no origin/device) keep their
	// original canonical form and hash. New rows with attribution gain the
	// extra protection without invalidating the existing chain. Order:
	// origin trailer (if any) then device trailer (if any).
	s := base
	if d.hasOrigin() {
		s += "|" +
			d.OriginKind + "|" +
			d.OriginIP + "|" +
			strconv.FormatUint(uint64(d.OriginPort), 10) + "|" +
			d.OriginUser + "|" +
			d.OriginFingerprint
	}
	if d.hasDevice() {
		s += d.deviceTail()
	}
	return s
}

func computeHash(prev, canonical string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalCandidates returns every canonical form the row could have
// been hashed under across this engine's history. VerifyDecisionChain
// accepts the row's stored hash if it matches ANY of these forms.
//
// This exists because canonical() has changed twice:
//
//  1. Original form: timestamp formatted at full nanosecond precision,
//     12 fields, no origin trailer.
//  2. Truncate-to-microsecond was added (to keep Postgres TIMESTAMPTZ
//     verification matching SQLite). Made all pre-truncate rows fail
//     verification on engines running the new code.
//  3. Origin fields appended conditionally (this branch). Rows with
//     attribution get a 5-field trailer; rows without keep the
//     legacy 12-field form for backward compatibility.
//
// Each historical era is reproduced here. Tamper-evidence is preserved
// — an attacker can't forge a row that produces a matching hash under
// any era without inverting sha256. Write-path canonical() still
// emits the single current form so new rows pin to the latest era.
func (d *Decision) canonicalCandidates() []string {
	tsMicro := d.Timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	tsNano := d.Timestamp.UTC().Format(time.RFC3339Nano)

	body := func(ts string) string {
		return ts + "|" +
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
	originTail := "|" +
		d.OriginKind + "|" +
		d.OriginIP + "|" +
		strconv.FormatUint(uint64(d.OriginPort), 10) + "|" +
		d.OriginUser + "|" +
		d.OriginFingerprint
	deviceTail := d.deviceTail()

	// Reproduce every form a row could have been written under. The write
	// path emits base[+origin][+device]; we enumerate the matching
	// combinations for each timestamp precision era so a canonical-format
	// change never retroactively invalidates the audit log. Tamper-evidence
	// is preserved — an attacker still can't forge a hash without inverting
	// sha256.
	out := make([]string, 0, 8)
	for _, ts := range []string{tsMicro, tsNano} {
		b := body(ts)
		if d.hasOrigin() && d.hasDevice() {
			out = append(out, b+originTail+deviceTail)
		}
		if d.hasOrigin() {
			out = append(out, b+originTail)
		}
		if d.hasDevice() {
			out = append(out, b+deviceTail)
		}
		out = append(out, b)
	}
	return out
}

// decisionStore is mixed into Store via composition (see sqlite.go) but
// kept here so the audit-chain code lives in one file. The store mutex
// serialises Hash chain updates so concurrent inserts produce a strictly
// linear chain.
type decisionStore struct {
	db      *sql.DB
	dialect string
	mu      sync.Mutex
	last    string // most recent Hash, cached so we don't re-read on every insert
}

func newDecisionStore(db *sql.DB, dialect string) *decisionStore {
	ds := &decisionStore{db: db, dialect: dialect}
	_ = ds.loadLastHash() // best effort; an error just means we start a new chain
	return ds
}

func (ds *decisionStore) migrate() error {
	idCol := "INTEGER PRIMARY KEY AUTOINCREMENT"
	tsCol := "DATETIME"
	if ds.dialect == "postgres" {
		idCol = "BIGSERIAL PRIMARY KEY"
		tsCol = "TIMESTAMPTZ"
	}
	if _, err := ds.db.Exec(`
	CREATE TABLE IF NOT EXISTS decisions (
		id          ` + idCol + `,
		timestamp   ` + tsCol + ` NOT NULL,
		exec_id     TEXT NOT NULL,
		pid         BIGINT NOT NULL,
		"binary"      TEXT,
		action      TEXT NOT NULL,
		from_state  TEXT NOT NULL,
		to_state    TEXT NOT NULL,
		score       INTEGER NOT NULL,
		reason      TEXT,
		dry_run     INTEGER NOT NULL DEFAULT 0,
		backend     TEXT,
		outcome     TEXT,
		origin_kind TEXT,
		origin_ip   TEXT,
		origin_port INTEGER,
		origin_user TEXT,
		origin_fp   TEXT,
		prev_hash   TEXT NOT NULL,
		hash        TEXT NOT NULL UNIQUE
	);
	CREATE INDEX IF NOT EXISTS idx_decisions_exec_id   ON decisions(exec_id);
	CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_decisions_action    ON decisions(action);
	`); err != nil {
		return err
	}
	// Backfill the origin columns on databases created before the
	// feature shipped. Idempotent: ADD COLUMN IF NOT EXISTS on Postgres,
	// a column-exists pre-check on SQLite (which lacks IF NOT EXISTS for
	// ADD COLUMN until 3.35 and even then has quirks). Pre-existing rows
	// keep NULL origin fields, which Scan reads as empty — and empty
	// origin yields the legacy canonical form, so the audit chain
	// verification continues to pass.
	//
	// Order matters here: the origin_ip index below references a column
	// that may not exist yet on legacy DBs, so the ADD COLUMN loop must
	// land before the index creation.
	for _, col := range []struct{ name, def string }{
		{"origin_kind", "TEXT"},
		{"origin_ip", "TEXT"},
		{"origin_port", "INTEGER"},
		{"origin_user", "TEXT"},
		{"origin_fp", "TEXT"},
		{"device_mac", "TEXT"},
		{"device_id", "TEXT"},
	} {
		if err := ds.addColumnIfMissing("decisions", col.name, col.def); err != nil {
			return fmt.Errorf("add %s: %w", col.name, err)
		}
	}
	if _, err := ds.db.Exec(`CREATE INDEX IF NOT EXISTS idx_decisions_origin_ip ON decisions(origin_ip)`); err != nil {
		return fmt.Errorf("create idx_decisions_origin_ip: %w", err)
	}
	return nil
}

// addColumnIfMissing performs a dialect-correct ALTER TABLE ADD COLUMN
// that is a no-op when the column already exists. Postgres handles this
// natively; SQLite needs a PRAGMA table_info pre-check.
func (ds *decisionStore) addColumnIfMissing(table, col, def string) error {
	if ds.dialect == "postgres" {
		_, err := ds.db.Exec(fmt.Sprintf(
			`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s`, table, col, def))
		return err
	}
	rows, err := ds.db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == col {
			return nil
		}
	}
	_, err = ds.db.Exec(fmt.Sprintf(
		`ALTER TABLE %s ADD COLUMN %s %s`, table, col, def))
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

	q := rewriteParams(ds.dialect, `
		INSERT INTO decisions
		(timestamp, exec_id, pid, "binary", action, from_state, to_state, score,
		 reason, dry_run, backend, outcome,
		 origin_kind, origin_ip, origin_port, origin_user, origin_fp,
		 device_mac, device_id,
		 prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	args := []interface{}{
		d.Timestamp, d.ExecID, d.PID, d.Binary, d.Action, d.FromState, d.ToState,
		d.Score, d.Reason, boolToInt(d.DryRun), d.Backend, d.Outcome,
		nullableString(d.OriginKind), nullableString(d.OriginIP), nullableUint16(d.OriginPort),
		nullableString(d.OriginUser), nullableString(d.OriginFingerprint),
		nullableString(d.DeviceMAC), nullableString(d.DeviceID),
		d.PrevHash, d.Hash,
	}
	var id int64
	if ds.dialect == "postgres" {
		if err := ds.db.QueryRow(q+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, err
		}
	} else {
		res, err := ds.db.Exec(q, args...)
		if err != nil {
			return 0, err
		}
		var lerr error
		id, lerr = res.LastInsertId()
		if lerr != nil {
			return 0, lerr
		}
	}
	d.ID = id
	ds.last = d.Hash
	return id, nil
}

// RecentDecisions returns the most recent decisions, newest first.
func (ds *decisionStore) RecentDecisions(limit int) ([]Decision, error) {
	rows, err := ds.db.Query(rewriteParams(ds.dialect, `
		SELECT id, timestamp, exec_id, pid, "binary", action, from_state, to_state,
		       score, reason, dry_run, backend, outcome,
		       origin_kind, origin_ip, origin_port, origin_user, origin_fp,
		       device_mac, device_id,
		       prev_hash, hash
		FROM decisions ORDER BY id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Decision, 0)
	for rows.Next() {
		d, err := scanDecisionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// scanDecisionRow reads one row in the canonical column order shared by
// RecentDecisions and VerifyDecisionChain. Centralising the Scan keeps
// the nullable origin columns from drifting between the two readers.
func scanDecisionRow(rows *sql.Rows) (Decision, error) {
	var d Decision
	var dr int
	var oKind, oIP, oUser, oFP sql.NullString
	var oPort sql.NullInt64
	var devMAC, devID sql.NullString
	if err := rows.Scan(&d.ID, &d.Timestamp, &d.ExecID, &d.PID, &d.Binary,
		&d.Action, &d.FromState, &d.ToState, &d.Score, &d.Reason,
		&dr, &d.Backend, &d.Outcome,
		&oKind, &oIP, &oPort, &oUser, &oFP,
		&devMAC, &devID,
		&d.PrevHash, &d.Hash); err != nil {
		return Decision{}, err
	}
	d.DryRun = dr != 0
	if oKind.Valid {
		d.OriginKind = oKind.String
	}
	if oIP.Valid {
		d.OriginIP = oIP.String
	}
	if oPort.Valid {
		d.OriginPort = uint16(oPort.Int64)
	}
	if oUser.Valid {
		d.OriginUser = oUser.String
	}
	if oFP.Valid {
		d.OriginFingerprint = oFP.String
	}
	if devMAC.Valid {
		d.DeviceMAC = devMAC.String
	}
	if devID.Valid {
		d.DeviceID = devID.String
	}
	return d, nil
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
		SELECT id, timestamp, exec_id, pid, "binary", action, from_state, to_state,
		       score, reason, dry_run, backend, outcome,
		       origin_kind, origin_ip, origin_port, origin_user, origin_fp,
		       device_mac, device_id,
		       prev_hash, hash
		FROM decisions ORDER BY id ASC`)
	if err != nil {
		return VerifyChainResult{}, err
	}
	defer rows.Close()

	var prev string
	res := VerifyChainResult{OK: true}
	for rows.Next() {
		d, err := scanDecisionRow(rows)
		if err != nil {
			return res, err
		}
		res.Total++
		if d.PrevHash != prev {
			res.OK = false
			res.BadAt = d.ID
			res.BadField = "prev_hash"
			return res, nil
		}
		// Tolerant verify: accept the row if its stored hash matches
		// ANY historical canonical era. The write path always emits
		// the current canonical, but verify has to recognise every
		// prior form so a canonical-algorithm change doesn't
		// retroactively invalidate the entire audit log. See
		// canonicalCandidates for the era list.
		matched := false
		for _, c := range d.canonicalCandidates() {
			if computeHash(d.PrevHash, c) == d.Hash {
				matched = true
				break
			}
		}
		if !matched {
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

// nullableString writes NULL for empty strings so empty origin fields
// stay distinguishable from explicit "" attributions on read-back. The
// canonical() form treats both equally, so the audit chain is unaffected.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableUint16 writes NULL for zero ports (the wildcard / unattributed
// case) and the numeric value otherwise.
func nullableUint16(v uint16) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

// formatDecisionRow keeps a stable rendering for log lines and tests.
func formatDecisionRow(d *Decision) string {
	return fmt.Sprintf("decision id=%d ts=%s action=%s %s→%s exec_id=%s pid=%d score=%d dry_run=%v",
		d.ID, d.Timestamp.UTC().Format(time.RFC3339), d.Action,
		d.FromState, d.ToState, d.ExecID, d.PID, d.Score, d.DryRun)
}
