package store

// The agent's durable outbound queue.
//
// architecture.md §2 describes "the local SQLite WAL becomes a durable queue"
// and the uplink buffer left the seam for it; this is that implementation. It
// lives in the same database as events, alerts and decisions, so a record and
// the note that it still needs sending are committed to one place with one
// fsync policy — a separate file could disagree with the store after a crash.
// The methods are deliberately primitive rather than implementing
// uplink.Journal directly: uplink already imports this package for
// store.Event, so importing it back would be a cycle. The adapter that
// satisfies the interface lives in cmd/agent, which imports both.
//
// UplinkEntry is one persisted record.
type UplinkEntry struct {
	Seq     uint64
	Payload []byte
}

const uplinkJournalSchema = `
CREATE TABLE IF NOT EXISTS uplink_queue (
  seq        BIGINT PRIMARY KEY,
  dedup_key  TEXT NOT NULL,
  payload    BLOB NOT NULL,
  queued_at  TIMESTAMP NOT NULL
);`

// AppendUplink records one enqueued record in the durable backlog.
func (s *Store) AppendUplink(seq uint64, dedupKey string, payload []byte) error {
	_, err := s.db.Exec(rewriteParams(s.dialect,
		// Idempotent on seq: a retried enqueue after a partial write must not
		// fail the send path, and the sequence is already unique per agent.
		`INSERT INTO uplink_queue (seq, dedup_key, payload, queued_at)
		 VALUES (?,?,?,CURRENT_TIMESTAMP)
		 ON CONFLICT(seq) DO NOTHING`),
		seq, dedupKey, payload)
	return err
}

// DeleteUplinkThrough removes everything the control plane has acked, or the
// cap has evicted. Both take the OLDEST records, so one operation serves both.
func (s *Store) DeleteUplinkThrough(seq uint64) error {
	_, err := s.db.Exec(rewriteParams(s.dialect,
		`DELETE FROM uplink_queue WHERE seq <= ?`), seq)
	return err
}

// LoadUplink returns the surviving backlog, oldest first.
func (s *Store) LoadUplink() ([]UplinkEntry, error) {
	// Oldest first: the buffer replays in order, and the control plane's ack
	// is cumulative, so an out-of-order restore would ack records that were
	// never sent.
	rows, err := s.db.Query(`SELECT seq, payload FROM uplink_queue ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UplinkEntry
	for rows.Next() {
		var e UplinkEntry
		if err := rows.Scan(&e.Seq, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
