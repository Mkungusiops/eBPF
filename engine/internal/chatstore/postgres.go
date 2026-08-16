package chatstore

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// schema mirrors internal/centralstore/postgres.go deliberately — same RLS
// discipline, same reasoning. Read that file's comments first; the decisions
// here are the same ones.
const schema = `
CREATE TABLE IF NOT EXISTS assistant_chat (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL,
  user_id           TEXT NOT NULL,
  title             TEXT NOT NULL DEFAULT 'New chat',
  mode              TEXT NOT NULL DEFAULT 'chat',
  compacted_summary TEXT NOT NULL DEFAULT '',
  pinned_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assistant_message (
  id         TEXT PRIMARY KEY,
  chat_id    TEXT NOT NULL REFERENCES assistant_chat(id) ON DELETE CASCADE,
  tenant_id  TEXT NOT NULL,
  role       TEXT NOT NULL,
  content    TEXT NOT NULL,
  model      TEXT NOT NULL DEFAULT '',
  steps      TEXT NOT NULL DEFAULT '',
  grounded   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The chat list is "this operator's chats, pinned first, newest first". Without
-- this it is a full scan plus a sort on every sidebar open — the same shape of
-- mistake that took the console down when telemetry(tenant_id, at) had no index.
CREATE INDEX IF NOT EXISTS assistant_chat_user
  ON assistant_chat (user_id, pinned_at DESC NULLS LAST, updated_at DESC);
CREATE INDEX IF NOT EXISTS assistant_message_chat
  ON assistant_message (chat_id, created_at);

-- tenant_id is denormalised onto messages ON PURPOSE. RLS policies are
-- per-table, so without a tenant column on the message table its policy would
-- have to join back to the chat — and a policy that depends on a join is a
-- policy that can be defeated by a planner change. Every tenant-partitioned
-- table carries its own tenant_id and is filtered directly.
ALTER TABLE assistant_chat    ENABLE ROW LEVEL SECURITY;
ALTER TABLE assistant_chat    FORCE  ROW LEVEL SECURITY;
ALTER TABLE assistant_message ENABLE ROW LEVEL SECURITY;
ALTER TABLE assistant_message FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON assistant_chat;
CREATE POLICY tenant_isolation ON assistant_chat
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON assistant_message;
CREATE POLICY tenant_isolation ON assistant_message
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
`

// PGStore is the Postgres-backed chat store.
type PGStore struct {
	db *sql.DB
	// role is the non-superuser role every statement runs as. RLS is bypassed
	// by a superuser even with FORCE, so dropping privilege is not optional.
	role string
}

func NewPGStore(db *sql.DB, role string) (*PGStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("chatstore: migrate: %w", err)
	}
	if role == "" {
		role = "ebpf_soc_app"
	}
	return &PGStore{db: db, role: role}, nil
}

// withScope runs fn inside a transaction that drops privilege and sets
// app.tenant_id, so the RLS policy filters every statement.
//
// The queries inside carry NO tenant predicate. That is the point: RLS does the
// scoping, so a forgotten WHERE clause cannot leak. Adding one "to be safe"
// would hide a policy that had stopped working.
func (p *PGStore) withScope(s Scope, fn func(*sql.Tx) error) error {
	if err := s.valid(); err != nil {
		return err
	}
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("SET LOCAL ROLE " + quoteIdent(p.role)); err != nil {
		return fmt.Errorf("chatstore: drop privilege: %w", err)
	}
	if _, err := tx.Exec("SELECT set_config('app.tenant_id', $1, true)", s.TenantID); err != nil {
		return fmt.Errorf("chatstore: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// quoteIdent guards the one place an identifier is interpolated. SET ROLE takes
// no parameter, so the role name is concatenated — and a role name is
// configuration, but configuration has been attacker-influenced before.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func (p *PGStore) CreateChat(s Scope, title, mode string) (Chat, error) {
	if strings.TrimSpace(title) == "" {
		title = "New chat"
	}
	if mode == "" {
		mode = "chat"
	}
	c := Chat{ID: newID(), TenantID: s.TenantID, UserID: s.UserID, Title: title, Mode: mode}
	err := p.withScope(s, func(tx *sql.Tx) error {
		return tx.QueryRow(`INSERT INTO assistant_chat (id, tenant_id, user_id, title, mode)
			VALUES ($1,$2,$3,$4,$5) RETURNING created_at, updated_at`,
			c.ID, s.TenantID, s.UserID, title, mode).Scan(&c.CreatedAt, &c.UpdatedAt)
	})
	return c, err
}

func (p *PGStore) ListChats(s Scope, limit int) ([]Chat, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []Chat
	err := p.withScope(s, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, tenant_id, user_id, title, mode, compacted_summary,
			pinned_at, created_at, updated_at FROM assistant_chat
			WHERE user_id = $1
			ORDER BY pinned_at DESC NULLS LAST, updated_at DESC LIMIT $2`, s.UserID, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		out, err = scanChats(rows)
		return err
	})
	return out, err
}

func (p *PGStore) GetChat(s Scope, id string) (Chat, error) {
	var c Chat
	err := p.withScope(s, func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT id, tenant_id, user_id, title, mode, compacted_summary,
			pinned_at, created_at, updated_at FROM assistant_chat
			WHERE id = $1 AND user_id = $2`, id, s.UserID)
		return scanChat(row, &c)
	})
	return c, err
}

func (p *PGStore) RenameChat(s Scope, id, title string) error {
	if strings.TrimSpace(title) == "" {
		return fmt.Errorf("chatstore: empty title")
	}
	return p.withScope(s, func(tx *sql.Tx) error {
		return affectOne(tx.Exec(`UPDATE assistant_chat SET title=$1, updated_at=now()
			WHERE id=$2 AND user_id=$3`, title, id, s.UserID))
	})
}

func (p *PGStore) PinChat(s Scope, id string, pinned bool) error {
	return p.withScope(s, func(tx *sql.Tx) error {
		var at any
		if pinned {
			at = time.Now().UTC()
		}
		return affectOne(tx.Exec(`UPDATE assistant_chat SET pinned_at=$1, updated_at=now()
			WHERE id=$2 AND user_id=$3`, at, id, s.UserID))
	})
}

func (p *PGStore) DeleteChat(s Scope, id string) error {
	return p.withScope(s, func(tx *sql.Tx) error {
		return affectOne(tx.Exec(`DELETE FROM assistant_chat WHERE id=$1 AND user_id=$2`, id, s.UserID))
	})
}

func (p *PGStore) AppendMessage(s Scope, chatID string, m Message) (Message, error) {
	m.ID = newID()
	m.ChatID = chatID
	err := p.withScope(s, func(tx *sql.Tx) error {
		// Ownership is checked here rather than trusted from the caller: an
		// endpoint that appends to a chat id from a request body must not be
		// able to write into someone else's conversation.
		var owner string
		if err := tx.QueryRow(`SELECT user_id FROM assistant_chat WHERE id=$1`, chatID).Scan(&owner); err != nil {
			return ErrNotFound
		}
		if owner != s.UserID {
			return ErrNotFound
		}
		if err := tx.QueryRow(`INSERT INTO assistant_message
			(id, chat_id, tenant_id, role, content, model, steps, grounded)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			m.ID, chatID, s.TenantID, m.Role, m.Content, m.Model, m.Steps, m.Grounded,
		).Scan(&m.CreatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE assistant_chat SET updated_at=now() WHERE id=$1`, chatID)
		return err
	})
	return m, err
}

func (p *PGStore) ListMessages(s Scope, chatID string, limit int) ([]Message, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Message
	err := p.withScope(s, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT m.id, m.chat_id, m.role, m.content, m.model, m.steps,
			m.grounded, m.created_at FROM assistant_message m
			JOIN assistant_chat c ON c.id = m.chat_id
			WHERE m.chat_id=$1 AND c.user_id=$2
			ORDER BY m.created_at LIMIT $3`, chatID, s.UserID, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var m Message
			if err := rows.Scan(&m.ID, &m.ChatID, &m.Role, &m.Content, &m.Model,
				&m.Steps, &m.Grounded, &m.CreatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

func (p *PGStore) Search(s Scope, query string, limit int) ([]Chat, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return p.ListChats(s, limit)
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var out []Chat
	err := p.withScope(s, func(tx *sql.Tx) error {
		// Title OR content. ILIKE with a leading wildcard cannot use a btree
		// index, which is fine at conversation volumes and is a deliberate
		// trade against adding a tsvector column before anyone has asked for
		// ranked search. Revisit if chat counts reach the tens of thousands.
		rows, err := tx.Query(`SELECT DISTINCT c.id, c.tenant_id, c.user_id, c.title, c.mode,
			c.compacted_summary, c.pinned_at, c.created_at, c.updated_at
			FROM assistant_chat c
			LEFT JOIN assistant_message m ON m.chat_id = c.id
			WHERE c.user_id = $1 AND (c.title ILIKE $2 OR m.content ILIKE $2)
			ORDER BY c.updated_at DESC LIMIT $3`, s.UserID, "%"+q+"%", limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		out, err = scanChats(rows)
		return err
	})
	return out, err
}

// ── helpers ────────────────────────────────────────────────────────────────

func affectOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Absent and not-yours are the SAME answer on purpose: distinguishing
		// them tells a caller that a chat exists in another scope.
		return ErrNotFound
	}
	return nil
}

func scanChats(rows *sql.Rows) ([]Chat, error) {
	var out []Chat
	for rows.Next() {
		var c Chat
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.Title, &c.Mode,
			&c.CompactedSummary, &c.PinnedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanChat(row *sql.Row, c *Chat) error {
	err := row.Scan(&c.ID, &c.TenantID, &c.UserID, &c.Title, &c.Mode,
		&c.CompactedSummary, &c.PinnedAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	return err
}
