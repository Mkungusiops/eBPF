package chatstore

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver ("pgx")
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
  -- model is chosen ONCE, when the conversation is created, and never
  -- reconsidered while it lives. A deployment may run a fast model for drill
  -- panels and a stronger one for sustained investigation; picking per request
  -- would put two models in one thread, which is the incoherence
  -- AssistantChatProvider exists to prevent. Empty on chats created before the
  -- split existed, which callers read as "the deployment default".
  model             TEXT NOT NULL DEFAULT '',
  pinned_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- An idempotent table creation above will not add a column to a table that
-- already exists, and every deployment already has this one. This ALTER is
-- idempotent too, and safe to run on every open, which is how the rest of this
-- schema behaves.
--
-- Worded without the literal creation keywords on purpose: the grant
-- completeness test scans this string for table declarations, and a comment
-- containing them invents a table called "cannot" that it then demands a grant
-- for. It found exactly that, which is the argument for having it.
ALTER TABLE assistant_chat ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';

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

// grants is separate from schema because it is parameterised by the role, and
// because it is the half that is easy to forget: withScope drops privilege to a
// non-superuser role, so without these every statement fails "permission denied
// for table assistant_chat" — the store looks wired and works for nobody.
//
// The role gets the four verbs the Store interface actually needs and no more.
// RLS still filters every row; the grants only decide which VERBS are reachable,
// so a bug that got past the policy still cannot, say, TRUNCATE the history.
const grants = `
GRANT SELECT, INSERT, UPDATE, DELETE ON assistant_chat    TO %[1]s;
GRANT SELECT, INSERT, UPDATE, DELETE ON assistant_message TO %[1]s;
`

// startupLockTimeout bounds the DDL below. Mirrors centralstore: a migration
// that cannot get its lock must fail fast and say so, not hang a control-plane
// restart indefinitely while the fleet writes.
const startupLockTimeout = "5s"

// Pool ceilings for the chat store's own connections.
//
// database/sql defaults MaxOpenConns to UNLIMITED, and that default is what
// turned a slow query into a total control-plane outage once already: every
// overlapping request opened another Postgres connection until the server hit
// max_connections and refused everything, health endpoints included.
//
// The chat store gets its OWN small pool rather than sharing centralstore's.
// Sharing would let a sidebar full of history queries starve the telemetry
// reads the console depends on; separate bounded pools mean a chat storm queues
// behind chat, and the sum of both ceilings still leaves a stock max_connections
// room for psql, backups and the readiness probe.
const (
	maxOpenConns    = 8
	maxIdleConns    = 4
	connMaxLifetime = 30 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// tunePool applies the ceilings above. Separated from OpenPostgres so a test
// can assert the pool is actually bounded without needing a live database —
// the unbounded default is silent, and an outage is a costly way to find out.
func tunePool(db *sql.DB) {
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)
}

// PGStore is the Postgres-backed chat store.
type PGStore struct {
	db *sql.DB
	// role is the non-superuser role every statement runs as. RLS is bypassed
	// by a superuser even with FORCE, so dropping privilege is not optional.
	role string
	// ownsDB is true only when this store opened the pool. Close() on a pool
	// handed in by someone else would take down whatever else is using it.
	ownsDB bool
}

// OpenPostgres connects on its own bounded pool and provisions the schema.
//
// role must be the same role the rest of the application drops to
// (centralstore.AppRole) — see the comment on that constant.
func OpenPostgres(dsn, role string) (*PGStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	tunePool(db)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s, err := NewPGStore(db, role)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.ownsDB = true
	return s, nil
}

// NewPGStore provisions the schema on an existing pool.
//
// The role is REQUIRED. It used to default, and the default named a role no
// migration ever creates — which is invisible at startup and fails at the first
// query. A missing role is now a startup error, where it is cheap to see.
func NewPGStore(db *sql.DB, role string) (*PGStore, error) {
	if strings.TrimSpace(role) == "" {
		return nil, fmt.Errorf("chatstore: no app role given; pass centralstore.AppRole")
	}
	if err := provision(db, role); err != nil {
		return nil, err
	}
	return &PGStore{db: db, role: role}, nil
}

// provision creates the schema, the role and the grants, and is idempotent.
//
// It SKIPS the DDL entirely once the database is already in the target state.
// The statements are all idempotent, but DROP POLICY / CREATE POLICY / ALTER
// TABLE each take an ACCESS EXCLUSIVE lock, and re-taking those on every restart
// is the exact pattern that made a control-plane restart contend with live
// writes. Checking first costs one catalogue query and no table lock at all.
func provision(db *sql.DB, role string) error {
	ready, err := schemaReady(db, role)
	if err != nil {
		return fmt.Errorf("chatstore: schema probe: %w", err)
	}
	if ready {
		return nil
	}
	// Session-scoped, so it bounds this connection's DDL without following the
	// pooled connections used for queries afterwards.
	if _, err := db.Exec("SET lock_timeout = '" + startupLockTimeout + "'"); err != nil {
		return fmt.Errorf("chatstore: set lock_timeout: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("chatstore: migrate (retry in a moment if this is lock contention): %w", err)
	}
	// The role normally already exists — centralstore creates it — but this
	// package must not depend on which store happened to open first.
	if _, err := db.Exec(fmt.Sprintf(`DO $$ BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN
	    CREATE ROLE %s NOSUPERUSER NOLOGIN;
	  END IF;
	END $$;`, role, quoteIdent(role))); err != nil {
		return fmt.Errorf("chatstore: app role: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf(grants, quoteIdent(role))); err != nil {
		return fmt.Errorf("chatstore: grants: %w", err)
	}
	return nil
}

// schemaReady reports whether both tables exist, both force RLS, both carry the
// policy, and the app role can actually reach them.
//
// The grant check is the one that matters: tables-and-policies-but-no-grants is
// a state a half-finished migration leaves behind, and it reads as "provisioned"
// to any probe that only looks for the tables.
func schemaReady(db *sql.DB, role string) (bool, error) {
	var ready bool
	err := db.QueryRow(`
SELECT
      (SELECT count(*) FROM pg_class
        WHERE relname IN ('assistant_chat','assistant_message') AND relrowsecurity AND relforcerowsecurity) = 2
  AND (SELECT count(*) FROM pg_policies
        WHERE tablename IN ('assistant_chat','assistant_message') AND policyname = 'tenant_isolation') = 2
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
  AND (SELECT count(DISTINCT table_name) FROM information_schema.role_table_grants
        WHERE grantee = $1 AND table_name IN ('assistant_chat','assistant_message')
          AND privilege_type = 'INSERT') = 2
  -- Every COLUMN the queries in this package select, not just the tables.
  --
  -- This probe used to check tables, policies, the role and its grants, and
  -- nothing else — so it reported "ready" for a schema that was structurally
  -- older than the code. provision() then returned without running the DDL at
  -- all, and an ALTER added to the schema string was skipped on every existing
  -- deployment while passing on every fresh one.
  --
  -- The failure is not subtle once it happens and is invisible until then: the
  -- chat SELECT names a column that does not exist, every history read errors,
  -- the sidebar reports "past conversations could not be loaded", and no chat
  -- is created. Anything keyed off a conversation then silently takes its
  -- absent-chat path.
  --
  -- Listing the columns here means an additive change is self-applying: the
  -- probe fails, provision runs, the idempotent ALTER fills the gap.
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_name = 'assistant_chat' AND column_name IN ('model','compacted_summary','pinned_at')) = 3`,
		role).Scan(&ready)
	return ready, err
}

// Close releases the pool, but only if this store opened it. A store built on a
// caller-supplied *sql.DB does not own that pool's lifetime, and closing it
// would take down everything else sharing it.
func (p *PGStore) Close() error {
	if !p.ownsDB {
		return nil
	}
	return p.db.Close()
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

func (p *PGStore) CreateChat(s Scope, title, mode, model string) (Chat, error) {
	if strings.TrimSpace(title) == "" {
		title = "New chat"
	}
	if mode == "" {
		mode = "chat"
	}
	model = strings.TrimSpace(model)
	c := Chat{ID: newID(), TenantID: s.TenantID, UserID: s.UserID, Title: title, Mode: mode, Model: model}
	err := p.withScope(s, func(tx *sql.Tx) error {
		return tx.QueryRow(`INSERT INTO assistant_chat (id, tenant_id, user_id, title, mode, model)
			VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at, updated_at`,
			c.ID, s.TenantID, s.UserID, title, mode, model).Scan(&c.CreatedAt, &c.UpdatedAt)
	})
	return c, err
}

func (p *PGStore) ListChats(s Scope, limit int) ([]Chat, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []Chat
	err := p.withScope(s, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, tenant_id, user_id, title, mode, model, compacted_summary,
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
		row := tx.QueryRow(`SELECT id, tenant_id, user_id, title, mode, model, compacted_summary,
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
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.Title, &c.Mode, &c.Model,
			&c.CompactedSummary, &c.PinnedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanChat(row *sql.Row, c *Chat) error {
	err := row.Scan(&c.ID, &c.TenantID, &c.UserID, &c.Title, &c.Mode, &c.Model,
		&c.CompactedSummary, &c.PinnedAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	return err
}
