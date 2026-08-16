package chatstore

import (
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests exist because the store was written, reviewed and committed in a
// state where it could not have served a single request in production. None of
// the failures were visible in Go: they were all "the SQL is fine, the database
// says no". Each test below pins one of them.

// tablesInSchema derives the table list from the schema itself rather than
// hardcoding it, so a table added later is covered without anyone remembering
// to update a list.
func tablesInSchema(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`(?i)CREATE TABLE IF NOT EXISTS\s+(\w+)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(schema, -1) {
		out = append(out, m[1])
	}
	// Guard the guard. A regex that silently matches nothing makes every test
	// below vacuously green — which is exactly how a completeness check in this
	// repo passed while parsing zero entries.
	if len(out) < 2 {
		t.Fatalf("parsed %d tables from the schema (%v); the regex has stopped matching "+
			"and every check derived from it is now vacuous", len(out), out)
	}
	sort.Strings(out)
	return out
}

func TestEveryTableGrantsToTheAppRole(t *testing.T) {
	// THE BUG THIS PINS: the schema created both tables, enabled and forced RLS
	// on them, and granted nothing. withScope drops privilege to a non-superuser
	// role before every statement, so each one would have failed "permission
	// denied for table assistant_chat". The store compiles, its unit tests pass,
	// and it serves no one.
	got := fmt.Sprintf(grants, quoteIdent("some_role"))
	for _, table := range tablesInSchema(t) {
		if !strings.Contains(got, table) {
			t.Errorf("table %s is created by the schema but never granted to the app role; "+
				"every statement against it will fail permission denied under SET ROLE", table)
		}
	}
	// The Store interface reads, writes, updates and deletes. A missing verb
	// fails only on the one operation that uses it — the kind of gap that ships.
	for _, verb := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if !strings.Contains(got, verb) {
			t.Errorf("grants omit %s, but the Store interface needs it", verb)
		}
	}
}

func TestGrantsGoToTheSameRoleWithScopeSetsTo(t *testing.T) {
	// THE BUG THIS PINS: NewPGStore defaulted to "ebpf_soc_app" while every
	// migration in the codebase creates "ebpf_app". SET LOCAL ROLE would have
	// failed on a role that does not exist. The two must be one value.
	const role = "role_under_test"
	p := &PGStore{role: role}
	got := fmt.Sprintf(grants, quoteIdent(p.role))
	if !strings.Contains(got, quoteIdent(role)) {
		t.Fatalf("grants do not name the role withScope sets (%q)", role)
	}
	// And there must be no OTHER role named anywhere in the provisioning SQL —
	// a second spelling is how the two drift apart again.
	for _, stray := range regexp.MustCompile(`ebpf\w*`).FindAllString(grants+schema, -1) {
		t.Errorf("provisioning SQL hardcodes a role/identifier %q; the role must come "+
			"from the caller (centralstore.AppRole) so there is one source of truth", stray)
	}
}

func TestEmptyRoleIsRefusedRatherThanDefaulted(t *testing.T) {
	// A default role is worse than no role: it names something plausible, starts
	// cleanly, and fails at the first query in production. Fail at startup.
	for _, role := range []string{"", "   "} {
		func() {
			// The nil pool is the assertion: a correct NewPGStore rejects the
			// role BEFORE it touches the database. Reaching the db at all —
			// which is what a reinstated default would do — is the failure, and
			// recovering keeps the message accurate instead of a bare panic.
			defer func() {
				if recover() != nil {
					t.Errorf("NewPGStore(role=%q) went on to use the database; a missing "+
						"role must be refused at startup, not defaulted to a role no "+
						"migration creates", role)
				}
			}()
			if _, err := NewPGStore(nil, role); err == nil {
				t.Errorf("NewPGStore accepted role %q; a missing role must be a startup error", role)
			}
		}()
	}
}

func TestPoolIsBounded(t *testing.T) {
	// THE BUG THIS PINS: database/sql defaults MaxOpenConns to unlimited, and
	// that default already caused one total control-plane outage — every
	// overlapping read opened another connection until Postgres hit
	// max_connections and refused everything, health endpoints included.
	//
	// sql.Open does not connect, so this needs no database.
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if n := db.Stats().MaxOpenConnections; n != 0 {
		t.Fatalf("a fresh pool reports MaxOpenConnections=%d; this test can no longer "+
			"tell tuned from untuned", n)
	}
	tunePool(db)
	n := db.Stats().MaxOpenConnections
	if n <= 0 {
		t.Fatal("the chat pool is unbounded; overload will exhaust max_connections " +
			"and take down every endpoint, not just chat")
	}
	// Leave headroom under a stock max_connections of 100: centralstore has its
	// own pool, and psql/backups/the readiness probe must still get in.
	if n > 25 {
		t.Errorf("chat pool ceiling is %d, too large a share of a stock max_connections", n)
	}
}

func TestCloseDoesNotCloseAPoolItDoesNotOwn(t *testing.T) {
	// A store built on a caller-supplied *sql.DB must not close it: that pool
	// may be serving the rest of the process.
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	p := &PGStore{db: db, role: "r"} // ownsDB false — the borrowed case
	if err := p.Close(); err != nil {
		t.Fatalf("Close on a borrowed pool: %v", err)
	}
	if err := db.PingContext(t.Context()); err == nil {
		t.Skip("no database here; the point is only that the pool was not closed")
	} else if strings.Contains(err.Error(), "closed") {
		t.Error("Close() closed a pool the store does not own")
	}
}
