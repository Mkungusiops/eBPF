package centralstore

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every table and column the schema declares must be named by some Go code.
//
// # The defect this exists to catch
//
// Three separate times, a migration created something and no code ever touched
// it, and each time the gap was invisible until someone went looking:
//
//	agents           the roster the console read from memory, so a restart
//	                 erased which hosts had ever reported
//	operator_audit   "which operator read which customer's data" had no answer
//	                 at all on an MSSP control plane
//	tenants          worse than unused — agents has a foreign key onto it, so
//	                 the roster could not be written until it was populated
//
// And one column: tenants.retention_days, which meant a customer contractually
// held to 14 days could have 14 stored in the platform and keep 30.
//
// The common shape is not "unused code". It is a SCHEMA MAKING A PROMISE THE
// CODE DOES NOT KEEP. A reviewer reading the migration sees a per-tenant
// retention control; a reviewer reading the code sees none; nobody reads both.
//
// # Why a test and not a startup check
//
// A startup check logs into a void on a box nobody is watching, and cannot tell
// a legitimately empty table on a fresh deployment from a dead one. This fails
// in CI, before the schema ships, which is the only point where the answer is
// unambiguous.
//
// # Adding something deliberately unused
//
// Put it in the exception map below with the reason. That makes the decision
// explicit and reviewable, which is exactly what the three dead tables never got.
var schemaKnownUnused = map[string]string{
	// table.column -> why it is legitimately unread by Go.
	"schema_migrations.version":    "the migration runner's own bookkeeping, applied by scripts/migrate.sh",
	"schema_migrations.checksum":   "as above",
	"schema_migrations.applied_at": "as above",
	"telemetry.rowid":              "postgres exposes ctid; rowid is the sqlite spelling used in the shared prune",
}

var (
	reCreateTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\((.*?)\n\s*\);`)
	reAddColumn   = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	reColumnLine  = regexp.MustCompile(`^\s*([a-z_][a-z0-9_]*)\s+[a-z]`)
)

// sqlNonColumns are the constraint keywords that begin a line inside a
// CREATE TABLE body and are not column names.
var sqlNonColumns = map[string]bool{
	"primary": true, "foreign": true, "unique": true, "check": true,
	"constraint": true, "exclude": true, "like": true,
}

func TestSchemaDeclaresNothingTheCodeIgnores(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "scripts", "migrations", "postgres")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("migrations not readable from here: %v", err)
	}

	// table -> set of columns
	schema := map[string]map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sql := string(raw)
		for _, m := range reCreateTable.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(m[1])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			for _, line := range strings.Split(m[2], "\n") {
				if i := strings.Index(line, "--"); i >= 0 {
					line = line[:i]
				}
				cm := reColumnLine.FindStringSubmatch(line)
				if cm == nil {
					continue
				}
				col := strings.ToLower(cm[1])
				if sqlNonColumns[col] {
					continue
				}
				schema[table][col] = true
			}
		}
		for _, m := range reAddColumn.FindAllStringSubmatch(sql, -1) {
			table, col := strings.ToLower(m[1]), strings.ToLower(m[2])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			schema[table][col] = true
		}
	}
	if len(schema) == 0 {
		t.Fatal("parsed no tables from the migrations — the parser, not the schema, is broken")
	}

	code := goSources(t, root)

	var deadTables, deadColumns []string
	for table, cols := range schema {
		if !strings.Contains(code, table) {
			deadTables = append(deadTables, table)
			continue // its columns cannot be referenced either
		}
		for col := range cols {
			if schemaKnownUnused[table+"."+col] != "" {
				continue
			}
			if !strings.Contains(code, col) {
				deadColumns = append(deadColumns, table+"."+col)
			}
		}
	}

	if len(deadTables) > 0 {
		t.Errorf("the schema creates %d table(s) no Go code names: %v\n"+
			"A table nothing reads is a promise the schema makes and the code does not keep. "+
			"Either wire it up or record it in schemaKnownUnused with the reason.", len(deadTables), deadTables)
	}
	if len(deadColumns) > 0 {
		t.Errorf("the schema declares %d column(s) no Go code names: %v\n"+
			"tenants.retention_days was exactly this: a data-residency control that existed "+
			"in the schema and did nothing.", len(deadColumns), deadColumns)
	}
}

// repoRoot walks up until it finds the migrations directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "scripts", "migrations")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repo root not found from the test's working directory")
	return ""
}

// goSources concatenates every .go file under the engine, so a table or column
// referenced anywhere — including in a query built by another package — counts.
func goSources(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(filepath.Join(root, "engine"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// The schema-coverage test itself names every table, which would make
		// the check pass trivially.
		if strings.HasSuffix(path, "schemacoverage_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		b.Write(raw)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		t.Skip("no Go sources found from the test's working directory")
	}
	return strings.ToLower(b.String())
}
