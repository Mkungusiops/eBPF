// Command socbackup takes a consistent, compressed snapshot of the engine's
// SQLite database while the engine is still running.
//
// Why not `cp`: internal/store opens events.db with journal_mode(WAL), and the
// engine holds it open continuously. Copying the file (plus its -wal/-shm
// sidecars) while a writer is active can capture a torn page set. SQLite's
// VACUUM INTO instead takes a read snapshot and writes a fully-formed database
// file — safe against the live writer, and it compacts the result as a bonus.
//
// Deployed on the live box as /usr/local/bin/socbackup and driven nightly by
// ebpf-soc-backup.timer. Exits non-zero on any failure so systemd records it.
package main

import (
	"compress/gzip"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	var (
		dbPath = flag.String("db", "/home/azureuser/ebpf-poc/events.db", "path to the live SQLite database")
		dest   = flag.String("dest", "/var/backups/ebpf-soc", "directory to write snapshots into")
		keep   = flag.Int("keep", 3, "number of compressed snapshots to retain")
	)
	flag.Parse()

	if err := os.MkdirAll(*dest, 0o700); err != nil {
		log.Fatalf("socbackup: mkdir %s: %v", *dest, err)
	}

	ts := time.Now().UTC().Format("20060102-150405")
	snap := filepath.Join(*dest, "events-"+ts+".db")

	if err := snapshot(*dbPath, snap); err != nil {
		log.Fatalf("socbackup: %v", err)
	}
	if err := verify(snap); err != nil {
		_ = os.Remove(snap)
		log.Fatalf("socbackup: snapshot failed verification (discarded): %v", err)
	}

	gzPath, err := compress(snap)
	if err != nil {
		log.Fatalf("socbackup: compress: %v", err)
	}
	_ = os.Remove(snap) // keep only the compressed copy

	if err := prune(*dest, *keep); err != nil {
		log.Printf("socbackup: prune: %v", err) // non-fatal: the snapshot is already safe
	}

	fi, err := os.Stat(gzPath)
	if err != nil {
		log.Fatalf("socbackup: stat %s: %v", gzPath, err)
	}
	log.Printf("socbackup: ok %s (%.1f MiB, retaining %d)", gzPath, float64(fi.Size())/(1<<20), *keep)
}

// snapshot runs VACUUM INTO against the live database. The destination must not
// already exist (SQLite refuses to overwrite), which the timestamped name
// guarantees.
func snapshot(dbPath, dest string) error {
	dsn := dbPath + "?_pragma=busy_timeout(60000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open %s: %w", dbPath, err)
	}
	defer db.Close()

	// The path is ours (timestamped, under -dest), but quote defensively so a
	// path containing a quote can't break out of the string literal.
	lit := "'" + strings.ReplaceAll(dest, "'", "''") + "'"
	if _, err := db.Exec("VACUUM INTO " + lit); err != nil {
		return fmt.Errorf("VACUUM INTO %s: %w", dest, err)
	}
	return nil
}

// verify re-opens the snapshot and confirms it is a readable database with a
// populated schema — cheap insurance against shipping a corrupt backup.
func verify(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()

	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		return fmt.Errorf("snapshot contains no tables")
	}
	return nil
}

func compress(path string) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.OpenFile(path+".gz", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return out.Name(), nil
}

// prune keeps the newest `keep` snapshots. Names are UTC-timestamped, so a
// lexical sort is chronological.
func prune(dir string, keep int) error {
	matches, err := filepath.Glob(filepath.Join(dir, "events-*.db.gz"))
	if err != nil {
		return err
	}
	if len(matches) <= keep {
		return nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, old := range matches[keep:] {
		if err := os.Remove(old); err != nil {
			return err
		}
	}
	return nil
}
