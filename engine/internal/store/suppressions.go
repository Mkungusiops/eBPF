package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Operator suppressions: "this behaviour is expected on OUR estate".
//
// # Why this exists and why it is shaped this way
//
// Every estate has legitimate activity that scores. Safaricom's backup agent
// reading credential paths, a config-management tool calling setuid on a
// schedule — real behaviour that is malicious somewhere and routine here. With
// no way to say so, a customer has two options: live with the noise, or turn
// enforcement off. They pick the second, and the platform stops protecting
// them.
//
// The engine already suppresses two such patterns, in Go: the auth stack
// reading credentials (score.IsAuthStackCredentialRead) and routine privilege
// transitions (score.IsRoutinePrivilegeTransition). Those are hardcoded because
// they are universal. This is the same idea for the patterns that are true of
// ONE customer.
//
// # Additive-only in effect, which is the safety property
//
// A suppression can only ever REDUCE a score. It cannot raise one, cannot
// create a rung, cannot widen what the platform acts on. That asymmetry is why
// this is safe to expose in a console while scoring WEIGHTS are not: a bad
// suppression costs a missed detection — bounded, and visible as a coverage
// gap. A bad weight could push everything past the sever threshold, which is
// the same failure class as an unvalidated threshold ladder.
//
// # What a suppression is NOT
//
// It is not an allow-list for containment. A suppressed chain still appears in
// events, still appears in the process tree, and a suppressed binary can still
// be jailed by hand. It only stops the behaviour from ADDING TO A SCORE, which
// is the thing that drives automatic action.
type Suppression struct {
	ID        int64     `json:"id"`
	Binary    string    `json:"binary"`
	Policy    string    `json:"policy,omitempty"`
	Parent    string    `json:"parent,omitempty"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
	// Hits counts how often this suppression has actually fired. A rule that
	// never matches is either wrong or obsolete, and an operator cannot tell
	// those apart without a number. Advisory: not chained, not durable across
	// a restart.
	Hits int64 `json:"hits"`
}

// Match reports whether this suppression covers an observation.
//
// Binary is required and matched exactly — a prefix or glob here would be a
// way to silence half the estate with one typo, and the whole point is that
// the blast radius of a mistake stays small. Policy and Parent are optional
// narrowing: empty means "any".
func (s Suppression) Match(binary, policy, parent string) bool {
	if s.Binary != binary {
		return false
	}
	if s.Policy != "" && s.Policy != policy {
		return false
	}
	if s.Parent != "" && s.Parent != parent {
		return false
	}
	return true
}

func (s Suppression) validate() error {
	if strings.TrimSpace(s.Binary) == "" {
		return fmt.Errorf("a suppression needs a binary path")
	}
	if !strings.HasPrefix(s.Binary, "/") {
		return fmt.Errorf("binary must be an absolute path, got %q — matching is exact, "+
			"so a bare name would never fire and would look like a working rule", s.Binary)
	}
	if len(strings.TrimSpace(s.Reason)) < 3 {
		return fmt.Errorf("a suppression needs a reason: it is a deliberate reduction in what this platform detects")
	}
	return nil
}

const suppressionSchema = `
CREATE TABLE IF NOT EXISTS suppressions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	binary     TEXT NOT NULL,
	policy     TEXT NOT NULL DEFAULT '',
	parent     TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL,
	UNIQUE(binary, policy, parent)
);`

// AddSuppression stores one. The UNIQUE constraint makes re-adding the same
// rule a no-op rather than a duplicate that would have to be deleted twice.
func (s *Store) AddSuppression(sup *Suppression) (int64, error) {
	if err := sup.validate(); err != nil {
		return 0, err
	}
	if sup.CreatedAt.IsZero() {
		sup.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.Exec(
		`INSERT OR REPLACE INTO suppressions (binary, policy, parent, reason, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sup.Binary, sup.Policy, sup.Parent, strings.TrimSpace(sup.Reason), sup.Actor, sup.CreatedAt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	sup.ID = id
	return id, nil
}

// Suppressions lists them, newest first.
func (s *Store) Suppressions() ([]Suppression, error) {
	rows, err := s.db.Query(
		`SELECT id, binary, policy, parent, reason, actor, created_at
		 FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Suppression{}
	for rows.Next() {
		var x Suppression
		if err := rows.Scan(&x.ID, &x.Binary, &x.Policy, &x.Parent, &x.Reason, &x.Actor, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// DeleteSuppression removes one. Returns whether a row actually went away, so
// the caller can tell "removed" from "was not there" rather than reporting
// success for a no-op.
func (s *Store) DeleteSuppression(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM suppressions WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

var _ = sql.ErrNoRows

// SuppressionCandidate is a binary that is generating findings, offered to the
// operator as something they might recognise as expected.
//
// # Why this exists
//
// A settings page that opens on an empty form asking for an absolute binary
// path is unusable by the person who needs it. An analyst does not arrive
// knowing which path to type — they arrive knowing that something is noisy.
// The platform already holds the answer: it recorded every scored event and
// which binary produced it.
//
// So the page leads with "these produced most of your findings this week — are
// any of them expected here?", which is a question a SOC analyst can answer,
// rather than a text field, which is not.
type SuppressionCandidate struct {
	Binary string `json:"binary"`
	Policy string `json:"policy,omitempty"`
	Events int    `json:"events"`
	// Suppressed marks a candidate an operator has already silenced, so the
	// list does not keep offering the same one and imply nothing was done.
	Suppressed bool `json:"suppressed"`
}

// SuppressionCandidates ranks the binaries producing the most scored activity
// in the window — the set actually worth reviewing.
//
// Ranked by EVENT VOLUME per (binary, detection), because that is what the
// schema can answer: events carry the binary and the policy, and score lives
// on the alert, which carries an exec_id rather than a binary. An earlier
// version claimed to rank by score and queried a column that does not exist;
// the query errored, the error was swallowed, and the page rendered "nothing
// noisy here" on a host producing thousands of findings. Volume is the honest
// measure available, and the UI says volume rather than implying severity.
//
// Only rows with a policy_name are offered. Those are the kprobe detections an
// operator recognises by name; a bare exec with no detection attached is not
// something anyone would think to suppress.
func (s *Store) SuppressionCandidates(since time.Time, limit int) ([]SuppressionCandidate, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.Query(`
		SELECT "binary", COALESCE(policy_name, ''), COUNT(*)
		FROM events
		WHERE timestamp >= ? AND "binary" != '' AND COALESCE(policy_name, '') != ''
		GROUP BY "binary", policy_name
		ORDER BY COUNT(*) DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SuppressionCandidate{}
	for rows.Next() {
		var c SuppressionCandidate
		if err := rows.Scan(&c.Binary, &c.Policy, &c.Events); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Mark the ones already handled. Re-offering a binary an operator has
	// already suppressed makes the list look like nothing happened.
	existing, err := s.Suppressions()
	if err != nil {
		return out, nil // advisory only; a failure here must not empty the list
	}
	for i := range out {
		for _, sup := range existing {
			if sup.Match(out[i].Binary, out[i].Policy, "") {
				out[i].Suppressed = true
				break
			}
		}
	}
	return out, nil
}
