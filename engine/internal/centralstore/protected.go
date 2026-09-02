package centralstore

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"
)

// Per-tenant guardrails: the binaries and MAC addresses containment must
// always refuse to act on.
//
// The agent floors this with a compiled-in list no signed command can strip,
// so nothing stored here can WEAKEN protection — only widen it. That
// asymmetry is the point: the worst outcome of an enforcement bug is locking
// every operator out of the estate, and a host nobody can log into cannot be
// remediated.
type Protected struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"` // "binary" | "mac"
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

// KindBinary and KindMAC are the only two kinds the table accepts; the CHECK
// constraint says the same thing, so a typo fails here with a readable error
// instead of as a constraint violation from the driver.
const (
	KindBinary = "binary"
	KindMAC    = "mac"
)

// Validate rejects entries that would parse into protection of nothing.
//
// Both failure modes are silent by nature and that is why they are refused
// here: a bare binary name never equals the absolute path the matcher
// compares against, and an unparseable MAC is dropped by the agent. Either
// one leaves an operator believing the uplink is safe while it is not, which
// is worse than having no entry at all.
func (p Protected) Validate() error {
	v := strings.TrimSpace(p.Value)
	switch p.Kind {
	case KindBinary:
		if v == "" {
			return fmt.Errorf("a protected binary needs a path")
		}
		if !strings.HasPrefix(v, "/") {
			return fmt.Errorf("binary must be an absolute path, got %q — matching is exact, "+
				"so a bare name would protect nothing while looking protected", v)
		}
	case KindMAC:
		if _, err := net.ParseMAC(v); err != nil {
			return fmt.Errorf("%q is not a MAC address — an address the agent cannot parse is silently not protected", v)
		}
	default:
		return fmt.Errorf("kind must be %q or %q, got %q", KindBinary, KindMAC, p.Kind)
	}
	if len(strings.TrimSpace(p.Reason)) < 3 {
		return fmt.Errorf("a guardrail needs a reason: it states what this platform will refuse to contain")
	}
	return nil
}

// ProtectedList returns a tenant's guardrails, binaries first then MACs, each
// group sorted — a stable order so the console does not reshuffle on refresh.
func (s *PGStore) ProtectedList(tenant string) ([]Protected, error) {
	if tenant == "" {
		return nil, ErrNoScope
	}
	out := []Protected{}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		rows, err := tx.Query(
			`SELECT id, kind, value, reason, actor, created_at
			 FROM tenant_protected ORDER BY kind, value`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x Protected
			if err := rows.Scan(&x.ID, &x.Kind, &x.Value, &x.Reason, &x.Actor, &x.CreatedAt); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// ReplaceProtected sets a tenant's guardrails to exactly the given set, in one
// transaction, and returns what is now stored.
//
// Replace rather than add-one/remove-one because the console edits this as a
// LIST: the operator sees the estate's protected paths and addresses together,
// and "what should never be touched here" is a single statement, not a stream
// of independent rows. It also makes the dispatch that follows unambiguous —
// the agents receive the whole desired state, which is the only form the
// signed UpdateProtectedList command has.
//
// Every entry is validated BEFORE anything is written, so a single bad MAC
// leaves the stored set untouched rather than half-applied.
func (s *PGStore) ReplaceProtected(tenant string, want []Protected) ([]Protected, error) {
	if tenant == "" {
		return nil, ErrNoScope
	}
	seen := map[string]bool{}
	clean := make([]Protected, 0, len(want))
	for _, p := range want {
		p.Value = strings.TrimSpace(p.Value)
		if err := p.Validate(); err != nil {
			return nil, err
		}
		k := p.Kind + "\x00" + p.Value
		if seen[k] {
			continue
		}
		seen[k] = true
		clean = append(clean, p)
	}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		for _, p := range clean {
			if _, err := tx.Exec(
				`INSERT INTO tenant_protected (tenant_id, kind, value, reason, actor)
				 VALUES ($1,$2,$3,$4,$5)
				 ON CONFLICT (tenant_id, kind, value)
				 DO UPDATE SET reason = EXCLUDED.reason, actor = EXCLUDED.actor`,
				tenant, p.Kind, p.Value, strings.TrimSpace(p.Reason), p.Actor); err != nil {
				return err
			}
		}
		// Delete what is no longer wanted. Scoped by the RLS policy as well as
		// this predicate; the predicate alone would be one refactor away from
		// deleting another tenant's rows.
		rows, err := tx.Query(`SELECT id, kind, value FROM tenant_protected`)
		if err != nil {
			return err
		}
		var stale []int64
		for rows.Next() {
			var id int64
			var kind, value string
			if err := rows.Scan(&id, &kind, &value); err != nil {
				rows.Close()
				return err
			}
			if !seen[kind+"\x00"+value] {
				stale = append(stale, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range stale {
			if _, err := tx.Exec(`DELETE FROM tenant_protected WHERE id = $1`, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.ProtectedList(tenant)
}
