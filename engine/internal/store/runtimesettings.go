package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Runtime settings: values an operator changed on a running host, kept so a
// restart does not silently undo them.
//
// # The precedence problem this exists to solve carefully
//
// The choke ladder could be changed at runtime and was read from config at
// startup, so a reboot silently restored the deployed defaults. An operator who
// tightened the ladder during an incident got it loosened again by an
// unattended restart, with nothing saying so.
//
// The obvious fix — "stored value always wins" — trades that for a worse bug.
// A deploy that changes the configured ladder would then be silently ignored
// forever, which is exactly the shape of the stale systemd drop-in that made
// this estate run an eight-day-old command line while every unit file on disk
// said otherwise.
//
// So each override records the CONFIGURED value in force when it was made.
// On startup the two are compared:
//
//   - config unchanged since the override → the override is the later
//     deliberate act, and it wins.
//   - config changed since the override → the deploy is the later deliberate
//     act, it wins, and the superseded override is logged rather than
//     discarded silently.
//
// Last deliberate change wins, and the host can always tell which was later.
type RuntimeSetting struct {
	Key string `json:"key"`
	// Value is what the operator set.
	Value string `json:"value"`
	// ConfigAtSet is the deploy-configured value at the moment of the override.
	// Comparing it to the current configured value is what distinguishes "the
	// deploy has not moved" from "the deploy has since said something else".
	ConfigAtSet string    `json:"config_at_set"`
	Actor       string    `json:"actor"`
	Reason      string    `json:"reason"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const runtimeSettingsSchema = `
CREATE TABLE IF NOT EXISTS runtime_settings (
  key           TEXT PRIMARY KEY,
  value         TEXT NOT NULL,
  config_at_set TEXT NOT NULL DEFAULT '',
  actor         TEXT NOT NULL DEFAULT '',
  reason        TEXT NOT NULL DEFAULT '',
  updated_at    TIMESTAMP NOT NULL
);`

// ErrNoRuntimeSetting reports that a key has never been overridden, which is
// distinct from an override whose value happens to be empty.
var ErrNoRuntimeSetting = errors.New("store: no runtime override for that key")

// PutRuntimeSetting records an operator's override of a configured value.
func (s *Store) PutRuntimeSetting(rs RuntimeSetting) error {
	if strings.TrimSpace(rs.Key) == "" {
		return errors.New("store: a runtime setting needs a key")
	}
	if rs.UpdatedAt.IsZero() {
		rs.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(rewriteParams(s.dialect, `
		INSERT INTO runtime_settings (key, value, config_at_set, actor, reason, updated_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET
		  value = excluded.value, config_at_set = excluded.config_at_set,
		  actor = excluded.actor, reason = excluded.reason, updated_at = excluded.updated_at`),
		rs.Key, rs.Value, rs.ConfigAtSet, rs.Actor, strings.TrimSpace(rs.Reason), rs.UpdatedAt)
	return err
}

// RuntimeSettingFor reads one override.
func (s *Store) RuntimeSettingFor(key string) (RuntimeSetting, error) {
	var rs RuntimeSetting
	row := s.db.QueryRow(rewriteParams(s.dialect,
		`SELECT key, value, config_at_set, actor, reason, updated_at FROM runtime_settings WHERE key = ?`), key)
	switch err := row.Scan(&rs.Key, &rs.Value, &rs.ConfigAtSet, &rs.Actor, &rs.Reason, &rs.UpdatedAt); {
	case errors.Is(err, sql.ErrNoRows):
		return rs, ErrNoRuntimeSetting
	case err != nil:
		return rs, err
	}
	return rs, nil
}

// EffectiveRuntimeSetting resolves an override against the currently configured
// value, and explains which won.
//
// Returns the value to use, and a human-readable note when the answer is not
// simply "the configured value" — so the caller can log it. A superseded
// override is reported rather than dropped in silence: an operator who set
// something during an incident is owed the sentence explaining why it is no
// longer in force.
func (s *Store) EffectiveRuntimeSetting(key, configured string) (string, string) {
	rs, err := s.RuntimeSettingFor(key)
	if err != nil {
		return configured, "" // never overridden, or unreadable: config stands
	}
	if rs.ConfigAtSet != configured {
		return configured, "an operator override (" + rs.Value + ", set by " +
			actorOrUnknown(rs.Actor) + ") is superseded: the deployed value changed from " +
			rs.ConfigAtSet + " to " + configured + " after it was set"
	}
	if rs.Value == configured {
		return configured, ""
	}
	return rs.Value, "using the operator override " + rs.Value + " set by " +
		actorOrUnknown(rs.Actor) + " (deployed value " + configured + " is unchanged since)"
}

// actorOrUnknown names who set an override, without inventing an answer.
//
// An empty actor is genuinely ambiguous here: a preset can move the ladder with
// no operator behind it, and the agent's applier interface does not carry the
// operator through from a signed command. "the platform" would resolve that
// ambiguity by asserting the more comfortable of the two, and the audit chain
// — which DOES record the operator on every config change — would contradict
// it. Saying the origin was not recorded is the only claim this value supports.
func actorOrUnknown(a string) string {
	if strings.TrimSpace(a) == "" {
		return "an unrecorded origin"
	}
	return a
}
