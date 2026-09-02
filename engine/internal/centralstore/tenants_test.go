package centralstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tenants was the third dead table from migration 0001, and not merely unused:
// agents has a foreign key onto it, so the agent roster could not be written
// at all until tenants existed. That surfaced as a constraint violation on
// every heartbeat once the roster started writing.

func TestRetentionOverrideOnlyShortens(t *testing.T) {
	// A tenant asking to keep data LONGER than the deployment does would need
	// rows the global pass has already deleted. Accepting it would be a
	// promise the platform cannot keep, and a retention policy that silently
	// fails is worse than one that is refused.
	deployment := defaultRetainEvents
	for _, tc := range []struct {
		name    string
		days    int
		applies bool
	}{
		{"shorter than the deployment", 7, true},
		{"longer than the deployment", 365, false},
		{"equal to the deployment", int(defaultRetainEvents.Hours() / 24), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := hoursToDuration(tc.days)
			if floor := retentionFloor(); h < floor {
				h = floor
			}
			shortens := h < deployment
			if shortens != tc.applies {
				t.Fatalf("%d days: applies=%v, want %v", tc.days, shortens, tc.applies)
			}
		})
	}
}

func TestATenantRetentionBelowTheFloorIsClamped(t *testing.T) {
	// Below twice the largest console window, every window-over-window delta
	// the console renders is computed against data that no longer exists —
	// trading a visible disk problem for an invisible correctness one.
	h := hoursToDuration(1) // one day
	floor := retentionFloor()
	if h >= floor {
		t.Skip("floor is under a day on this build")
	}
	if got := clampToFloor(h); got != floor {
		t.Fatalf("clamped to %v, want the floor %v", got, floor)
	}
}

// migration 0009 exists because "no tenant choice" was unrepresentable: the
// column was NOT NULL DEFAULT 90 CHECK (> 0). Two defects followed on the
// first live deployment, and both are pinned here at the resolution layer
// because that is where the false alarm was rendered.
func TestTheSchemaDefaultIsNotReportedAsATenantChoice(t *testing.T) {
	// 0 is what RetentionDaysFor returns for a NULL column. It must resolve to
	// the deployment default with NO complaint attached — before 0009 every
	// tenant carried a 90 nobody chose, and the console reported "this setting
	// is not doing what it says" on all of them.
	p := EffectiveRetention(0)
	if p.Ignored || p.Clamped {
		t.Fatalf("%+v: an unset tenant must resolve silently to the deployment default", p)
	}
	if p.TenantDays != 0 {
		t.Fatalf("TenantDays=%d, want 0 for unset", p.TenantDays)
	}
}

// The migration must be present and must make the column nullable — the API
// documents 0 as "clear", and against the 0001 CHECK that was a constraint
// violation dressed up as a control.
func TestMigrationMakesRetentionNullable(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "migrations", "postgres", "0009_retention_unset.sql"))
	if err != nil {
		t.Fatalf("migration 0009 is missing: %v", err)
	}
	sql := strings.ToUpper(string(raw))
	for _, want := range []string{"DROP NOT NULL", "DROP DEFAULT", "IS NULL OR RETENTION_DAYS > 0"} {
		if !strings.Contains(sql, want) {
			t.Errorf("0009 does not %q — unset stays unrepresentable", want)
		}
	}
}
