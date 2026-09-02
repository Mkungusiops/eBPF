package centralstore

import "testing"

// The console must be able to show what a tenant ACTUALLY gets, not what it
// asked for. A control that echoes the request back is how a data-residency
// commitment gets signed against a setting that never took effect.
func TestEffectiveRetentionReportsWhatActuallyHappens(t *testing.T) {
	deploymentEvents := int(defaultRetainEvents.Hours() / 24) // 30
	floor := int(retentionFloor().Hours() / 24)               // 14

	t.Run("unset falls back to the deployment", func(t *testing.T) {
		p := EffectiveRetention(0)
		if p.EffectiveEventDays != deploymentEvents || p.Clamped || p.Ignored {
			t.Fatalf("%+v: an unset tenant should silently follow the deployment", p)
		}
	})

	t.Run("shorter than the deployment takes effect", func(t *testing.T) {
		p := EffectiveRetention(20)
		if p.EffectiveEventDays != 20 {
			t.Fatalf("effective=%d, want the tenant's 20 days", p.EffectiveEventDays)
		}
		if p.Ignored || p.Clamped {
			t.Fatalf("%+v: 20 days is between the floor and the deployment", p)
		}
	})

	t.Run("below the floor is clamped and says so", func(t *testing.T) {
		p := EffectiveRetention(3)
		if !p.Clamped {
			t.Fatal("a 3-day request was not reported as clamped")
		}
		if p.EffectiveEventDays != floor {
			t.Fatalf("effective=%d, want the floor %d", p.EffectiveEventDays, floor)
		}
	})

	t.Run("longer than the deployment is ignored and says so", func(t *testing.T) {
		p := EffectiveRetention(3650)
		if !p.Ignored {
			t.Fatal("a 10-year request was not reported as ignored")
		}
		// The critical assertion: it must NOT claim the tenant gets 10 years.
		if p.EffectiveEventDays != deploymentEvents {
			t.Fatalf("effective=%d, want the deployment's %d — the older rows are already pruned",
				p.EffectiveEventDays, deploymentEvents)
		}
	})
}
