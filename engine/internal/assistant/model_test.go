package assistant

import "testing"

// A deployment may answer drill panels from a fast model and sustained sidebar
// conversations from a stronger one. These pin the two properties that keep
// that from becoming a mess: a single-model deployment cannot accidentally
// acquire a second one, and a model id that came out of a database is never
// trusted straight onto the wire.

func TestOneModelDeploymentNeverSplits(t *testing.T) {
	// The default. If ModelFor(true) could differ here, every existing
	// deployment would silently start answering the sidebar from something
	// nobody configured.
	c := Config{Model: "gpt-oss:120b"}
	if got := c.ModelFor(false); got != "gpt-oss:120b" {
		t.Fatalf("panel model = %q", got)
	}
	if got := c.ModelFor(true); got != "gpt-oss:120b" {
		t.Fatalf("with no DeepModel the sidebar must use the only model, got %q", got)
	}
}

func TestTwoModelDeploymentSplitsByDepth(t *testing.T) {
	c := Config{Model: "fast", DeepModel: "deep"}
	if got := c.ModelFor(false); got != "fast" {
		t.Fatalf("panel model = %q, want fast", got)
	}
	if got := c.ModelFor(true); got != "deep" {
		t.Fatalf("sidebar model = %q, want deep", got)
	}
}

func TestOnlyConfiguredModelsAreRecognised(t *testing.T) {
	// A conversation carries the model it was created with, and that value
	// comes back out of Postgres. A retired model, a bad migration or an
	// edited row must not become a request against something nobody
	// configured.
	c := Config{Model: "fast", DeepModel: "deep"}
	for _, ok := range []string{"fast", "deep", " deep "} {
		if !c.KnownModel(ok) {
			t.Fatalf("KnownModel(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "  ", "retired-model", "fast-v2", "../../etc/passwd"} {
		if c.KnownModel(bad) {
			t.Fatalf("KnownModel(%q) = true — an unconfigured id would reach the endpoint", bad)
		}
	}
}

func TestWithModelReturnsACopy(t *testing.T) {
	// Two concurrent requests resolve different models. A provider holding a
	// mutable model field would race them into each other's answer, so
	// WithModel must not touch the shared config.
	base := Config{BaseURL: "https://x/v1", Model: "fast", DeepModel: "deep"}
	pinned := base.WithModel("deep")

	if base.Model != "fast" {
		t.Fatalf("WithModel mutated the shared config: Model = %q", base.Model)
	}
	if pinned.Model != "deep" {
		t.Fatalf("pinned copy = %q, want deep", pinned.Model)
	}
	if pinned.BaseURL != base.BaseURL || pinned.DeepModel != base.DeepModel {
		t.Fatal("WithModel dropped the rest of the configuration")
	}
	// An empty id is a no-op rather than an unconfigured provider.
	if got := base.WithModel("").Model; got != "fast" {
		t.Fatalf("WithModel(\"\") = %q, want the original", got)
	}
}

func TestProviderNameReportsTheModelThatAnswered(t *testing.T) {
	// Name() flows into the answer's provenance. With two models configured, a
	// name taken from the deployment default would misattribute half the
	// traffic in exactly the record a reviewer consults.
	cfg := Config{BaseURL: "https://x/v1", Model: "fast", DeepModel: "deep"}
	if got := NewOpenAICompatible(cfg.WithModel("deep"), nil).Name(); got != "openai-compatible:deep" {
		t.Fatalf("Name() = %q, want the pinned model", got)
	}
}
