package policyassets

import "testing"

// The staged bodies must be findable under the name everything else uses — the
// policy's metadata.name, which is what telemetry rows, the kernel and the
// console all key on. A build that stages the files but indexes them under the
// wrong key serves no bodies at all, and does it silently.
func TestShippedPoliciesIndexedByMetadataName(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Skip("no policies staged: this is a plain `go build` tree, not a `make` one")
	}
	for _, want := range []string{"sensitive-file-access", "outbound-connections", "privilege-escalation"} {
		body, ok := Lookup(want)
		if !ok {
			t.Errorf("policy %q not indexed; have %v", want, names)
			continue
		}
		if len(body) == 0 {
			t.Errorf("policy %q indexed with an empty body", want)
		}
	}
}

// metadataName has one job that a naive YAML walk gets wrong: `name:` appears
// several times in a TracingPolicy, and only the one under metadata is the
// policy's name. These cases are the ones that actually bit.
func TestMetadataNameIgnoresOtherNameKeys(t *testing.T) {
	cases := []struct{ label, body, want string }{
		{
			label: "options block also has a name key",
			body: "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"real-name\"\nspec:\n  options:\n    - name: \"policy-mode\"\n      value: \"monitor\"\n",
			want: "real-name",
		},
		{
			label: "spec comes first",
			body: "spec:\n  options:\n    - name: \"policy-mode\"\nmetadata:\n  name: real-name\n",
			want: "real-name",
		},
		{
			label: "unquoted with a trailing comment line above",
			body: "metadata:\n  # CHANGE ME\n  name: real-name\n",
			want: "real-name",
		},
		{
			label: "no metadata block at all",
			body:  "spec:\n  options:\n    - name: \"policy-mode\"\n",
			want:  "",
		},
	}
	for _, c := range cases {
		if got := metadataName(c.body); got != c.want {
			t.Errorf("%s: metadataName = %q, want %q", c.label, got, c.want)
		}
	}
}
