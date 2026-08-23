import { describe, expect, it } from "vitest";
import { DETECTION_TEMPLATES } from "../features/soc/detectionTemplates";
import { preflight, renameInCopy } from "../features/soc/DetectionsBody";

/**
 * The templates promise "this loads as-is". That promise is the entire point of
 * them — an engineer's first push should succeed so the second one can be an
 * edit rather than a debug — so the properties that would break it are pinned
 * here. Only a real push to a real kernel proves the kprobe symbols resolve;
 * these cover the failures that never reach the kernel at all.
 */
describe("detection templates load as-is", () => {
  for (const t of DETECTION_TEMPLATES) {
    describe(t.id, () => {
      it("names itself the same way in the form field and in the YAML", () => {
        // The single most common first-push failure: the console sends `name`
        // as the policy identifier while Tetragon keys on metadata.name, so a
        // mismatch applies a policy the operator cannot then find or remove.
        const meta = t.yaml.match(/^\s*name:\s*"?([^"\n]+)"?\s*$/m);
        expect(meta?.[1], `${t.id} has no metadata.name`).toBe(t.name);
      });

      it("is a TracingPolicy the push endpoint will accept", () => {
        expect(t.yaml).toContain("apiVersion: cilium.io/v1alpha1");
        expect(t.yaml).toContain("kind: TracingPolicy");
        expect(t.yaml).toMatch(/kprobes:/);
        expect(t.yaml).toMatch(/matchActions:\s*\n\s*- action: Post/);
      });

      it("is monitor mode, declaratively", () => {
        // Declarative policy-mode survives a restart; a mode applied any other
        // way does not. The control plane refuses an enforce push outright, so
        // a template that shipped enforcing would be rejected on send — but the
        // reason to pin it is that an enforcing TracingPolicy kills with no
        // audit row, no reversal and no kill-switch.
        expect(t.yaml).toMatch(/name:\s*"policy-mode"\s*\n\s*value:\s*"monitor"/);
      });

      it("carries no enforcing action", () => {
        for (const banned of ["Sigkill", "Override", "NotifyEnforcer", "action: Signal"]) {
          expect(t.yaml, `${t.id} contains ${banned}`).not.toContain(banned);
        }
      });

      it("marks what to change, and says why in the operator's terms", () => {
        // A template with nothing marked is a template nobody knows how to
        // edit — which is the state the blank textarea was already in.
        expect(t.yaml).toContain("CHANGE ME");
        expect(t.editThese.length).toBeGreaterThan(0);
        expect(t.intent.length).toBeGreaterThan(20);
      });
    });
  }

  it("offers distinct ids and names so one cannot overwrite another", () => {
    expect(new Set(DETECTION_TEMPLATES.map((t) => t.id)).size).toBe(DETECTION_TEMPLATES.length);
    expect(new Set(DETECTION_TEMPLATES.map((t) => t.name)).size).toBe(DETECTION_TEMPLATES.length);
  });
});

describe("copying a running policy renames it", () => {
  const body = [
    "apiVersion: cilium.io/v1alpha1",
    "kind: TracingPolicy",
    "metadata:",
    '  name: "sensitive-file-access"',
    "spec:",
    "  options:",
    '    - name: "policy-mode"',
    '      value: "monitor"',
    ""
  ].join("\n");

  it("renames metadata.name and nothing else", () => {
    const out = renameInCopy(body, "sensitive-file-access", "sensitive-file-access-copy");
    expect(out).toContain('name: "sensitive-file-access-copy"');
    // Tetragon keys on metadata.name, so a copy pushed under the original's
    // name REPLACES the live detection instead of adding a variant beside it.
    expect(out).not.toMatch(/name:\s*"sensitive-file-access"/);
    // The options block has a `name:` key too; a looser match rewrote it.
    expect(out).toContain('name: "policy-mode"');
  });

  it("handles an unquoted name", () => {
    const out = renameInCopy("metadata:\n  name: watch-me\n", "watch-me", "watch-me-copy");
    expect(out).toContain('name: "watch-me-copy"');
  });

  it("leaves a body it cannot find the name in untouched", () => {
    const out = renameInCopy(body, "some-other-policy", "x");
    expect(out).toBe(body);
  });
});

describe("pre-flight catches what would fail on the agent", () => {
  const good = DETECTION_TEMPLATES[0];

  it("passes every shipped template unchanged", () => {
    // A template that its own form rejects is worse than no template.
    for (const t of DETECTION_TEMPLATES) {
      const { blocking } = preflight(t.name, t.yaml);
      expect(blocking, `${t.id}: ${blocking.join(" | ")}`).toEqual([]);
    }
  });

  it("says nothing about an empty form", () => {
    expect(preflight("", "")).toEqual({ blocking: [], warnings: [] });
  });

  it("catches the name mismatch, which otherwise fails silently", () => {
    // This one does not error on the agent at all: the policy loads under
    // metadata.name, so the operator's chosen name matches nothing they can
    // later find or remove.
    const { blocking } = preflight("my-policy", good.yaml);
    expect(blocking.join(" ")).toContain("metadata.name");
  });

  it("is not fooled by the name key inside the options block", () => {
    const { blocking } = preflight(good.name, good.yaml);
    expect(blocking.join(" ")).not.toContain("policy-mode");
  });

  it("rejects an enforcing action", () => {
    const armed = good.yaml.replace("- action: Post", "- action: Sigkill");
    expect(preflight(good.name, armed).blocking.join(" ")).toContain("Sigkill");
  });

  it("rejects enforce mode", () => {
    const armed = good.yaml.replace('value: "monitor"', 'value: "enforce"');
    expect(preflight(good.name, armed).blocking.join(" ")).toContain("enforce");
  });

  it("rejects a document that hooks nothing", () => {
    const inert = "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec: {}\n";
    expect(preflight("x", inert).blocking.join(" ")).toContain("hook nothing");
  });

  it("warns without blocking when there is no action", () => {
    const noAction = good.yaml.replace(/\s*matchActions:\s*\n\s*- action: Post\s*$/m, "\n");
    const { blocking, warnings } = preflight(good.name, noAction);
    expect(warnings.join(" ")).toContain("matchActions");
    expect(blocking).toEqual([]);
  });
});
