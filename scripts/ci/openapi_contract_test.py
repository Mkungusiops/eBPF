#!/usr/bin/env python3
"""Tests for scripts/ci/gen-openapi.py — the published API contract.

docs/api/openapi.yaml is what an integrating team builds against, so a wrong
entry in it is worse than a missing one: nobody codes against a gap, everybody
codes against a lie. Two shipped, and both came from the generator rather than
from the handlers:

  * `targets` — a []string naming the hosts a fleet write may reach — was
    published as `type: string` on twelve write endpoints, because the type
    mapper tested for a "[]" prefix on a Go type declared `*[]string` and fell
    through to a silent "string" default. Following the spec meant sending
    "targets":"bravo" and being refused by the handler.

  * the five fleet write paths listed 200/401/404 and nothing else, though an
    empty target list and an unknown host name are both 400s with an
    {error, unknown[]} body. Three of the five also lost the doc comment that
    states the targeting rule, because two surfaces serve those paths and only
    the first handler's prose was emitted.

Run:  python3 scripts/ci/openapi_contract_test.py
      (or via pytest / `python3 -m unittest discover -s scripts/ci -p '*_test.py'`)
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

_spec = importlib.util.spec_from_file_location("gen_openapi", HERE / "gen-openapi.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# The five fleet WRITE paths. Every one of them refuses an empty target list
# and an unknown host name with a 400, and every one of them must say so.
FLEET_WRITES = [
    "/api/fleet/preset",
    "/api/fleet/thresholds",
    "/api/fleet/kill-switch",
    "/api/fleet/thaw",
    "/api/fleet/device-jail",
]


def path_block(doc: str, path: str) -> str:
    """The YAML under one path key, up to the next path key."""
    start = doc.find('\n  "' + path + '":\n')
    if start < 0:
        return ""
    rest = doc[start + 1:]
    nxt = rest[1:].find('\n  "/')
    return rest[:nxt + 1] if nxt >= 0 else rest


def collapsed(s: str) -> str:
    """Descriptions are re-wrapped at 74 columns, so a phrase straddles lines."""
    return " ".join(s.split())


class TypeMapping(unittest.TestCase):
    def test_pointer_to_slice_is_a_slice(self):
        # `Targets *[]string`. The pointer only distinguishes absent from [],
        # which is nullability, not type — and the difference between an
        # estate-wide write and a refusal, so it is never dropped in the code.
        self.assertEqual(
            gen.go_schema("*[]string", "t"),
            {"type": "array", "items": {"type": "string"}},
        )
        self.assertEqual(
            gen.go_schema("[]string", "t"),
            {"type": "array", "items": {"type": "string"}},
        )
        self.assertEqual(gen.go_schema("*bool", "t"), {"type": "boolean"})
        self.assertEqual(
            gen.go_schema("*[]uint32", "t"),
            {"type": "array", "items": {"type": "integer", "format": "int32"}},
        )

    def test_an_unknown_go_type_is_loud(self):
        gen.PROBLEMS.clear()
        try:
            gen.go_schema("map[string]badger", "handleX.field")
            self.assertTrue(gen.PROBLEMS, "an unrecognised Go type was silently "
                                          "mapped; that is how []string shipped as string")
            self.assertIn("handleX.field", gen.PROBLEMS[0])
        finally:
            gen.PROBLEMS.clear()

    def test_a_count_is_not_a_boolean(self):
        # `"ok": out.applied > 0` next to `"applied": out.applied` set a rule
        # that published the count of hosts reached as a boolean.
        self.assertEqual(gen._value_type("out.applied > 0", {}), "boolean")
        self.assertEqual(gen._value_type("out.applied", {}), "integer")
        # Nothing in the source settles this one, so nothing is published.
        self.assertIsNone(gen._value_type("out.hosts", {}))
        self.assertEqual(gen._value_type("b.On", {"On": "boolean"}), "boolean")


class PublishedSpec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        gen.PROBLEMS.clear()
        cls.routes = gen.collect_routes()
        cls.doc = gen.render(cls.routes)
        cls.problems = list(gen.PROBLEMS)

    def test_generator_guessed_nothing(self):
        self.assertEqual(self.problems, [], "the generator fell back on a guess")

    def test_targets_is_never_published_as_a_string(self):
        lines = self.doc.split("\n")
        for i, ln in enumerate(lines):
            if ln.strip() != '"targets":':
                continue
            following = [x.strip() for x in lines[i + 1:i + 5] if x.strip()]
            # A request-body `targets` is an array of host names. A response
            # `targets` is the echoed selection and may be untyped, but it is
            # never a string either.
            self.assertNotIn("type: string", following[:2],
                             f"targets published as a string at line {i + 1}")

    def test_every_fleet_write_publishes_its_400(self):
        for path in FLEET_WRITES:
            with self.subTest(path=path):
                block = path_block(self.doc, path)
                self.assertTrue(block, f"{path} is not in the spec at all")
                self.assertIn('"400":', block,
                              f"{path} publishes no 400, though an empty target list "
                              f"and an unknown host name are both refused with one — "
                              f"an integrator reads the refusal as an outage")

    def test_every_fleet_write_publishes_the_targeting_rule(self):
        # Three of these are served by BOTH surfaces, and the control-plane
        # handler sorts first: emitting only the first handler's doc comment
        # dropped the engine's statement of the rule on preset, thresholds and
        # thaw, leaving those doc comments as text nothing published.
        for path in FLEET_WRITES:
            with self.subTest(path=path):
                block = collapsed(path_block(self.doc, path))
                for want in ("every peer in the hosts file", "exactly those peers",
                             "refused 400", "stripped"):
                    self.assertIn(want, block,
                                  f"{path} does not publish {want!r}")

    def test_the_fleet_kill_switch_is_not_a_get(self):
        # handleChokeKill's whole body is a call to dispatchKillSwitch, so a
        # handler-body-only reading published the fleet-wide EMERGENCY STOP as
        # a GET with no request body.
        block = path_block(self.doc, "/api/fleet/kill-switch")
        self.assertIn("    post:", block)
        self.assertNotIn("    get:", block)
        self.assertIn('"targets":', block, "the kill-switch body is undocumented")

    def test_whoami_states_what_tenants_and_viewing_tenant_mean(self):
        block = path_block(self.doc, "/api/whoami")
        self.assertIn('"viewing_tenant":', block,
                      "whoami publishes viewing_tenant but the spec does not list it")
        flat = collapsed(block)
        self.assertIn("`tenants` is", flat,
                      "tenants is published with no statement of what it is, and it "
                      "reads as an enumeration of the estate")
        self.assertIn("grant", flat)
        self.assertIn("customer roster", flat)
        self.assertIn("`viewing_tenant` is", flat)

    def test_committed_spec_matches_the_source(self):
        self.assertEqual(gen.OUT.read_text(), self.doc,
                         "docs/api/openapi.yaml is stale — run ./scripts/ci/gen-openapi.py")

    def test_overlapping_surface_schemas_use_anyof(self):
        # These schemas declare nothing required and forbid no extra property,
        # so every payload matches every branch. oneOf means EXACTLY one, which
        # would make the document reject every response it describes.
        self.assertNotIn("oneOf:", self.doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
