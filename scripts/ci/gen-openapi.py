#!/usr/bin/env python3
"""Generate docs/api/openapi.yaml from the Go source.

WHY GENERATED, NOT HAND-WRITTEN
-------------------------------
This repository has already been bitten by hand-synced duplication: the
telemetry schema is authored in four places and has drifted into a duplicate
index, and an audit found four code comments asserting things that were no
longer true. A hand-maintained OpenAPI file would become the fifth place to
drift — and a wrong API spec is worse than none, because an integrating team
builds against it and finds out in production.

So three things are machine-derived from the code and can never go stale:

  * the PATH INVENTORY   — from the mux.HandleFunc registrations
  * the HTTP METHODS     — from each handler's own method guard
  * the DESCRIPTIONS     — from each handler's doc comment

scripts/ci/check-openapi.sh then fails the build when the committed spec no
longer matches the code, which is the same ratchet pattern
internal/isolationguard already applies to the gRPC surface.

  * the REQUEST BODIES   — from the anonymous struct each handler decodes into

WHAT IS NOT GENERATED
---------------------
RESPONSE schemas. Responses are assembled as map[string]any at many points and
vary by outcome, so there is no single declaration to read; guessing them would
produce exactly the confidently-wrong document this is trying to avoid. The
response fields that matter (ok, status, target_match, approval_required) are
documented by hand, and verified against a running server, in
docs/api/integration-guide.md.

Usage:  ./scripts/ci/gen-openapi.py [--check]
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENGINE = ROOT / "engine"
OUT = ROOT / "docs" / "api" / "openapi.yaml"

SURFACES = {
    "control-plane": ENGINE / "internal" / "controlplane",
    "engine": ENGINE / "internal" / "api",
}

# Functional grouping so 136 endpoints are navigable. First match wins.
TAG_RULES = [
    ("/api/choke/device", "Containment — device plane"),
    ("/api/choke", "Containment — process plane"),
    ("/api/approvals", "Change control (dual authorisation)"),
    ("/api/fleet", "Fleet operations"),
    ("/api/admin", "Administration"),
    ("/api/tenants", "Tenancy"),
    ("/api/telemetry", "Telemetry"),
    ("/api/alerts", "Detections"),
    ("/api/alert-stats", "Detections"),
    ("/api/events", "Detections"),
    ("/api/decisions", "Enforcement audit"),
    ("/api/policies", "Policy"),
    ("/api/kprobes", "Policy"),
    ("/api/attacks", "Simulation"),
    ("/api/honeypots", "Simulation"),
    ("/api/system-health", "Operations"),
    ("/api/version", "Operations"),
    ("/healthz", "Operations"),
    ("/readyz", "Operations"),
    ("/auth", "Authentication"),
    ("/api/login", "Authentication"),
    ("/api/logout", "Authentication"),
    ("/api/whoami", "Authentication"),
]


def tag_for(path: str) -> str:
    for prefix, tag in TAG_RULES:
        if path.startswith(prefix):
            return tag
    return "Other"


def go_files(d: pathlib.Path):
    return [f for f in d.glob("*.go") if not f.name.endswith("_test.go")]


def collect_handlers(d: pathlib.Path) -> dict[str, dict]:
    """handler name -> {doc, methods} parsed from the source."""
    out: dict[str, dict] = {}
    for f in go_files(d):
        lines = f.read_text().split("\n")
        for i, ln in enumerate(lines):
            m = re.match(r"^func \([^)]*\) (\w+)\(w http\.ResponseWriter", ln)
            if not m:
                continue
            name = m.group(1)

            doc: list[str] = []
            j = i - 1
            while j >= 0 and lines[j].lstrip().startswith("//"):
                doc.append(lines[j].lstrip()[2:].strip())
                j -= 1
            doc.reverse()

            # Read the handler body until the next top-level func, and infer the
            # accepted methods from its own guard. This is the handler's real
            # contract, not a guess.
            body: list[str] = []
            k = i + 1
            while k < len(lines) and not lines[k].startswith("func "):
                body.append(lines[k])
                k += 1
            blob = "\n".join(body)

            methods = set(re.findall(r"http\.Method([A-Z][a-z]+)", blob))
            guarded = re.findall(r"r\.Method\s*!=\s*http\.Method([A-Z][a-z]+)", blob)
            if guarded:
                # `if r.Method != POST { reject }` means POST-only; several
                # handlers allow a pair (POST/PUT).
                methods = set(guarded)
            elif "authorizeRespond(" in blob:
                # Most control-plane WRITE handlers do not guard inline — the
                # method check lives in the shared authorizeRespond helper, which
                # rejects anything that is not POST or PUT. Reading only the
                # handler body therefore mislabelled every one of them as GET,
                # which would have told an integrating team to send the wrong
                # verb to the containment endpoints.
                methods = {"Post", "Put"}
            elif "authorizeRead(" in blob:
                methods = {"Get"}
            if not methods:
                methods = {"Get"}

            out[name] = {
                "doc": " ".join(x for x in doc if x).strip(),
                "methods": sorted(m.upper() for m in methods),
            }
    return out



# ── request bodies ───────────────────────────────────────────────────────────
# Derived from the anonymous struct each handler decodes into, e.g.
#
#     var b struct {
#         ExecID string `json:"exec_id"`
#         Pid    uint32 `json:"pid"`
#     }
#     json.NewDecoder(r.Body).Decode(&b)
#
# That struct IS the request contract — it is what the handler actually parses —
# so a schema derived from it cannot disagree with the code. This is the reason
# annotations were not used: a `// @Param` comment can say one thing while the
# struct says another, and nothing checks. Here there is nothing to keep in sync.
GO_TO_OPENAPI = {
    "string": ("string", None),
    "bool": ("boolean", None),
    "int": ("integer", None),
    "int32": ("integer", "int32"),
    "int64": ("integer", "int64"),
    "uint": ("integer", None),
    "uint16": ("integer", None),
    "uint32": ("integer", "int32"),
    "uint64": ("integer", "int64"),
    "float32": ("number", "float"),
    "float64": ("number", "double"),
}

FIELD_RX = re.compile(
    r"^\s*([A-Z]\w*)\s+([\[\]\w.*]+)\s*`[^`]*json:\"([^\",]+)"
)


def _parse_struct_body(lines: list[str], start: int) -> tuple[dict, int]:
    """Parse an anonymous struct body.

    `start` is the line opening the struct. Returns (properties, index-of-closing
    -brace-line). A nested struct is consumed entirely by the recursive call, so
    the parent must not count its braces — getting that wrong makes the parent's
    depth never return to zero and it swallows whatever follows, which is how
    response fields first leaked into a request schema.
    """
    props: dict[str, dict] = {}
    depth = lines[start].count("{") - lines[start].count("}")
    i = start + 1
    pending_doc: list[str] = []

    while i < len(lines) and depth > 0:
        ln = lines[i]
        stripped = ln.strip()

        if stripped.startswith("//"):
            pending_doc.append(stripped[2:].strip())
            i += 1
            continue

        nested = re.match(r"^\s*([A-Z]\w*)\s+(\[\])?struct\s*\{", ln)
        if nested:
            name, is_slice = nested.group(1), bool(nested.group(2))
            inner, close = _parse_struct_body(lines, i)
            tag = re.search(r'json:"([^",]+)', lines[close] if close < len(lines) else "")
            key = tag.group(1) if tag else name.lower()
            obj: dict = {"type": "object", "properties": inner}
            props[key] = {"type": "array", "items": obj} if is_slice else obj
            if pending_doc:
                props[key]["description"] = " ".join(pending_doc)
            pending_doc = []
            i = close + 1
            continue

        depth += ln.count("{") - ln.count("}")
        if depth <= 0:
            return props, i

        m = FIELD_RX.match(ln)
        if m:
            _, gotype, jsonname = m.groups()
            if gotype.startswith("[]"):
                t, fmt = GO_TO_OPENAPI.get(gotype[2:], ("string", None))
                schema: dict = {"type": "array", "items": {"type": t}}
                if fmt:
                    schema["items"]["format"] = fmt
            else:
                t, fmt = GO_TO_OPENAPI.get(gotype.lstrip("*"), ("string", None))
                schema = {"type": t}
                if fmt:
                    schema["format"] = fmt
            if pending_doc:
                schema["description"] = " ".join(pending_doc)
            props[jsonname] = schema
        pending_doc = []
        i += 1

    return props, i


def collect_request_bodies(d: pathlib.Path) -> dict[str, dict]:
    """handler name -> JSON schema properties for its decoded request body."""
    out: dict[str, dict] = {}
    for f in go_files(d):
        lines = f.read_text().split("\n")
        current = None
        for i, ln in enumerate(lines):
            m = re.match(r"^func \([^)]*\) (\w+)\(w http\.ResponseWriter", ln)
            if m:
                current = m.group(1)
                continue
            if current and re.match(r"^\s*var b struct \{", ln):
                props, _ = _parse_struct_body(lines, i)
                if props:
                    out[current] = props
        # a handler with no body decode simply never appears here
    return out


def collect_routes() -> list[dict]:
    rx = re.compile(r'mux\.HandleFunc\("([^"]+)",\s*([A-Za-z0-9_.()*]+)')
    routes: list[dict] = []
    for surface, d in SURFACES.items():
        handlers = collect_handlers(d)
        bodies = collect_request_bodies(d)
        seen = set()
        for f in go_files(d):
            for path, expr in rx.findall(f.read_text()):
                key = (surface, path)
                if key in seen:
                    continue
                seen.add(key)
                hname = expr.split(".")[-1].strip("()")
                info = handlers.get(hname, {})
                routes.append(
                    {
                        "path": path,
                        "surface": surface,
                        "handler": hname,
                        "doc": info.get("doc", ""),
                        "methods": info.get("methods", ["GET"]),
                        "body": bodies.get(hname),
                    }
                )
    routes.sort(key=lambda r: (r["surface"], r["path"]))
    return routes


def yaml_str(s: str) -> str:
    """Emit a scalar safely without a YAML dependency."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def render(routes: list[dict]) -> str:
    L: list[str] = []
    a = L.append
    a("# GENERATED by scripts/ci/gen-openapi.py — do not edit by hand.")
    a("#")
    a("# Paths, HTTP methods and descriptions are derived from the Go source, so")
    a("# they cannot drift from the code. scripts/ci/check-openapi.sh fails CI when")
    a("# this file no longer matches. Regenerate with:")
    a("#     ./scripts/ci/gen-openapi.py")
    a("#")
    a("# Request/response schemas are intentionally NOT generated — see the module")
    a("# docstring in the generator for why guessing them would be worse than")
    a("# omitting them. Hand-written integration guides live in docs/api/.")
    a("openapi: 3.1.0")
    a("info:")
    a('  title: "eBPF-SOC platform API"')
    a('  version: "1.0.0"')
    a("  description: |")
    a("    Two independent HTTP surfaces. They are NOT interchangeable and are")
    a("    documented together only because one console can drive both.")
    a("")
    a("      * control-plane — multi-tenant. Every request is tenant-scoped and")
    a("        authorisation is evaluated per tenant. This is the MSSP/MSOC")
    a("        surface.")
    a("      * engine — single-tenant. One host, its own console, no tenancy")
    a("        model. This is the standalone product.")
    a("")
    a("    A third surface, the agent-to-control-plane wire contract, is gRPC and")
    a("    is specified by the protobuf IDL in engine/proto/ebpfsoc/v1 — not here.")
    a("")
    a("    Denials return 404, never 403, so a caller cannot use error codes to")
    a("    discover which tenants or resources exist. Treat a 404 as")
    a("    'no such thing, or not yours' — the distinction is deliberately")
    a("    unavailable.")
    a("servers:")
    a('  - url: "https://console.example.com"')
    a('    description: "Control plane (multi-tenant)"')
    a('  - url: "https://engine.example.com"')
    a('    description: "Single-tenant engine"')
    a("tags:")
    for t in sorted({tag_for(r["path"]) for r in routes}):
        a(f"  - name: {yaml_str(t)}")
    a("components:")
    a("  securitySchemes:")
    a("    bearerAdmin:")
    a("      type: http")
    a("      scheme: bearer")
    a("      description: |")
    a("        Control-plane admin token (CP_ADMIN_TOKEN). Grants the")
    a("        msoc-admin role across tenants. Machine-to-machine only.")
    a("    sessionCookie:")
    a("      type: apiKey")
    a("      in: cookie")
    a("      name: soc_session")
    a("      description: |")
    a("        Opaque session cookie. On the control plane it is issued by the")
    a("        BFF after an OIDC Authorization Code + PKCE flow, so an access")
    a("        token never reaches the browser. On the engine it is a signed,")
    a("        stateless cookie. Unsafe methods under /api/ additionally require")
    a("        the X-CSRF-Token header echoing the csrf_token cookie.")
    a("  parameters:")
    a("    tenant:")
    a("      name: tenant")
    a("      in: query")
    a("      required: true")
    a("      schema: { type: string }")
    a("      description: |")
    a("        Tenant id. Control-plane only. Authorisation is evaluated against")
    a("        it; a caller outside the tenant receives 404.")
    a("security:")
    a("  - sessionCookie: []")
    a("  - bearerAdmin: []")
    a("paths:")

    by_path: dict[str, list[dict]] = {}
    for r in routes:
        by_path.setdefault(r["path"], []).append(r)

    for path in sorted(by_path):
        entries = by_path[path]
        a(f"  {yaml_str(path)}:")
        methods: dict[str, list[dict]] = {}
        for e in entries:
            for m in e["methods"]:
                methods.setdefault(m, []).append(e)
        for method in sorted(methods):
            es = methods[method]
            primary = es[0]
            surfaces = sorted({x["surface"] for x in es})
            a(f"    {method.lower()}:")
            a(f"      tags: [{yaml_str(tag_for(path))}]")
            a(f"      operationId: {method.lower()}_{re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_')}")
            a(f"      summary: {yaml_str(primary['handler'])}")
            desc = primary["doc"] or "No handler documentation in source."
            a("      description: |")
            for line in _wrap(desc, 74):
                a(f"        {line}")
            a("")
            a(f"        Surface: {', '.join(surfaces)}.")
            if "control-plane" in surfaces and path.startswith("/api/"):
                a("        Requires the tenant query parameter.")
                a("      parameters:")
                a("        - $ref: '#/components/parameters/tenant'")
            if method in ("POST", "PUT", "PATCH") and primary.get("body"):
                a("      requestBody:")
                a("        required: true")
                a("        content:")
                a("          application/json:")
                a("            schema:")
                a("              type: object")
                a("              properties:")
                for line in _schema_lines(primary["body"], 16):
                    a(line)
            a("      responses:")
            a('        "200": { description: "Success" }')
            a('        "401": { description: "Unauthenticated" }')
            a('        "404": { description: "Not found, or not visible to this caller" }')
    return "\n".join(L) + "\n"


def _schema_lines(props: dict, indent: int) -> list[str]:
    """Render a properties map as YAML at the given indent."""
    pad = " " * indent
    out: list[str] = []
    for name, sch in props.items():
        out.append(f"{pad}{yaml_str(name)}:")
        inner = " " * (indent + 2)
        if desc := sch.get("description"):
            out.append(f"{inner}description: {yaml_str(desc)}")
        t = sch.get("type", "string")
        out.append(f"{inner}type: {t}")
        if fmt := sch.get("format"):
            out.append(f"{inner}format: {fmt}")
        if t == "array":
            items = sch.get("items", {"type": "string"})
            out.append(f"{inner}items:")
            deep = " " * (indent + 4)
            out.append(f"{deep}type: {items.get('type', 'string')}")
            if items.get("type") == "object" and items.get("properties"):
                out.append(f"{deep}properties:")
                out.extend(_schema_lines(items["properties"], indent + 6))
        elif t == "object" and sch.get("properties"):
            out.append(f"{inner}properties:")
            out.extend(_schema_lines(sch["properties"], indent + 4))
    return out


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]


def main() -> int:
    routes = collect_routes()
    spec = render(routes)
    check = "--check" in sys.argv
    if check:
        if not OUT.exists():
            print(f"MISSING: {OUT.relative_to(ROOT)} — run ./scripts/ci/gen-openapi.py")
            return 1
        if OUT.read_text() != spec:
            print("DRIFT: docs/api/openapi.yaml no longer matches the routes in the code.")
            print("A route was added, removed, or renamed without regenerating the spec.")
            print("Fix with: ./scripts/ci/gen-openapi.py")
            return 1
        print(f"openapi.yaml matches the source ({len(routes)} routes)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(spec)
    documented = sum(1 for r in routes if r["doc"])
    print(f"wrote {OUT.relative_to(ROOT)}: {len(routes)} routes, "
          f"{documented} with descriptions from source ({100*documented//len(routes)}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
