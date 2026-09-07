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

So these are machine-derived from the code and can never go stale:

  * the PATH INVENTORY   — from the mux.HandleFunc registrations
  * the HTTP METHODS     — from the method guard on the handler's response
                           path (the guard is routinely one call away)
  * the DESCRIPTIONS     — from the doc comment of EVERY handler serving the
                           path, one labelled paragraph per surface
  * the REQUEST BODIES   — from the anonymous struct each handler decodes into
  * the REFUSALS         — from the status codes the handler's response path
                           actually writes (401 and 404 are the platform floor,
                           applied by middleware ahead of the handler, and are
                           published on every operation)

`./scripts/ci/gen-openapi.py --check` then fails the build when the committed
spec no longer matches the code (CI runs it; see .github/workflows/ci.yml),
which is the same ratchet pattern internal/isolationguard applies to the gRPC
surface.

FOLLOW THE RESPONSE PATH, NOT THE HANDLER BODY
----------------------------------------------
Reading only the handler's own body is how this generator published lies. Most
handlers here delegate: handleChokeKill's whole body is a call to
dispatchKillSwitch, and handleWhoami's is `writeJSON(w, 200, s.whoamiFor(p))`.
A body-only reading therefore published the fleet KILL-SWITCH as a GET with no
request body, and whoami as a response with no fields at all.

So every fact below is derived from the RESPONSE PATH: the handler plus,
transitively, every function in the same package that is handed the
http.ResponseWriter (those are the functions that can answer this request),
plus one hop into whatever builds the body passed to a response writer. If a
function cannot touch `w` and cannot produce what `w` is given, it is not part
of the contract and is not read.

WHAT IS NOT GENERATED
---------------------
CLOSED response schemas. Response FIELD NAMES are extracted from the response
path's writeJSON/Encode map literals and published as observed, non-exhaustive
properties - about 40% of responses are assembled inline and the shape varies
by outcome, so declaring them closed would be wrong. Typed-value responses are
not covered. The response semantics that actually matter (ok means applied, not
accepted) are documented by hand and verified against a running server in
docs/api/integration-guide.md.

NOTHING IS GUESSED
------------------
A Go type this generator does not recognise, or a status constant it cannot
name, aborts the run instead of falling back to `type: string`. Publishing
`targets` — a []string — as a string for twelve endpoints, so that an
integrator following the spec sent "targets":"bravo" and got a 400 from the
very handler that was fixed to read it, is precisely what a silent default
buys. A generator that guesses wrong is worse than one that stops.

Usage:  ./scripts/ci/gen-openapi.py [--check]
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENGINE = ROOT / "engine"
OUT = ROOT / "docs" / "api" / "openapi.yaml"

SURFACES = {
    "control-plane": ENGINE / "internal" / "controlplane",
    "engine": ENGINE / "internal" / "api",
}

# Anything the generator refused to guess at. Collected rather than raised so
# one run reports every unknown, and main() then writes nothing.
PROBLEMS: list[str] = []


def problem(msg: str) -> None:
    if msg not in PROBLEMS:
        PROBLEMS.append(msg)


# Functional grouping so a hundred-plus endpoints are navigable. First match wins.
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


# ── the package's functions, and the response path through them ──────────────
FUNC_RX = re.compile(r"^func (?:\([^)]*\)\s*)?(\w+)\(")
CALL_RX = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def parse_package(d: pathlib.Path) -> dict[str, dict]:
    """Every function in the package: name -> {doc, docblock, body, takes_w}.

    Methods are keyed by their bare name because that is how the mux
    registrations and the call sites name them. Two functions sharing a name
    (a method and a helper, say) have their bodies merged, which can only widen
    the response path — never narrow it into missing a refusal.
    """
    funcs: dict[str, dict] = {}
    for f in go_files(d):
        lines = f.read_text().split("\n")
        starts = [i for i, ln in enumerate(lines) if ln.startswith("func ")]
        for n, i in enumerate(starts):
            m = FUNC_RX.match(lines[i])
            if not m:
                continue
            name = m.group(1)
            end = starts[n + 1] if n + 1 < len(starts) else len(lines)
            body = lines[i + 1:end]

            doc: list[str] = []
            j = i - 1
            while j >= 0 and lines[j].lstrip().startswith("//"):
                doc.append(lines[j].lstrip()[2:].strip())
                j -= 1
            doc.reverse()

            sig = lines[i]
            entry = funcs.setdefault(name, {
                "doc": "", "docblock": [], "body": [], "takes_w": False,
            })
            entry["doc"] = entry["doc"] or " ".join(x for x in doc if x).strip()
            entry["body"] += body
            entry["docblock"] += doc
            entry["takes_w"] = entry["takes_w"] or "http.ResponseWriter" in sig
    return funcs


# Calls that hand a response writer its body. A package-local function named
# inside one of these builds part of the answer, so it is on the response path
# even though it never sees `w` itself — that is exactly how whoamiFor holds
# every field /api/whoami returns.
BODY_BUILDER_RX = re.compile(r"(?:writeJSON|writeJSONStatus|Encode)\((.*)$")


def response_path(funcs: dict[str, dict], start: str) -> tuple[list[str], set[str]]:
    """The functions that can answer a request for `start`, `start` included.

    Follows a call only when the callee is handed the http.ResponseWriter, or
    when it builds the value passed to a response writer. A function that can
    do neither cannot contribute to what the caller receives.

    Also returns the BUILDERS — the functions whose return value is handed to a
    response writer. `writeJSON(w, 200, s.whoamiFor(p))` means whoamiFor holds
    every field /api/whoami answers with, and it never touches `w`, so without
    this hop the spec published the identity endpoint as a response with no
    fields at all.
    """
    seen: list[str] = []
    builders: set[str] = set()
    queue = [start]
    while queue:
        name = queue.pop(0)
        if name in seen or name not in funcs:
            continue
        seen.append(name)
        body = funcs[name]["body"]
        for ln in body:
            for callee in CALL_RX.findall(ln):
                if callee == name or callee in seen or callee not in funcs:
                    continue
                if funcs[callee]["takes_w"]:
                    queue.append(callee)
            bb = BODY_BUILDER_RX.search(ln)
            if bb:
                for callee in CALL_RX.findall(bb.group(1)):
                    if callee in funcs and not funcs[callee]["takes_w"]:
                        builders.add(callee)
                        if callee not in seen:
                            queue.append(callee)
    return seen, builders


def path_lines(funcs: dict[str, dict], names: list[str]) -> list[str]:
    out: list[str] = []
    for n in names:
        out += funcs[n]["body"]
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
    "time.Time": ("string", "date-time"),
}

FIELD_RX = re.compile(
    r"^\s*([A-Z]\w*)\s+([\[\]\w.*]+)\s*`[^`]*json:\"([^\",]+)"
)


def go_schema(gotype: str, where: str) -> dict:
    """Map a Go field type onto a JSON Schema fragment.

    A POINTER IS ITS POINTEE. `Targets *[]string` is a slice — the pointer only
    distinguishes "absent" from "[]", which for these handlers is the whole
    difference between an estate-wide write and a refusal, and is a nullability
    fact, not a type. This function used to test `gotype.startswith("[]")`
    before stripping the star, so every `*[]string` fell through to the scalar
    branch and `targets` was published as `type: string` on twelve write
    endpoints. An integrator obeying that spec sends "targets":"bravo" and is
    refused by the handler.
    """
    t = gotype.lstrip("*")
    if t.startswith("[]"):
        elem = t[2:].lstrip("*")
        if elem not in GO_TO_OPENAPI:
            problem(f"unknown Go element type []{elem} ({where}) — add it to "
                    f"GO_TO_OPENAPI; the generator will not guess it into a string")
            return {"type": "array", "items": {"type": "string"}}
        et, efmt = GO_TO_OPENAPI[elem]
        items: dict = {"type": et}
        if efmt:
            items["format"] = efmt
        return {"type": "array", "items": items}
    if t not in GO_TO_OPENAPI:
        problem(f"unknown Go type {t} ({where}) — add it to GO_TO_OPENAPI; "
                f"the generator will not guess it into a string")
        return {"type": "string"}
    st, sfmt = GO_TO_OPENAPI[t]
    schema: dict = {"type": st}
    if sfmt:
        schema["format"] = sfmt
    return schema


def _parse_struct_body(lines: list[str], start: int, where: str,
                       gofields: dict | None = None) -> tuple[dict, int]:
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
            inner, close = _parse_struct_body(lines, i, where, gofields)
            tag = re.search(r'json:"([^",]+)', lines[close] if close < len(lines) else "")
            key = tag.group(1) if tag else name.lower()
            obj: dict = {"type": "object", "properties": inner}
            props[key] = {"type": "array", "items": obj} if is_slice else obj
            if pending_doc:
                props[key]["description"] = _squeeze(" ".join(pending_doc))
            pending_doc = []
            i = close + 1
            continue

        depth += ln.count("{") - ln.count("}")
        if depth <= 0:
            return props, i

        m = FIELD_RX.match(ln)
        if m:
            goname, gotype, jsonname = m.groups()
            schema = go_schema(gotype, f"{where}.{jsonname}")
            if pending_doc:
                schema["description"] = _squeeze(" ".join(pending_doc))
            props[jsonname] = schema
            if gofields is not None:
                # Remembered so a response key whose value is `b.On` can be
                # published with the type the request struct DECLARES, instead
                # of the generator guessing "string" at a bool.
                gofields[goname] = schema.get("type")
        pending_doc = []
        i += 1

    return props, i


def request_body_for(funcs: dict[str, dict], path_fns: list[str],
                     gofields: dict | None = None) -> dict | None:
    """The decoded request struct anywhere on the handler's response path.

    Handlers that delegate — handleChokeKill's body is one call to
    dispatchKillSwitch — decode nothing themselves. Reading only the handler
    published the fleet kill-switch as a body-less endpoint, so the `targets`
    list the console sends appeared in no contract at all.
    """
    for name in path_fns:
        lines = funcs[name]["body"]
        for i, ln in enumerate(lines):
            if re.match(r"^\s*var b struct \{", ln):
                props, _ = _parse_struct_body(lines, i, name, gofields)
                if props:
                    return props
    return None


# ── response fields ──────────────────────────────────────────────────────────
# Extracted from the `writeJSON(w, <code>, map[string]any{...})` literals on the
# response path. Unlike request bodies there is no single declaration to read:
# about 40% of responses are map[string]any assembled inline and the rest are
# typed values, and the shape legitimately varies by outcome (APPLIED vs
# NO_AGENT vs APPROVAL_REQUIRED). So these are published as OBSERVED fields,
# explicitly non-exhaustive, rather than as a closed schema that would be wrong.
#
# Naming them is still worth doing: the fields that decide whether a caller
# believes a containment happened — ok, status, target_match, approval_required
# — are exactly the ones that were being misread.
RESP_KEY_RX = re.compile(r'"([a-z_][a-z0-9_]*)"\s*:')
WRITES_BODY_RX = re.compile(r"writeJSON\(|writeJSONStatus\(|\.Encode\(")

# A doc-comment convention the generator reads, because some fields cannot be
# explained next to the map key that emits them. A comment paragraph that opens
# with a backticked JSON key documents that key:
#
#     // `tenants` is REACH THAT NEEDS NO NAMING: the tenants this principal
#     // holds a tenant-bound grant for. …
#
# whoami's three easily-confused fields (tenants, host, viewing_tenant) are
# already written this way in controlplane/http.go; without this the published
# spec listed the field names and said nothing about what they mean, and
# `tenants` looked like an enumeration of the estate.
KEY_DOC_RX = re.compile(r"^`([a-z_][a-z0-9_]*)`\s+(.*)$", re.S)


def key_docs(funcs: dict[str, dict], path_fns: list[str]) -> dict[str, str]:
    """field -> prose, from backticked-key paragraphs on the response path.

    A paragraph ends at a blank comment line OR at the first line of code:
    without that second rule two comment blocks separated by a statement merge
    into one, and `viewing_tenant`'s description ran on into the next three
    fields' explanations.
    """
    out: dict[str, str] = {}
    for name in path_fns:
        block = list(funcs[name]["docblock"]) + [""]
        for ln in funcs[name]["body"]:
            st = ln.strip()
            block.append(st[2:].strip() if st.startswith("//") else "")
        para: list[str] = []
        for line in block + [""]:
            if line:
                para.append(line)
                continue
            if para:
                text = " ".join(para)
                m = KEY_DOC_RX.match(text)
                if m and m.group(1) not in out:
                    # Keep the backticked key in the published prose: the
                    # paragraph is written as a sentence about it, and
                    # stripping the subject left descriptions beginning "is
                    # REACH THAT NEEDS NO NAMING".
                    out[m.group(1)] = _squeeze(text)
            para = []
    return out


def _squeeze(s: str) -> str:
    return " ".join(s.split())


def _value_type(val: str, gofields: dict) -> str | None:
    """Infer a JSON type from the expression assigned to a response key.

    Returns None when the expression does not settle the type, and the field is
    then published WITHOUT one. Two lies came out of the previous "default to
    string": `"applied": out.applied` is a COUNT the spec called a boolean
    (only the prefix was tested, and the neighbouring `"ok": out.applied > 0`
    set the rule), and `"hosts": out.hosts` is the per-host array the console
    reads for coverage, published as a string. An observed field with no type
    is honest; a typed-wrong one is what an integrator codes against.
    """
    if val in ("true", "false") or val.startswith("!") or val.endswith(".OK"):
        return "boolean"
    if re.search(r"(>=|<=|==|!=|\s>\s|\s<\s)", val):
        return "boolean"
    if re.fullmatch(r"-?\d+", val) or val.startswith("len(") or val.startswith("int("):
        return "integer"
    if val in ("out.applied", "out.total"):
        return "integer"
    if val.startswith('"') or val.startswith("string(") or val.startswith("fmt.Sprintf("):
        return "string"
    if val.endswith(".Error()") or val.endswith(".String()"):
        return "string"
    m = re.fullmatch(r"b\.(\w+)", val)
    if m:
        return gofields.get(m.group(1))
    return None


def response_fields(funcs: dict[str, dict], path_fns: list[str],
                    builders: set[str], gofields: dict) -> dict[str, dict]:
    """field -> {type, description} observed on the handler's response path."""
    fields: dict[str, dict] = {}
    docs = key_docs(funcs, path_fns)
    for name in path_fns:
        lines = funcs[name]["body"]
        for i, ln in enumerate(lines):
            if "map[string]any{" not in ln and "map[string]interface{}{" not in ln:
                continue
            window = "\n".join(lines[max(0, i - 1):i + 1])
            # In a writer, the literal must be the argument to the write. In a
            # BUILDER the literal IS the response — it is returned, and the
            # write happens at the call site one frame up.
            builder_return = name in builders and ln.lstrip().startswith("return ")
            if not builder_return and not WRITES_BODY_RX.search(window):
                continue
            depth = 0
            j = i
            buf: list[str] = []
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                buf.append(lines[j])
                if depth <= 0:
                    break
                j += 1
            pending: list[str] = []
            for line in buf:
                s = line.strip()
                if s.startswith("//"):
                    pending.append(s[2:].strip())
                    continue
                for key in RESP_KEY_RX.findall(s):
                    mv = re.search(r'"' + re.escape(key) + r'"\s*:\s*([^,\n}]+)', s)
                    val = mv.group(1).strip() if mv else ""
                    entry = fields.setdefault(key, {"type": _value_type(val, gofields)})
                    desc = docs.get(key) or _squeeze(" ".join(pending))
                    if desc and "description" not in entry:
                        entry["description"] = desc
                pending = []
    # A field explained by the backticked-key convention keeps that prose even
    # when the map key it came from carried a comment of its own.
    for key, entry in fields.items():
        if key in docs:
            entry["description"] = docs[key]
    return fields


# ── refusals ─────────────────────────────────────────────────────────────────
# The statuses the response path actually writes. Hardcoding 200/401/404 was a
# convenient fiction: an empty "targets" list and an unknown host name are both
# 400s with a {error, unknown[]} body, and a spec that lists three outcomes
# none of which is 400 tells an integrator to read a refusal as an outage.
#
# Only a status handed to a RESPONSE WRITER counts. A status compared against
# an upstream peer's reply (peerCall) is that peer's answer, not ours.
STATUS_NAMES = {
    "Continue": 100, "OK": 200, "Created": 201, "Accepted": 202, "NoContent": 204,
    "MovedPermanently": 301, "Found": 302, "SeeOther": 303, "NotModified": 304,
    "TemporaryRedirect": 307, "PermanentRedirect": 308,
    "BadRequest": 400, "Unauthorized": 401, "PaymentRequired": 402, "Forbidden": 403,
    "NotFound": 404, "MethodNotAllowed": 405, "NotAcceptable": 406,
    "RequestTimeout": 408, "Conflict": 409, "Gone": 410, "PreconditionFailed": 412,
    "RequestEntityTooLarge": 413, "UnsupportedMediaType": 415,
    "UnprocessableEntity": 422, "TooEarly": 425, "TooManyRequests": 429,
    "InternalServerError": 500, "NotImplemented": 501, "BadGateway": 502,
    "ServiceUnavailable": 503, "GatewayTimeout": 504,
}

STATUS_TEXT = {
    200: "Success",
    201: "Created",
    202: "Accepted",
    204: "No content",
    301: "Moved permanently",
    302: "Redirect",
    303: "Redirect (see other)",
    304: "Not modified",
    307: "Temporary redirect",
    308: "Permanent redirect",
    400: ("The handler refused the request; the conditions it refuses are in "
          "the description above. A 400 is a REJECTED request, not a failed "
          "change - nothing was applied anywhere."),
    401: "Unauthenticated",
    402: "Payment required",
    403: "Forbidden",
    404: "Not found, or not visible to this caller",
    405: "Method not allowed",
    406: "Not acceptable",
    408: "Request timeout",
    409: "Conflict with the resource's current state",
    410: "Gone",
    412: "Precondition failed",
    413: "Request body too large",
    415: "Unsupported media type",
    422: "Unprocessable content",
    425: "Too early",
    429: "Rate limited",
    500: ("Server error. On a write this does not say whether the change was "
          "applied; re-read the state rather than assuming either way."),
    501: "Not implemented on this deployment",
    502: "Upstream failure",
    503: "Not ready, or the dependency this endpoint needs is unavailable",
    504: "Upstream timeout",
}

_TOK = r"(http\.Status([A-Za-z]+)|[1-5]\d\d)"
STATUS_CALLS = [
    re.compile(r"writeJSONStatus\(\s*\w+\s*,\s*" + _TOK),
    re.compile(r"writeJSON\(\s*\w+\s*,\s*" + _TOK),
    re.compile(r"WriteHeader\(\s*" + _TOK),
    re.compile(r"http\.Error\(.*,\s*" + _TOK + r"\s*\)"),
    re.compile(r"http\.Redirect\(.*,\s*" + _TOK + r"\s*\)"),
]


def statuses(funcs: dict[str, dict], path_fns: list[str], where: str) -> set[int]:
    """Every status the response path can write."""
    found: set[int] = set()
    for ln in path_lines(funcs, path_fns):
        if "http.NotFound(" in ln:
            found.add(404)
        for rx in STATUS_CALLS:
            for m in rx.finditer(ln):
                tok, name = m.group(1), m.group(2)
                if name:
                    if name not in STATUS_NAMES:
                        problem(f"unknown status constant http.Status{name} "
                                f"({where}) — add it to STATUS_NAMES")
                        continue
                    found.add(STATUS_NAMES[name])
                else:
                    found.add(int(tok))
    return found


# ── methods ──────────────────────────────────────────────────────────────────
def methods_for(funcs: dict[str, dict], path_fns: list[str]) -> list[str]:
    """The verbs the response path accepts.

    Inference walks the response path rather than the handler body because the
    guard is routinely one call away: handleChokeKill delegates every line of
    its work to dispatchKillSwitch, so a body-only reading published the
    fleet-wide EMERGENCY STOP as a GET.
    """
    for name in path_fns:
        blob = "\n".join(funcs[name]["body"])
        guarded = re.findall(r"r\.Method\s*!=\s*http\.Method([A-Z][a-z]+)", blob)
        if guarded:
            # `if r.Method != POST { reject }` means POST-only; several
            # handlers allow a pair (POST/PUT).
            return sorted({g.upper() for g in guarded})
        if "authorizeRespond(" in blob:
            # Most control-plane WRITE handlers do not guard inline — the
            # method check lives in the shared authorizeRespond helper, which
            # rejects anything that is not POST or PUT. Reading only the
            # handler body therefore mislabelled every one of them as GET,
            # which would have told an integrating team to send the wrong
            # verb to the containment endpoints.
            return ["POST", "PUT"]
        if "authorizeRead(" in blob:
            return ["GET"]
        found = sorted({m.upper() for m in re.findall(r"http\.Method([A-Z][a-z]+)", blob)})
        if found:
            return found
    return ["GET"]


# ── routes ───────────────────────────────────────────────────────────────────
def collect_routes() -> list[dict]:
    rx = re.compile(r'mux\.HandleFunc\("([^"]+)",\s*([A-Za-z0-9_.()*]+)')
    routes: list[dict] = []
    for surface, d in SURFACES.items():
        funcs = parse_package(d)
        seen = set()
        for f in go_files(d):
            for path, expr in rx.findall(f.read_text()):
                key = (surface, path)
                if key in seen:
                    continue
                seen.add(key)
                hname = expr.split(".")[-1].strip("()")
                if hname not in funcs:
                    routes.append({
                        "path": path, "surface": surface, "handler": hname,
                        "doc": "", "methods": ["GET"], "body": None,
                        "resp": None, "statuses": {200, 401, 404},
                    })
                    continue
                fns, builders = response_path(funcs, hname)
                gofields: dict[str, str] = {}
                doc = funcs[hname]["doc"]
                if not doc:
                    # An undocumented handler that hands the answer to a builder
                    # is documented one call away — the builder is what the
                    # response IS. Only builders are consulted: falling back to
                    # any function on the path would publish the doc comment of
                    # a shared helper like writeJSON over an endpoint.
                    for nxt in fns[1:]:
                        if nxt in builders and funcs[nxt]["doc"]:
                            # Attributed, not passed off as the endpoint's own
                            # prose. A builder's doc comment is written for the
                            # reader of the code ("filterAlerts applies f"), and
                            # publishing it unlabelled would read as a statement
                            # about the API that nobody wrote.
                            doc = (f"Described by {nxt}(), which builds this "
                                   f"response: {funcs[nxt]['doc']}")
                            break
                # Order matters: the request struct's Go field types are what
                # let a response value like `b.On` be typed at all, so the body
                # must be parsed before the response fields are read.
                body = request_body_for(funcs, fns, gofields)
                routes.append({
                    "path": path,
                    "surface": surface,
                    "handler": hname,
                    "doc": doc,
                    "methods": methods_for(funcs, fns),
                    "body": body,
                    "resp": response_fields(funcs, fns, builders, gofields) or None,
                    "statuses": statuses(funcs, fns, f"{surface}:{hname}"),
                })
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
    a("# Paths, HTTP methods, descriptions, request bodies and the refusal")
    a("# statuses are derived from the Go source, so they cannot drift from the")
    a("# code. ./scripts/ci/gen-openapi.py --check fails CI when this file no")
    a("# longer matches. Regenerate with:")
    a("#     ./scripts/ci/gen-openapi.py")
    a("#")
    a("# Response schemas are OBSERVED, not closed — see the module docstring in")
    a("# the generator for why guessing them would be worse than omitting them.")
    a("# Hand-written integration guides live in docs/api/.")
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
    a("    Where one path is served by both, the operation below carries a")
    a("    labelled description per surface, and a labelled schema branch")
    a("    wherever the two answer differently: they are different handlers,")
    a("    and only one of them is the server you are calling.")
    a("")
    a("    A third surface, the agent-to-control-plane wire contract, is gRPC and")
    a("    is specified by the protobuf IDL in engine/proto/ebpfsoc/v1 — not here.")
    a("")
    a("    An authorisation denial on a tenant-scoped resource returns 404,")
    a("    never 403, so a caller cannot use error codes to discover which")
    a("    tenants or resources exist. Treat a 404 as 'no such thing, or not")
    a("    yours' — the distinction is deliberately unavailable. Where a 403 is")
    a("    listed it is a different refusal (no scope held at all, a failed CSRF")
    a("    check, a path outside the served tree) and never separates one")
    a("    tenant's resources from another's.")
    a("")
    a("    Every operation lists 401 and 404. Those two are the platform floor,")
    a("    not a per-handler derivation: authentication and the deny-as-404 rule")
    a("    are applied by middleware ahead of the handler, so they are reachable")
    a("    on paths whose own code never writes them. Every OTHER status listed")
    a("    is one the handler's own response path writes.")
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
            surfaces = sorted({x["surface"] for x in es})
            a(f"    {method.lower()}:")
            a(f"      tags: [{yaml_str(tag_for(path))}]")
            a(f"      operationId: {method.lower()}_{re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_')}")
            a(f"      summary: {yaml_str(' / '.join(_unique(x['handler'] for x in es)))}")
            a("      description: |")
            for line in _description(es):
                a(f"        {line}" if line else "")
            a("")
            a(f"        Surface: {', '.join(surfaces)}.")
            if "control-plane" in surfaces and path.startswith("/api/"):
                if len(surfaces) > 1:
                    a("        Requires the tenant query parameter on the control plane; the")
                    a("        engine surface has no tenancy model and ignores it.")
                else:
                    a("        Requires the tenant query parameter.")
                a("      parameters:")
                a("        - $ref: '#/components/parameters/tenant'")
            if method in ("POST", "PUT", "PATCH"):
                bodies = _variants(es, "body")
                if bodies:
                    a("      requestBody:")
                    a("        required: true")
                    a("        content:")
                    a("          application/json:")
                    a("            schema:")
                    for line in _object_or_variants(bodies, 14, _schema_lines):
                        a(line)
            a("      responses:")
            resps = _variants(es, "resp")
            if resps:
                a('        "200":')
                a("          description: |")
                a("            Success. The fields below are those OBSERVED on this handler's")
                a("            response path, derived from its writeJSON literals - they are")
                a("            NOT an exhaustive schema, and the shape varies by outcome.")
                a("            Read `ok` as 'the agent confirmed it applied', not 'accepted'.")
                a("            A field published WITHOUT a type is one the source does not")
                a("            settle - it is listed because the handler emits it, and left")
                a("            untyped rather than guessed.")
                a("          content:")
                a("            application/json:")
                a("              schema:")
                for line in _object_or_variants(resps, 16, _resp_lines):
                    a(line)
            else:
                a('        "200": { description: "Success" }')
            codes = set()
            for e in es:
                codes |= set(e["statuses"])
            codes |= {401, 404}
            for code in sorted(c for c in codes if c != 200):
                text = STATUS_TEXT.get(code)
                if text is None:
                    problem(f"no published description for status {code} "
                            f"(path {path}) — add it to STATUS_TEXT")
                    continue
                if len(text) < 60:
                    a(f'        "{code}": {{ description: {yaml_str(text)} }}')
                else:
                    a(f'        "{code}":')
                    a("          description: |")
                    for line in _wrap(text, 70):
                        a(f"            {line}")
    return "\n".join(L) + "\n"


def _unique(it):
    out = []
    for x in it:
        if x not in out:
            out.append(x)
    return out


def _description(es: list[dict]) -> list[str]:
    """One paragraph per handler serving this path+method.

    Taking only the first handler's doc comment is how three of the five fleet
    write paths ended up published with descriptions that never mention
    targeting: /api/fleet/preset, /thresholds and /thaw are served by BOTH
    surfaces, the control-plane handler sorts first, and its one-line comment
    silently displaced the engine handler's full statement of the rule. The
    engine's doc comments were dead text nothing emitted.
    """
    named = _unique_pairs(es)
    if len(named) <= 1:
        doc = named[0][2] if named else ""
        return _wrap(doc or "No handler documentation in source.", 74)
    out: list[str] = []
    for surface, handler, doc in named:
        if out:
            out.append("")
        out.append(f"{surface} — {handler}:")
        out += _wrap(doc or "No handler documentation in source.", 74)
    return out


def _unique_pairs(es: list[dict]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for e in es:
        trip = (e["surface"], e["handler"], e["doc"])
        if trip not in out:
            out.append(trip)
    return out


def _variants(es: list[dict], key: str) -> list[tuple[str, dict]]:
    """Distinct schemas for this path+method, labelled by the handler they came
    from. Two surfaces on one path answer differently — /api/whoami returns a
    tenancy document on the control plane and {user, hostname, csrf} on the
    engine — so merging them would publish a shape neither one returns."""
    out: list[tuple[str, dict]] = []
    for e in es:
        v = e.get(key)
        if not v:
            continue
        if any(v == prev for _, prev in out):
            continue
        out.append((f"{e['surface']} — {e['handler']}", v))
    return out


def _object_or_variants(variants, indent, body_fn) -> list[str]:
    """One object schema, or a titled anyOf when the surfaces disagree.

    anyOf, not oneOf: these schemas declare no required properties and forbid
    no extra ones, so every payload matches BOTH branches — and `oneOf` means
    exactly one, which would make the spec reject every response it describes.
    """
    pad = " " * indent
    if len(variants) == 1:
        out = [f"{pad}type: object", f"{pad}properties:"]
        return out + body_fn(variants[0][1], indent + 2)
    out = [f"{pad}anyOf:"]
    for label, props in variants:
        out.append(f"{pad}  - title: {yaml_str(label)}")
        out.append(f"{pad}    type: object")
        out.append(f"{pad}    properties:")
        out += body_fn(props, indent + 6)
    return out


def _resp_lines(fields: dict, indent: int) -> list[str]:
    pad = " " * indent
    inner = " " * (indent + 2)
    out: list[str] = []
    for k, v in sorted(fields.items()):
        # No `type` when the source does not settle one. The value is an
        # expression, not a declaration, and an inferred-wrong type is the
        # same defect as publishing a []string as a string. An empty schema is
        # the JSON Schema way to say "present, any type" — a bare key with no
        # value would be null, which is not a schema at all.
        if not v.get("type") and not v.get("description"):
            out.append(f"{pad}{yaml_str(k)}: {{}}")
            continue
        out.append(f"{pad}{yaml_str(k)}:")
        if v.get("type"):
            out.append(f"{inner}type: {v['type']}")
        if desc := v.get("description"):
            out.append(f"{inner}description: {yaml_str(desc)}")
    return out


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
            if items.get("format"):
                out.append(f"{deep}format: {items['format']}")
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
    if PROBLEMS:
        # Refuse to publish a spec built on a guess. Every one of these is a
        # place the generator would otherwise have quietly emitted
        # `type: string`, which is how `targets` — a list of host names —
        # shipped as a string on twelve write endpoints.
        print("REFUSING to write docs/api/openapi.yaml — the generator will not guess:")
        for p in PROBLEMS:
            print(f"  * {p}")
        return 2
    check = "--check" in sys.argv
    if check:
        if not OUT.exists():
            print(f"MISSING: {OUT.relative_to(ROOT)} — run ./scripts/ci/gen-openapi.py")
            return 1
        if OUT.read_text() != spec:
            print("DRIFT: docs/api/openapi.yaml no longer matches the routes in the code.")
            print("A route, method, body or refusal changed without regenerating the spec.")
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
