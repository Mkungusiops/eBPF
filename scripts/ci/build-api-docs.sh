#!/usr/bin/env bash
#
# scripts/ci/build-api-docs.sh — render docs/api/openapi.yaml into ONE
# self-contained HTML file that needs no server and no network.
#
# Why not just `npx @redocly/cli build-docs`: its output loads the renderer from
# cdn.redocly.com at VIEW time. That breaks in the airgapped environments
# enterprise security teams actually review in, and it means opening the API
# documentation for a security product fetches third-party JavaScript. This
# inlines the renderer instead, so the artefact is a single file you can email,
# host internally, or open from a USB stick, and it renders identically in five
# years when that CDN path has moved.
#
#   ./scripts/ci/build-api-docs.sh              # -> docs/api/dist/index.html
#   API_DOCS_OUT=/tmp/x.html ./scripts/ci/build-api-docs.sh
LOG_TAG="api-docs"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

SPEC="$REPO_ROOT/docs/api/openapi.yaml"
OUT="${API_DOCS_OUT:-$REPO_ROOT/docs/api/dist/index.html}"
CACHE="$REPO_ROOT/.deploy-build/redoc.standalone.js"
REDOC_URL="https://cdn.redocly.com/redoc/v2.5.3/bundles/redoc.standalone.js"

[[ -f "$SPEC" ]] || die "no spec at $SPEC — run ./scripts/ci/gen-openapi.py first"

# The spec is generated from the source, so it must be current before we render
# it. A beautiful document of last month's API is the failure this avoids.
"$REPO_ROOT/scripts/ci/gen-openapi.py" --check >/dev/null \
  || die "openapi.yaml is out of date — run ./scripts/ci/gen-openapi.py"

mkdir -p "$(dirname "$OUT")" "$(dirname "$CACHE")"

if [[ ! -s "$CACHE" ]]; then
  log "fetching the renderer once into .deploy-build (cached, gitignored)"
  curl -sSfL "$REDOC_URL" -o "$CACHE" || die "could not fetch $REDOC_URL"
fi
ok "renderer $(wc -c <"$CACHE" | tr -d ' ') bytes (cached)"

log "inlining spec + renderer"
python3 - "$SPEC" "$CACHE" "$OUT" <<'PY'
import json, sys, pathlib
try:
    import yaml
except ImportError:
    sys.exit("python3 -m pip install pyyaml (needed to inline the spec)")

spec_path, redoc_path, out_path = sys.argv[1:4]
spec = yaml.safe_load(pathlib.Path(spec_path).read_text())
redoc = pathlib.Path(redoc_path).read_text()

# </script> anywhere inside the JSON would close the tag early.
spec_json = json.dumps(spec).replace("</", "<\\/")

html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eBPF-SOC platform API</title>
<style>
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .banner {{ background:#1F5C67; color:#fff; padding:12px 20px; font-size:14px; line-height:1.5; }}
  .banner strong {{ font-weight:650; }}
  .banner code {{ background:rgba(255,255,255,.15); padding:1px 5px; border-radius:3px; }}
  .banner a {{ color:#cfe9ee; }}
</style>
</head>
<body>
<div class="banner">
  <strong>Generated from source.</strong> Paths, methods and descriptions come from the Go
  handler registrations and are gated in CI, so they cannot drift.
  Request/response schemas are deliberately omitted rather than guessed — see
  <code>docs/api/integration-guide.md</code> for verified worked examples, and
  <code>docs/api/README.md</code> for the three-surface model.
  <br><strong>Internal document.</strong> This is a complete map of a security platform's API,
  including containment and kill-switch endpoints. Do not publish it publicly.
</div>
<div id="redoc"></div>
<script>{redoc}</script>
<script>
  Redoc.init(
    {spec_json},
    {{ scrollYOffset: 0, hideDownloadButton: true, expandResponses: "200",
       theme: {{ colors: {{ primary: {{ main: "#1F5C67" }} }} }} }},
    document.getElementById("redoc")
  );
</script>
</body>
</html>
"""
pathlib.Path(out_path).write_text(html)
print(f"  wrote {out_path} ({len(html)//1024} KiB)")
PY

# Prove it: no http(s) fetches at view time.
if grep -qoE '(src|href)="https?://' "$OUT"; then
  err "output still references an external URL — not self-contained"
  grep -oE '(src|href)="https?://[^"]+"' "$OUT" | sort -u | sed 's/^/  /'
  exit 1
fi
ok "self-contained: no external requests at view time"
ok "open it with: open $OUT"
