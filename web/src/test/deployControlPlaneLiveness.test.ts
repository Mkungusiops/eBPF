import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The deploy's closing "control plane live" line must be earned by the SERVICE.
 *
 * scripts/deploy/lib.sh used to decide it from one probe: `curl http://localhost/`
 * through nginx, accepting any 2xx/3xx. On the TLS estate the :80 vhost the same
 * file writes answers `301 -> https` from nginx's own config — no proxy_pass, no
 * upstream — so the green tick was printed from a reply nginx produces whether or
 * not the Go control plane behind it is running. That is the case the line exists
 * to catch, and it was the one case it could not see.
 *
 * These tests EXECUTE the shell rather than grepping it: lib.sh's provisioning is
 * driven entirely through a RUN() the entrypoints inject, so the verdict function
 * can be run for real against a stubbed target that reports whatever status codes
 * we choose. The stub answers each probe separately, which is the whole point —
 * the layers must be able to disagree.
 */

const LIB = "../scripts/deploy/lib.sh";

function bash(script: string): string {
  return execFileSync("bash", ["-c", script], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" }
  });
}

/** `undefined` = the probe itself returned nothing (dropped transport, box
 *  mid-restart), which is not a status code. */
function emit(v: string | undefined): string {
  return v === undefined ? "return 1" : `echo "EBPF-HTTP-CODE|${v}"`;
}

/** Run _cp_liveness against a stubbed target. Four probes at most: the
 *  service's own loopback port, the plain-HTTP edge, the ORIGIN this deploy is
 *  about to print (via _origin_code), and — only when the verified origin probe
 *  failed on https — the same origin with verification off. */
function liveness(
  app: string | undefined,
  edge: string | undefined,
  origin: string | undefined = "200",
  scheme = "https",
  insecure: string | undefined = "000"
): string {
  const script = `
    source ${LIB}
    RUN() {
      case "$1" in
        *127.0.0.1:9090/readyz*)             ${emit(app)} ;;
        *"-k --resolve"*)                    ${emit(insecure)} ;;
        *https://*/readyz*|*127.0.0.1/readyz*) ${emit(origin)} ;;
        *http://localhost/*)                 ${emit(edge)} ;;
        *) return 0 ;;
      esac
    }
    TARGET_HOST=soc.example.test TARGET_SCHEME=${scheme} CP_HTTP_PORT=9090
    _cp_liveness 2>&1
  `;
  return bash(script);
}

/** The tick `ok()` prints; its absence is what "not confirmed live" looks like. */
const TICK = "✓";

describe("the deploy's control-plane liveness verdict", () => {
  it("passes a healthy TLS estate, whose edge answers 301 by design", () => {
    const out = liveness("200", "301", "200");
    expect(out).toContain(TICK);
    expect(out).toContain("control plane live at");
    // The first pass was right that a stricter EDGE test would fail a good
    // deploy. The strictness moved to the port nginx cannot answer for, so the
    // redirect must still read as healthy.
    expect(out).toContain("console HTTP 301");
  });

  it("does NOT claim live when only nginx answers and the service is down", () => {
    // Exactly the live-estate shape: :80 redirects (nginx alone), and nothing is
    // listening on the control plane's loopback port. The old one-probe check
    // printed a green tick here.
    const out = liveness("000", "301", "000");
    expect(out).not.toContain(TICK);
    expect(out).toContain("NOT confirmed live");
    // and it must say WHY the site may still look fine to a browser
    expect(out).toContain("no service");
  });

  it("does NOT claim live when the process is up but cannot read its store", () => {
    const out = liveness("503", "301", "503");
    expect(out).not.toContain(TICK);
    expect(out).toContain("NOT READY");
    expect(out).toContain("central store");
  });

  it("reports 'could not ask' — never 'down' — when the probe returns nothing", () => {
    const out = liveness(undefined, "301", undefined);
    expect(out).not.toContain(TICK);
    expect(out).toContain("could not ask");
    expect(out).toContain("NOT confirmed either way");
  });

  it("does NOT claim live when the service is ready but the edge serves nothing", () => {
    const out = liveness("200", "000", "200");
    expect(out).not.toContain(TICK);
    expect(out).toContain("nginx did not serve the console");
  });
});

/**
 * The fallback branch used to print ONE fixed sentence for every status code it
 * caught, and that sentence was false in two reachable states.
 */
describe("the liveness verdict describes what it measured, not a fixed story", () => {
  it("does not gloss an answered-but-wrong code as 'nothing is listening'", () => {
    // A renamed route: something DID answer on the control plane's port.
    const out = liveness("404", "301", "404");
    expect(out).not.toContain(TICK);
    expect(out).toContain("curl reported 404");
    expect(out).toContain("Something answered there");
    // The old text appended "000 means nothing is listening there" to every code
    // in this branch, including this one.
    expect(out).not.toContain("000 is curl's");
    expect(out).not.toContain("nothing is listening");
  });

  it("keeps the 000 gloss for the code it is actually about", () => {
    const out = liveness("000", "301", "000");
    expect(out).toContain("000 is curl's");
    expect(out).toContain("nothing is listening on that port");
    expect(out).not.toContain("Something answered there");
  });

  it("does not say nginx answered at the edge when nothing answered there", () => {
    // Whole box down: no service, no edge. The old line still read "nginx
    // answered 000 at the edge, so https://host/ can still serve a page".
    const out = liveness("000", "000", "000");
    expect(out).not.toContain(TICK);
    expect(out).toContain("nothing served http://localhost/ either");
    expect(out).not.toContain("can still serve a");
  });

  it("calls an unmeasured edge unmeasured", () => {
    const out = liveness("000", undefined, undefined);
    expect(out).toContain("the edge probe returned nothing");
    expect(out).not.toContain("can still serve a");
  });
});

/**
 * The tick names $TARGET_SCHEME://$TARGET_HOST/ — an origin no probe touched.
 * The loopback probes speak plain HTTP to :9090 and :80; on a TLS estate the
 * printed address is :443, a different server block and a certificate, and this
 * same file installs a `location /readyz { proxy_pass … }` in the vhost
 * specifically so a store-reachability probe can reach the control plane through
 * it. _origin_code is that probe.
 */
describe("the origin the ✓ names is now probed", () => {
  /** The curl argument string _origin_code hands to _http_code. _http_code
   *  captures RUN's stdout and drops its stderr, so the trace goes to a file. */
  function originProbe(scheme: string): string {
    return bash(`
      source ${LIB}
      TRACE="$(mktemp)"
      RUN() { printf 'CURL|%s\\n' "$1" >> "$TRACE"; printf 'EBPF-HTTP-CODE|200\\n'; }
      TARGET_HOST=soc.example.test TARGET_SCHEME=${scheme}
      _origin_code /readyz >/dev/null 2>&1
      cat "$TRACE"
    `);
  }

  it("dials :443 with the certificate VERIFIED on an https estate", () => {
    const cmd = originProbe("https");
    expect(cmd).toContain("--resolve soc.example.test:443:127.0.0.1");
    expect(cmd).toContain("https://soc.example.test/readyz");
    // --resolve pins the socket to loopback while still checking the cert. -k
    // would reach :443 too and prove nothing about it.
    expect(cmd).not.toContain("--insecure");
    expect(/(^|\s)-k(\s|$)/.test(cmd)).toBe(false);
  });

  it("goes through the vhost by Host header on a plain-http estate", () => {
    const cmd = originProbe("http");
    expect(cmd).toContain("-H 'Host: soc.example.test'");
    expect(cmd).toContain("http://127.0.0.1/readyz");
  });

  it("withholds the ✓ when the origin does not reach the control plane", () => {
    // Ready service, serving nginx, and the console origin 404s /readyz: a
    // renamed location block, or a :443 server that failed to load. Both probes
    // the old check had were green here.
    const out = liveness("200", "301", "404");
    expect(out).not.toContain(TICK);
    expect(out).toContain("answered 404 through it");
    expect(out).toContain("NOT confirmed live");
  });

  it("names a certificate the box refuses, instead of blaming the vhost", () => {
    // On https, curl says 000 both when nothing answers and when it will not
    // accept the certificate. Blaming the vhost for the second would be this
    // file's own defect in a new place — a working estate whose box lacks a CA
    // bundle told that its origin does not reach the service.
    const out = liveness("200", "301", "000", "https", "200");
    expect(out).not.toContain(TICK);
    expect(out).toContain("only with");
    expect(out).toContain("certificate verification OFF");
    expect(out).not.toContain("does not reach the service");
  });

  it("blames the origin when the unverified probe fails too", () => {
    const out = liveness("200", "301", "000", "https", "000");
    expect(out).not.toContain(TICK);
    expect(out).toContain("does not reach the service");
    expect(out).not.toContain("certificate verification OFF");
  });

  it("states what the ✓ still does not observe", () => {
    const out = liveness("200", "301", "200", "https");
    expect(out).toContain(TICK);
    expect(out).toContain("certificate verified for soc.example.test");
    expect(out).toContain("DNS, the firewall and the path from the internet are not checked here");
  });

  it("does not claim a verified certificate on a plain-http estate", () => {
    const out = liveness("200", "200", "200", "http");
    expect(out).toContain(TICK);
    expect(out).not.toContain("certificate verified");
    expect(out).toContain("not checked here");
  });
});

describe("the probes the verdict is built from", () => {
  const lib = readFileSync(LIB, "utf8");

  it("asks the control plane's own loopback port, which nginx cannot answer for", () => {
    // The port is loopback-bound in the unit's ExecStart, which is what makes a
    // reply there proof of the Go process rather than of anything in front of it.
    expect(lib).toContain('-http 127.0.0.1:$CP_HTTP_PORT');
    expect(lib).toContain('_http_code "http://127.0.0.1:$CP_HTTP_PORT/readyz"');
  });

  it("uses /readyz, which exercises the store, not the constant /healthz", () => {
    const readyz = readFileSync("../engine/internal/controlplane/http.go", "utf8");
    // Guard the guard: if /readyz stopped touching the store, a 200 from it would
    // mean no more than /healthz does and this check would be back where it was.
    expect(readyz).toContain("func (s *Server) handleReadyz");
    expect(readyz).toMatch(/handleReadyz[\s\S]{0,400}cfg\.Store\.Count/);
    // /healthz is named in lib.sh's own comment explaining the choice; what must
    // not exist is a PROBE pointed at it.
    expect(lib).not.toMatch(/_http_code\s+"[^"]*healthz/);
  });

  it("returns an empty code, not a status, when no marker comes back", () => {
    // _http_code's contract: curl's 000 is a measurement, silence is not, and the
    // two must not collapse into one string.
    const out = bash(
      `source ${LIB}; RUN() { echo "transport noise"; }; printf "[%s]" "$(_http_code http://x/)"`
    );
    expect(out).toBe("[]");
  });
});

/**
 * The single-tenant engine's two verdicts. They were inline in provision_engine —
 * 300 lines of docker, tar and heredocs around them — so nothing could execute
 * them. They are now _engine_up_or_die and _engine_edge_verdict, and this is what
 * they say in each reachable state.
 */
describe("the engine's own-port verdict", () => {
  function upOrDie(code: string | undefined): { out: string; status: number } {
    try {
      const out = bash(`
        source ${LIB}
        RUN() { ${emit(code)} ; }
        TARGET_HOST=10.0.0.5 ENGINE_PORT=8090
        _engine_up_or_die 2>&1; echo "SURVIVED"
      `);
      return { out, status: 0 };
    } catch (e) {
      const err = e as { status: number; stdout: string };
      return { out: err.stdout, status: err.status };
    }
  }

  it("passes silently when the engine answers 200 on its own port", () => {
    const r = upOrDie("200");
    expect(r.status).toBe(0);
    expect(r.out).toContain("SURVIVED");
  });

  it("dies with the code when the engine answers something else", () => {
    const r = upOrDie("502");
    expect(r.status).toBe(1);
    expect(r.out).toContain("engine did not come up (HTTP 502)");
    expect(r.out).not.toContain("SURVIVED");
  });

  it("says 'could not ask' — not 'did not come up' — when the probe returns nothing", () => {
    // A verdict on a measurement that does not exist is the defect this whole
    // file is about; here it is still fatal, but it must not claim the engine is
    // down when nothing was observed.
    const r = upOrDie(undefined);
    expect(r.status).toBe(1);
    expect(r.out).toContain("could not ask the target whether the engine came up");
    expect(r.out).toContain("cannot say either way");
    expect(r.out).not.toContain("did not come up");
  });
});

describe("the engine's front-door verdict", () => {
  function edge(code: string | undefined, scheme = "https"): string {
    return bash(`
      source ${LIB}
      RUN() { ${emit(code)} ; }
      TARGET_HOST=engine.example.test TARGET_SCHEME=${scheme}
      ENGINE_USER=admin ENGINE_PASS=secret ENGINE_PORT=8090
      _engine_edge_verdict 2>&1
    `);
  }

  it("passes a redirect, which is what a TLS box's :80 correctly answers", () => {
    const out = edge("301");
    expect(out).toContain(TICK);
    expect(out).toContain("engine live at https://engine.example.test/");
    expect(out).toContain("answered HTTP 301");
    expect(out).toContain("admin / secret");
  });

  it("says a 000 on https can be the certificate, not only a dead vhost", () => {
    const out = edge("000", "https");
    expect(out).not.toContain(TICK);
    expect(out).toContain("a certificate this box would not accept");
  });

  it("does not offer the certificate explanation on a plain-http estate", () => {
    const out = edge("000", "http");
    expect(out).not.toContain(TICK);
    expect(out).toContain("nginx did not serve engine.example.test (000)");
    expect(out).not.toContain("a certificate this box would not accept");
  });

  it("withholds the ✓ when nginx does not serve the host", () => {
    const out = edge("502");
    expect(out).not.toContain(TICK);
    expect(out).toContain("nginx did not serve engine.example.test (502)");
    expect(out).toContain("NOT confirmed reachable");
    // the credentials are still printed, just not as a live login
    expect(out).toContain("login when it is: admin / secret");
  });

  it("separates 'the probe said nothing' from 'the front door failed'", () => {
    const out = edge(undefined);
    expect(out).not.toContain(TICK);
    expect(out).toContain("could not ask whether nginx serves engine.example.test");
    expect(out).toContain("NOT confirmed either way");
    expect(out).not.toContain("nginx did not serve");
  });

  it("earns an https line with an https request, not a plain-HTTP one", () => {
    const cmd = bash(`
      source ${LIB}
      TRACE="$(mktemp)"
      RUN() { printf 'CURL|%s\\n' "$1" >> "$TRACE"; printf 'EBPF-HTTP-CODE|200\\n'; }
      TARGET_HOST=engine.example.test TARGET_SCHEME=https
      ENGINE_USER=admin ENGINE_PASS=secret
      _engine_edge_verdict >/dev/null 2>&1
      cat "$TRACE"
    `);
    expect(cmd).toContain("https://engine.example.test/");
    expect(cmd).toContain("--resolve engine.example.test:443:127.0.0.1");
  });
});

/**
 * Ordering, executed. Two ✓ lines in provision_engine described
 * devchoke_protect / devchoke_obj / devchoke_ifaces some 70 lines BEFORE the
 * engine.yaml heredoc that carries them — in the same function whose "choke
 * thresholds" line had just been moved after that heredoc for exactly this
 * reason. The test runs provision_engine for real against a stubbed driver and
 * compares positions in one merged stream: the RUN trace goes to stderr, the
 * ticks to stdout, and 2>&1 makes the order of the two the order of events.
 */
function provisionEngine(iface: string | null): { out: string; yaml: string } {
  const dir = mkdtempSync(join(tmpdir(), "ebpf-prov-"));
  writeFileSync(join(dir, "engine"), "#!/bin/sh\n");
  const yamlFile = join(dir, "engine.yaml.written");
  const out = bash(`
    source ${LIB}
    YAMLFILE=${JSON.stringify(yamlFile)}
    RUN() {
      printf 'RUN|%s\\n' "$1" | sed -n 1p >&2
      case "$1" in
        *EBPF-HTTP-CODE*)                    printf 'EBPF-HTTP-CODE|200\\n' ;;
        "gw="*)                              printf 'aa:bb:cc:dd:ee:ff\\n' ;;
        "ip -o -4 route show default"*)      ${iface === null ? ":" : `printf '%s\\n' ${JSON.stringify(iface)}`} ;;
        "hostname -s"*)                      printf 'testbox\\n' ;;
        *"cat > /etc/ebpf-engine/engine.yaml"*) printf '%s\\n' "$1" > "$YAMLFILE" ;;
      esac
      return 0
    }
    PUT() { return 0; }
    PKG() { return 0; }
    BUILD_DIR=${JSON.stringify(dir)}
    TARGET_HOST=10.0.0.5 TARGET_SCHEME=http
    ENGINE_MODE=fake ENGINE_PASS=secret ENGINE_PORT=8090 DEVCHOKE=1
    provision_engine 2>&1
  `);
  return { out, yaml: readFileSync(yamlFile, "utf8") };
}

describe("provision_engine reports the device-choke keys after writing them", () => {
  it("writes engine.yaml BEFORE it ticks the values that config carries", () => {
    const { out, yaml } = provisionEngine("eth0");
    // the write really did carry them — otherwise the ordering below is vacuous
    expect(yaml).toContain("devchoke_protect: aa:bb:cc:dd:ee:ff");
    expect(yaml).toContain("devchoke_ifaces: eth0");

    const wrote = out.indexOf("RUN|umask 077; cat > /etc/ebpf-engine/engine.yaml");
    const protectTick = out.indexOf("protected MACs: aa:bb:cc:dd:ee:ff");
    const planeTick = out.indexOf("device data plane compiled");
    expect(wrote).toBeGreaterThan(-1);
    expect(protectTick).toBeGreaterThan(-1);
    expect(planeTick).toBeGreaterThan(-1);
    // A ✓ printed ahead of the thing it describes is a claim about work that has
    // not happened yet — the rule already written above the thresholds line.
    expect(protectTick).toBeGreaterThan(wrote);
    expect(planeTick).toBeGreaterThan(wrote);
  });

  it("does not claim a data plane on an interface that never resolved", () => {
    // The lookup's stderr is silenced and it can come back empty. The line then
    // read "device data plane compiled (tc on )" — and the blank devchoke_ifaces
    // it wrote leaves the engine on the noop backend anyway, because hoststack
    // loads tc only with an object AND at least one interface.
    const { out, yaml } = provisionEngine(null);
    expect(out).not.toContain("device data plane compiled");
    expect(out).toContain("no default-route interface resolved");
    expect(out).toContain("stays on the noop backend");
    expect(yaml).not.toContain("devchoke_ifaces");
    expect(yaml).not.toContain("devchoke_obj");
    // the protect list is a SAFETY control and is still written and reported
    expect(yaml).toContain("devchoke_protect: aa:bb:cc:dd:ee:ff");
    expect(out).toContain("protected MACs: aa:bb:cc:dd:ee:ff");
  });
});

/**
 * provision_tls's early return decided "TLS is fine" from `test -s
 * fullchain.pem`. A file existing is not a certificate that works: an expired
 * one satisfied it, so the deploy skipped renewal, printed a green line and set
 * the caller's scheme to https, and every browser then met a TLS interstitial.
 */
function provisionTls(certPresent: boolean, notExpiring: boolean): string {
  return bash(`
    source ${LIB}
    RUN() {
      printf 'RUN|%s\\n' "$1" | sed -n 1p >&2
      case "$1" in
        *checkend*)     return ${certPresent && notExpiring ? 0 : 1} ;;
        *fullchain.pem*) return ${certPresent ? 0 : 1} ;;
        *acme-challenge/.probe*) printf 'probe\\n' ;;
      esac
      return 0
    }
    PUT() { return 0; }
    PKG() { return 0; }
    TARGET_HOST=soc.example.test
    # provision_tls returns non-zero when it could not produce a certificate, and
    # lib.sh's set -e would otherwise kill the harness before we can read what it
    # said.
    provision_tls soc.example.test 2>&1 || true
  `);
}

describe("provision_tls's 'already have a certificate' shortcut", () => {
  it("takes the shortcut only for a cert that is still valid", () => {
    const out = provisionTls(true, true);
    expect(out).toContain(TICK);
    expect(out).toContain("valid for at least 7 more days");
    expect(out).not.toContain("certbot certonly");
  });

  it("renews instead of trusting a certificate that has expired", () => {
    const out = provisionTls(true, false);
    expect(out).toContain("expired, expires within 7 days, or could not be read");
    expect(out).toContain("RUN|certbot certonly");
    expect(out).not.toContain("valid for at least 7 more days");
  });

  it("still requests one when there is no certificate at all", () => {
    const out = provisionTls(false, false);
    expect(out).toContain("RUN|certbot certonly");
    expect(out).not.toContain("valid for at least 7 more days");
    // nothing on disk afterwards is a failure, not a green line
    expect(out).toContain("no cert on disk");
    expect(out).not.toContain(TICK);
  });
});

/**
 * The same shape, one function up: `_ship_intel` printed its ✓ unconditionally,
 * so an empty deploy/intel/ (a bad checkout, a tarball that lost the directory)
 * reported "threat-intel feeds shipped" after shipping nothing — while the box
 * kept matching against whatever indicators it already had.
 */
function shipIntel(srcRoot: string, operatorFilesExist = false): string {
  return bash(`
    source ${LIB}
    # RUN's only decision here is the operator-owned "[ -e … ]" test.
    RUN() { case "$1" in *"[ -e "*) return ${operatorFilesExist ? 0 : 1};; esac; return 0; }
    PUT() { echo "PUT $2"; }
    REPO_ROOT=${JSON.stringify(srcRoot)}
    _ship_intel 2>&1
  `);
}

describe("the deploy's threat-intel shipping line", () => {
  const repoRoot = join(process.cwd(), "..");

  it("reports the count of files it actually sent", () => {
    const out = shipIntel(repoRoot);
    const sent = [...out.matchAll(/^PUT /gm)].length;
    expect(sent).toBeGreaterThan(0);
    expect(out).toContain(TICK);
    expect(out).toContain(`threat-intel: ${sent} file(s) shipped`);
  });

  it("does not claim files were shipped when the source directory is empty", () => {
    const empty = mkdtempSync(join(tmpdir(), "ebpf-intel-"));
    mkdirSync(join(empty, "deploy", "intel"), { recursive: true });
    const out = shipIntel(empty);
    expect(out).not.toContain(TICK);
    expect(out).toContain("NO feed files were shipped");
  });

  it("says so, without a bare zero, when every file on the target is operator-owned", () => {
    const out = shipIntel(repoRoot, true);
    // allow.txt and feeds.yaml are kept; starter.low.txt is still shipped. The
    // count must be files SENT, not files found — the kept ones did not move.
    const sent = [...out.matchAll(/^PUT /gm)].length;
    expect(sent).toBeGreaterThan(0);
    expect(out).toContain(`threat-intel: ${sent} file(s) shipped`);
    expect(out).toContain("operator-owned file(s) left untouched");
    expect(out).not.toContain("0 operator-owned");
  });
});

/**
 * And the copy of that defect that survived one file over. Every agent host in
 * the estate is provisioned by provision-agent-ssh.sh, whose intel loop ended in
 * an UNCONDITIONAL "threat-intel feeds shipped to /etc/ebpf-soc/intel" — the
 * exact line _ship_intel was fixed for, on the hosts that do the detecting.
 *
 * That script cannot be sourced (it ssh's to the target during its own
 * preflight), so the function is lifted out of the file and executed against
 * stubbed m/push. The extraction is asserted, or an empty eval would make every
 * expectation below pass against nothing.
 */
function agentShipIntel(srcRoot: string, operatorFilesExist = false): string {
  return bash(`
    eval "$(sed -n '/^ship_intel() {/,/^}/p' ../scripts/deploy/provision-agent-ssh.sh)"
    declare -F ship_intel >/dev/null || { echo "EXTRACTION FAILED"; exit 0; }
    log()  { printf 'LOG %s\\n' "$*"; }
    ok()   { printf '✓ %s\\n' "$*"; }
    warn() { printf '! %s\\n' "$*"; }
    m()    { case "$1" in *"[ -e "*) ${operatorFilesExist ? 'echo yes' : ':'} ;; esac; return 0; }
    push() { cat >/dev/null; printf 'PUSH %s\\n' "$1"; }
    REPO_ROOT=${JSON.stringify(srcRoot)}
    ship_intel 2>&1
  `);
}

describe("the agent provisioner's threat-intel line", () => {
  const repoRoot = join(process.cwd(), "..");

  it("counts what it sent", () => {
    const out = agentShipIntel(repoRoot);
    expect(out).not.toContain("EXTRACTION FAILED");
    const sent = [...out.matchAll(/^PUSH /gm)].length;
    expect(sent).toBeGreaterThan(0);
    expect(out).toContain(TICK);
    expect(out).toContain(`threat-intel: ${sent} file(s) shipped`);
  });

  it("does not report feeds shipped when it shipped none", () => {
    const empty = mkdtempSync(join(tmpdir(), "ebpf-agent-intel-"));
    mkdirSync(join(empty, "deploy", "intel"), { recursive: true });
    const out = agentShipIntel(empty);
    expect(out).not.toContain("EXTRACTION FAILED");
    expect(out).not.toContain(TICK);
    expect(out).toContain("NO feed files were shipped");
    expect(out).toContain("whatever indicators it already had");
  });

  it("says the directory is missing rather than saying nothing at all", () => {
    // A tarball that lost deploy/intel used to skip the whole block in silence:
    // the agent then matched against whatever it already had, with no line in the
    // deploy log either way.
    const gone = mkdtempSync(join(tmpdir(), "ebpf-agent-nointel-"));
    const out = agentShipIntel(gone);
    expect(out).not.toContain("EXTRACTION FAILED");
    expect(out).not.toContain(TICK);
    expect(out).toContain("is not there");
  });

  it("keeps the operator's allow.txt and counts only what moved", () => {
    const out = agentShipIntel(repoRoot, true);
    const sent = [...out.matchAll(/^PUSH /gm)].length;
    expect(out).toContain(`threat-intel: ${sent} file(s) shipped`);
    expect(out).toContain("operator-owned file(s) left untouched");
    expect(out).toContain("keeping the existing /etc/ebpf-soc/intel/allow.txt");
    expect(out).not.toContain("0 operator-owned");
  });
});
