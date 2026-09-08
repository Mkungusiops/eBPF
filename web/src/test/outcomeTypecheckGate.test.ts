import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

/**
 * THE GATE MUST FAIL ON A CONSOLE THAT WILL NOT BUILD.
 *
 * vitest does not typecheck. Nothing about a green test run says the TypeScript
 * compiles — and in the change set before this one it did not: `tsc -b` was
 * broken for two full rounds of fix-then-verify while 741 tests reported
 * passing, because every gate anyone ran was a vitest gate. CI did run
 * `npm run typecheck` in its own step, but the work was verified and deployed
 * from a workstation, where "the tests are green" was the whole check.
 *
 * The fix is wiring, not a new command: `npm test` and `npm run test:coverage`
 * run the typecheck themselves, so a type error fails the SAME invocation a
 * failing test fails, whoever runs it.
 *
 * WHAT THIS FILE ASSERTS, AND HOW
 *
 * It runs `npm test` — the command a human or an agent actually types — as a
 * child process, twice, and compares the two EXIT STATUSES:
 *
 *   clean tree            -> exit 0, and the output shows vitest was reached
 *   one .ts file with a
 *   deliberate type error -> non-zero, the output names that file and TS2322,
 *                            and vitest was never reached
 *
 * That pair is the whole point. The two previous versions of this file pinned a
 * SPELLING: they lifted the tsc invocation out of package.json and spawned the
 * compiler themselves, which proves that string catches type errors but never
 * that `npm test`'s exit status depends on it. Nothing about npm was exercised,
 * so any change to how the stages are SEQUENCED slipped through — replacing the
 * `&&` with `;` (or otherwise swallowing the status) prints the type error,
 * runs vitest anyway, and exits with vitest's 0. That mutation was measured
 * against this file: it fails, on the exit status of the second run.
 *
 * Two more were measured and fail on that same exit status: deleting
 * `npm run typecheck &&` from the script, and pointing the typecheck at a
 * project that reads no console source, so that it compiles this repo without
 * ever seeing the error (measured by retargeting `-p` at a project whose
 * `include` omits src; an empty `include` or a `--noCheck` is the same defect).
 *
 * NEUTRALISING THE VITEST HALF, AND WHY IT IS NOT A DIFFERENT COMMAND
 *
 * `npm test` from inside `npm test` would re-enter this suite — 864 tests, this
 * file among them, recursively. So the child is invoked as
 *
 *   npm test -- --passWithNoTests <a filter no test file can match>
 *
 * npm appends `--` arguments to the END of the script, i.e. to `vitest run`; the
 * `npm run typecheck` stage in front of it is untouched, which is the half under
 * test. vitest then collects zero files and exits 0 instead of recursing. The
 * shape that makes this safe is asserted below (the typecheck stage runs first,
 * the vitest stage is last), and a `_CHILD` env guard skips this describe block
 * outright in the child as a second layer, in case a future filter change ever
 * matches a real file.
 *
 * THE DELIBERATE ERROR NEVER GOES IN TRACKED SOURCE
 *
 * The previous version appended a bad line to `src/app/render.tsx`, a tracked,
 * shipping file, on every run of the default suite — in a tree several agents
 * share, that is a fabricated type error in someone else's diff. Here the error
 * goes in a file this test creates and owns: `src/test/__typecheckGateProbe.
 * <pid>.ts`, untracked, inside `include: ["src", ...]` so the real tsconfig
 * really compiles it. No tracked file is ever written.
 *
 * WHAT THIS FILE DOES NOT COVER — none of the following is detectable here, and
 * the assertions above are narrower than they may read:
 *
 * - Coverage of any file other than the probe. It sits in `src/test`, so it
 *   proves that subtree is compiled and nothing more: a tsconfig narrowed to
 *   `src/test`, or one that dropped `e2e`, still passes every assertion here.
 * - Whether a human types `npm test` rather than `vitest run`. On a workstation
 *   that is unenforceable by any test; the CI assertion below is the stand-in,
 *   and it binds CI only.
 * - Whether CI's runner honours `needs:`, or that the workflow file read here is
 *   the one that ran. That assertion reads YAML, not a run.
 * - `npm run test:coverage`. It is asserted to resolve to the SAME single tsc
 *   command as `npm test`, which is why one child run speaks for both — but it
 *   is never itself executed here.
 * - A gate that fails only INTERMITTENTLY. Each direction is one invocation.
 * - Anything, on a tree that does not compile for an unrelated reason: the clean
 *   direction then fails and says so, rather than reporting a verdict on the
 *   gate. Under `npm test` that is unreachable — the outer typecheck fails
 *   first, so this file never runs; it was seen under a bare `npx vitest run`
 *   while another agent was mid-edit, which is the only way in.
 *
 * WHILE THE PROBE EXISTS, THIS TREE DOES NOT TYPECHECK. That is unavoidable:
 * the gate compiles a fixed project, so proving it goes red means making that
 * project red for the length of the one `npm test` that dies in the
 * typechecker. Measured on this tree, the two child runs together take ~30s on
 * an idle machine and ~90s with several agents' suites running beside them —
 * that, and a probe window of roughly a third of it, is what this file costs. A
 * concurrent typecheck inside that window fails naming
 * `__typecheckGateProbe.<pid>.ts`, and that file says in its first line what it
 * is, so the window is diagnosable rather than mysterious.
 */

/** web/ — the directory the gate is run from, and where vitest is started. */
const WEB = resolve(".");
const PACKAGE = JSON.parse(readFileSync(join(WEB, "package.json"), "utf8")) as {
  scripts: Record<string, string>;
};

/**
 * Set on the child `npm test`. If the child ever DID collect this file — a
 * filter that stopped matching nothing, a vitest that ignored it — the describe
 * block skips instead of spawning a grandchild, so the failure is a skipped
 * test rather than a fork bomb on a shared machine.
 */
const CHILD_ENV = "OUTCOME_TYPECHECK_GATE_CHILD";

/** A vitest positional filter no path under src/ can match. */
const NO_SUCH_SPEC = "__outcome_typecheck_gate_matches_no_file__";

const PROBE_DIR = join(WEB, "src", "test");
const PROBE_PATTERN = /^__typecheckGateProbe\.(\d+)\.ts$/;
const PROBE_NAME = `__typecheckGateProbe.${process.pid}.ts`;
/** Relative, because that is how tsc names the file in its diagnostics. */
const PROBE_REL = `src/test/${PROBE_NAME}`;
const PROBE_SOURCE =
  "// Written by src/test/outcomeTypecheckGate.test.ts to prove `npm test` fails\n" +
  "// on a type error. Deleted again by that test. If git status or a red\n" +
  "// typecheck is showing you this file, a run of that test was killed before\n" +
  "// it could clean up: delete the file.\n" +
  'export const typecheckGateProbe: number = "deliberate type error";\n';

/** Split a shell script on `&&` / `;` — the sequencing npm scripts actually use. */
function stages(script: string): string[] {
  return script
    .split(/&&|;/)
    .map((stage) => stage.trim())
    .filter(Boolean);
}

/**
 * Every leaf command a script runs, with `npm run <other>` expanded in place —
 * which is how a type error in a nested script still fails the outer one.
 */
function leafCommands(scriptName: string, seen = new Set<string>()): string[] {
  if (seen.has(scriptName)) return []; // a script that calls itself would hang npm too
  seen.add(scriptName);
  const script = PACKAGE.scripts[scriptName];
  if (!script) return [];
  return stages(script).flatMap((stage) => {
    const nested = /^npm\s+(?:run|run-script)\s+(\S+)/.exec(stage);
    if (nested) return leafCommands(nested[1], seen);
    // `npm test` is a built-in alias for the `test` script.
    if (/^npm\s+(?:test|t)\b/.test(stage)) return leafCommands("test", seen);
    return [stage];
  });
}

/** The leaf commands that invoke the TypeScript compiler. */
function typecheckCommands(scriptName: string): string[] {
  return leafCommands(scriptName).filter((command) => /^(npx\s+)?tsc\b/.test(command));
}

/**
 * Run the real gate: `npm test`, from web/, with only its vitest half disarmed.
 *
 * Nothing about the command is reconstructed from package.json — that is what
 * the earlier versions of this file did wrong. npm reads the script, npm
 * sequences the stages, and the status returned is the one npm exits with, so a
 * gate that stops depending on the typecheck reports differently here.
 *
 * VITEST_* and NODE_ENV are inherited deliberately (the child is a plain nested
 * npm run, as it would be from a shell); only the recursion guard is added.
 */
function runGate(): { status: number; output: string } {
  const result = spawnSync("npm", ["test", "--", "--passWithNoTests", NO_SUCH_SPEC], {
    cwd: WEB,
    encoding: "utf8",
    env: { ...process.env, [CHILD_ENV]: "1" },
  });
  if (result.error) throw new Error(`could not run \`npm test\`: ${result.error.message}`);
  return { status: result.status ?? -1, output: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

/**
 * Did the run get past the typecheck into vitest?
 *
 * npm echoes the script line, so the word "vitest" appears even in the output of
 * a run that died in tsc; only vitest's own banner (or its no-files message)
 * says it actually started. The red direction asserts vitest was NOT reached,
 * and that is what keeps the non-zero status attributable to the typecheck: with
 * `typecheck ; vitest` sequencing the status is vitest's, and a run whose vitest
 * half failed for its own reasons would otherwise read exactly like a gate that
 * caught the type error.
 */
function reachedVitest(output: string): boolean {
  return /\bRUN\b\s+v\d/.test(output) || /No test files found/.test(output);
}

/**
 * Delete probe files left by runs that are no longer alive.
 *
 * A run killed mid-tsc (SIGKILL, a cancelled job) reaches no `finally`, and its
 * probe then breaks the typecheck for everyone in this shared tree until the
 * next run of this test sweeps it. The pid in the name says which are safe to
 * remove: signal 0 tests for existence without delivering anything, and only
 * ESRCH ("no such process") means dead — EPERM is a live process this user
 * cannot signal. A probe whose owner is still running belongs to a concurrent
 * run mid-compile and must be left exactly where it is. A recycled pid now held
 * by an unrelated process reads as live, so that probe waits for a later sweep;
 * erring that way cannot break a running compile.
 */
function sweepStaleProbes(): void {
  for (const name of readdirSync(PROBE_DIR)) {
    const owner = PROBE_PATTERN.exec(name);
    if (!owner) continue;
    const pid = Number(owner[1]);
    // Our own pid can only be a leftover from an earlier run that died holding
    // this pid — this run's probe is written after the sweep, never before it.
    if (pid !== process.pid) {
      try {
        process.kill(pid, 0);
        continue; // alive: someone else's compile is depending on it
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") continue;
      }
    }
    rmSync(join(PROBE_DIR, name), { force: true });
  }
}

/**
 * Create the probe, run `body`, delete the probe.
 *
 * Two layers here, because the file must not outlive the run: the `finally`
 * covers a thrown assertion, and the `exit` hook covers vitest bailing out
 * without unwinding. Neither can cover SIGKILL — nothing in-process can — so the
 * guarantee there is weaker and worth stating plainly: the file is untracked and
 * named after this pid, so the worst a killed run leaves behind is one
 * obviously-labelled file, which the sweep at the top of the next run of this
 * test deletes. No tracked file is ever written, in any outcome.
 */
function withProbe<T>(body: () => T): T {
  const onExit = () => rmSync(join(PROBE_DIR, PROBE_NAME), { force: true });
  writeFileSync(join(PROBE_DIR, PROBE_NAME), PROBE_SOURCE);
  process.once("exit", onExit);
  try {
    return body();
  } finally {
    process.off("exit", onExit);
    rmSync(join(PROBE_DIR, PROBE_NAME), { force: true });
  }
}

describe.skipIf(process.env[CHILD_ENV])("a type error fails the same command a failing test fails", () => {
  it("routes every gate script through the typechecker, from web/", () => {
    // Both are gates: `npm test` is what a developer runs, `npm run
    // test:coverage` is what CI runs. Neither may be able to pass on source
    // that does not compile.
    for (const gate of ["test", "test:coverage"]) {
      expect(PACKAGE.scripts[gate], `there is no ${gate} script to gate on`).toBeTruthy();
      expect(
        typecheckCommands(gate),
        `\`npm run ${gate}\` resolves to [${leafCommands(gate).join(" | ")}], none of which typechecks: ` +
          "vitest reports green over TypeScript that will not build"
      ).not.toEqual([]);
      // And it must still run the tests, or the "gate" passes by doing less.
      expect(
        leafCommands(gate).some((command) => /vitest/.test(command)),
        `\`npm run ${gate}\` no longer runs vitest`
      ).toBe(true);
      // The child below runs `npm test` from web/. A stage that changed
      // directory first would compile a different project than a developer's
      // `npm test` does, and the run's verdict would not be the gate's.
      expect(
        leafCommands(gate).filter((command) => /^(cd|pushd|chdir)\b/.test(command)),
        `\`npm run ${gate}\` changes directory, so the gate no longer runs from web/`
      ).toEqual([]);
    }

    // One injected error can only speak for the command it is run against. Hold
    // the gates to a single shared typecheck so that one child run covers both,
    // and so a second, unexercised typecheck cannot be added beside a proven one.
    const commands = [...new Set(typecheckCommands("test"))];
    expect(commands, "`npm test` runs more than one distinct typecheck; only one of them is exercised below").toHaveLength(1);
    expect(
      [...new Set(typecheckCommands("test:coverage"))],
      "`npm run test:coverage` typechecks differently from `npm test`, so proving one says nothing about the other"
    ).toEqual(commands);

    // `tsc -b` reports "up to date" out of tsconfig.tsbuildinfo. A gate whose
    // green can come from a stale cache is the same defect as a gate nobody runs.
    expect(commands[0], "the gate typechecks in build mode, which answers from a cache").not.toMatch(
      /(^|\s)(-b|--build)(\s|$)/
    );

    // Preconditions for disarming the vitest half with `npm test -- <args>`:
    // npm appends those args to the END of the script, so the last stage must be
    // the vitest one (or the args would land on tsc and the run would fail for
    // the wrong reason), and the typecheck must come before it.
    const testStages = stages(PACKAGE.scripts.test);
    expect(testStages[testStages.length - 1], "`npm test`'s last stage is not the vitest run").toMatch(/vitest/);
    expect(
      testStages.findIndex((stage) => /typecheck|tsc\b/.test(stage)),
      "`npm test`'s first stage is not the typecheck"
    ).toBe(0);
  });

  it("exits 0 clean and non-zero with a type error in a file the real tsconfig covers", () => {
    sweepStaleProbes();

    // Direction 1: the gate as it stands, on this tree, exits 0 — so a non-zero
    // in direction 2 is the injected error and not a gate that fails
    // everything. It also shows the disarmed vitest half is reached when the
    // typecheck passes, which is what gives "vitest was never reached" below
    // its meaning.
    const clean = runGate();
    const otherProbe = /__typecheckGateProbe\.\d+\.ts/.exec(clean.output);
    expect(
      otherProbe?.[0],
      `a concurrent run of this test had ${otherProbe?.[0]} in the tree while this one compiled, so this run proves nothing — re-run it`
    ).toBeUndefined();
    expect(
      clean.status,
      "`npm test` does not pass on the tree as it stands, so the direction below is not attributable to the " +
        "injected error. This says the console does not compile right now — a concurrent edit mid-save, or a real " +
        `breakage — not that the gate is broken:\n${clean.output}`
    ).toBe(0);
    expect(reachedVitest(clean.output), `\`npm test\` never reached vitest on a clean tree:\n${clean.output}`).toBe(true);

    // Direction 2: same command, one file with one bad type.
    const broken = withProbe(() => {
      const result = runGate();
      // Checked before the verdict: `git clean -fd` from a concurrent agent
      // deletes the probe (it is untracked), tsc then compiles a clean tree and
      // exits 0, and that would read as "the gate passed a type error".
      return { result, held: existsSync(join(PROBE_DIR, PROBE_NAME)) };
    });
    expect(broken.held, `${PROBE_REL} was deleted by something else while the gate compiled — re-run this test`).toBe(true);
    expect(
      broken.result.status,
      `\`npm test\` exited 0 with a type error in ${PROBE_REL}: the gate no longer depends on the typecheck\n${broken.result.output}`
    ).not.toBe(0);
    // Naming the file and the code rules out a red that came from somewhere
    // else — a pre-existing error, or an npm that failed to start.
    expect(broken.result.output, `\`npm test\` failed, but not on the error in ${PROBE_REL}:\n${broken.result.output}`).toContain(PROBE_REL);
    expect(broken.result.output).toMatch(/TS2322/);
    // And npm's non-zero must be the TYPECHECK's. With `typecheck ; vitest` the
    // error is printed, vitest runs anyway, and npm exits with vitest's status.
    expect(
      reachedVitest(broken.result.output),
      `\`npm test\` ran vitest after the typecheck failed, so its exit status is vitest's:\n${broken.result.output}`
    ).toBe(false);

    expect(existsSync(join(PROBE_DIR, PROBE_NAME)), "the probe file was left behind").toBe(false);
    // Two full `npm test` startups plus two whole-project typechecks. The
    // timeout is far above the ~90s measured under load on purpose: a shared
    // gate that goes red when the machine is busy is the same defect as a gate
    // nobody runs.
  }, 600_000);
});

describe("CI fails the same way", () => {
  const CI = readFileSync(resolve("..", ".github", "workflows", "ci.yml"), "utf8");

  /** The workflow's jobs, by name — job keys are the only 2-space keys under `jobs:`. */
  function jobs(): Map<string, string> {
    const marker = "\njobs:\n";
    const start = CI.indexOf(marker);
    expect(start, "ci.yml declares no jobs").toBeGreaterThan(-1);
    const out = new Map<string, string>();
    let name: string | null = null;
    let body: string[] = [];
    for (const line of CI.slice(start + marker.length).split("\n")) {
      const header = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
      if (header) {
        if (name) out.set(name, body.join("\n"));
        name = header[1];
        body = [];
        continue;
      }
      if (name) body.push(line);
    }
    if (name) out.set(name, body.join("\n"));
    return out;
  }

  it("runs the web gate in a job that blocks the signed image", () => {
    const all = jobs();
    const gate = [...all].filter(([, body]) => /npm run test:coverage|npm (run )?test\b/.test(body));
    expect(gate.map(([name]) => name), "no CI job runs the web test gate").not.toEqual([]);

    const image = all.get("image");
    expect(image, "ci.yml no longer builds the container image").toBeDefined();
    const needs = /^\s*needs:\s*\[(.*)\]/m.exec(image ?? "");
    expect(needs, "the image job declares no `needs`, so nothing gates it").not.toBeNull();
    const required = (needs?.[1] ?? "").split(",").map((entry) => entry.trim());
    for (const [name] of gate) {
      expect(
        required,
        `the ${name} job runs the web gate but is not in image.needs, so a red gate would still publish a signed image`
      ).toContain(name);
    }
  });
});
