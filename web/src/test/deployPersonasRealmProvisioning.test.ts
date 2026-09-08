import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * The realm must contain every role the platform enforces.
 *
 * authz.go defines four roles. scripts/deploy/lib.sh provisioned two of them,
 * and the gap was invisible from every direction: the Go tests build their
 * Principals by hand, the mocked e2e suite answers whoami from page.route(),
 * and the live probe specs for the missing two — the ONLY measurement of who
 * may fire containment against a real deployment — skipped for want of an
 * account to sign in as. Eleven specs reported "skipped", the run reported
 * green, and `read-only` had never once been exercised anywhere.
 *
 * This test reads the provisioner as text because that is where the defect
 * lives. There is no live Keycloak here and no unit boundary to mock: the
 * question is whether the shell that builds the realm names the same four roles
 * the Go authorizer recognises, and whether the accounts it creates for the two
 * new ones are shaped so the probe suite can actually use them.
 */
const lib = readFileSync("../scripts/deploy/lib.sh", "utf8");
const authz = readFileSync("../engine/internal/authz/authz.go", "utf8");
const probeSupport = readFileSync("e2e/probe/support/live.ts", "utf8");

/** The roles the authorizer recognises, read from the source of truth. */
function declaredRoles(): string[] {
  return [...authz.matchAll(/^\s*Role\w+\s+Role\s*=\s*"([^"]+)"/gm)].map((m) => m[1]);
}

/** Realm roles the provisioner creates in the ebpf-soc realm. */
function provisionedRoles(): string[] {
  return [...lib.matchAll(/K create roles -r ebpf-soc -s name=([\w-]+)/g)].map((m) => m[1]);
}

/** username -> realm role, from every `K add-roles` in the provisioner. */
function roleAssignments(): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of lib.matchAll(/K add-roles -r ebpf-soc --uusername (\S+) --rolename ([\w-]+)/g)) {
    out.set(m[2], m[1]);
  }
  return out;
}

/**
 * The lines the deploy prints and writes to the credentials file.
 *
 * `userlist+=` carries most of them; the per-tenant lines take their persona
 * hint from a `probe_hint` the loop interpolates, so that is part of the same
 * output and is read here too.
 */
const credentialLines = [
  ...[...lib.matchAll(/userlist\+="([^"]*)"/g)].map((m) => m[1]),
  ...[...lib.matchAll(/^\s*\d\)\s*probe_hint="([^"]*)"/gm)].map((m) => m[1])
];

describe("the deploy provisions every role the authorizer enforces", () => {
  it("creates all four realm roles named in authz.go", () => {
    const declared = declaredRoles();
    // Guard the guard: a rename in authz.go that broke this regex would make
    // the assertion below pass vacuously.
    expect(declared, "expected to have read the Role constants out of authz.go").toEqual(
      expect.arrayContaining(["read-only", "tenant-analyst", "msoc-admin", "cross-tenant-responder"])
    );
    const provisioned = provisionedRoles();
    for (const role of declared) {
      expect(provisioned, `authz.go enforces \`${role}\` but no realm role is created for it`).toContain(role);
    }
  });

  it("gives read-only and cross-tenant-responder an account that holds them", () => {
    const assigned = roleAssignments();
    for (const role of ["read-only", "cross-tenant-responder"]) {
      const user = assigned.get(role);
      expect(user, `no account is granted \`${role}\`, so nothing can ever sign in as it`).toBeTruthy();
    }
  });

  it("stamps the tenant attribute on both persona accounts", () => {
    // Load-bearing, not cosmetic: authz.DefaultTenant reads this attribute and
    // whoami publishes it as viewing_tenant, so a persona created without one
    // resolves to no tenant and is refused reads it is entitled to — which on
    // screen is indistinguishable from the RBAC defect the probes measure.
    const assigned = roleAssignments();
    for (const role of ["read-only", "cross-tenant-responder"]) {
      const user = assigned.get(role)!;
      const create = lib
        .split("\n")
        .find((line) => line.includes("K create users -r ebpf-soc") && line.includes(`username=${user} `));
      expect(create, `no create-users line for ${user}`).toBeTruthy();
      expect(create, `${user} is created without a tenant attribute`).toContain("attributes.tenant=[");
    }
  });

  it("keeps the persona passwords stable across redeploys", () => {
    // console_password reads back the value already recorded on the host and
    // only mints one when there is none. Minting inline instead would rotate
    // the persona's password on every deploy and silently break the next probe
    // run, whose e2e.env still carries the old one.
    const assigned = roleAssignments();
    for (const role of ["read-only", "cross-tenant-responder"]) {
      const user = assigned.get(role)!;
      expect(
        lib,
        `${user}'s password must come from console_password, or every redeploy rotates it`
      ).toContain(`console_password ${user}`);
      const create = lib
        .split("\n")
        .find((line) => line.includes("K create users -r ebpf-soc") && line.includes(`username=${user} `))!;
      expect(create, `creating ${user} on a redeploy must not fail the deploy`).toMatch(/\|\| true\s*$/);
    }
  });
});

describe("the credentials output says which account is which probe persona", () => {
  it("names the env vars the probe suite reads", () => {
    // Every PROBE_*_USER live.ts reads has to be traceable to an account, or
    // the values reach .deploy-build/e2e.env by guesswork.
    const wanted = [...probeSupport.matchAll(/env\.(PROBE_\w+_USER)/g)].map((m) => m[1]);
    expect(wanted.length, "expected to have read the persona env vars out of live.ts").toBeGreaterThanOrEqual(4);
    const printed = credentialLines.join("\n");
    for (const name of wanted) {
      expect(printed, `the credentials output never says which account is ${name}`).toContain(name);
    }
  });

  it("pairs each persona hint with the account that actually holds the role", () => {
    const assigned = roleAssignments();
    const pairs: Array<[string, string]> = [
      ["read-only", "PROBE_RO_USER"],
      ["cross-tenant-responder", "PROBE_XR_USER"]
    ];
    for (const [role, envName] of pairs) {
      const user = assigned.get(role)!;
      const line = credentialLines.find((l) => l.includes(envName));
      expect(line, `no credentials line mentions ${envName}`).toBeTruthy();
      expect(line, `${envName} is advertised on a line that is not ${user}'s`).toContain(`${user} / $`);
      expect(line, `${envName}'s line does not say which role the account holds`).toContain(role);
    }
  });
});
