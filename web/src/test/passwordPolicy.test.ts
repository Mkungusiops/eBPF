import { describe, expect, it } from "vitest";

import { PASSWORD_RULES, evaluatePassword, passwordMeetsPolicy } from "../lib/passwordPolicy";

describe("password policy", () => {
  it("exposes exactly the five policy rules", () => {
    expect(PASSWORD_RULES.map((r) => r.id)).toEqual(["length", "upper", "lower", "digits", "special"]);
  });

  it("accepts a compliant password", () => {
    // Same shape the deploy tooling generates: >=14, upper, lower, 3+ digits, 3+ special.
    expect(passwordMeetsPolicy("A2pl9386&CCjp&@4U@15")).toBe(true);
  });

  it("rejects the retired demo credential and reports why", () => {
    expect(passwordMeetsPolicy("ebpf-soc-demo")).toBe(false);
    const r = evaluatePassword("ebpf-soc-demo");
    expect(r.length).toBe(false); // 13 chars
    expect(r.upper).toBe(false);
    expect(r.lower).toBe(true);
    expect(r.digits).toBe(false); // 0 digits
    expect(r.special).toBe(false); // only two hyphens
  });

  it("counts digits and specials, not just presence", () => {
    // "12!@3": digits 1,2,3 = 3 (ok); specials !,@ = 2 (short one) -> overall fail.
    expect(passwordMeetsPolicy("Abcdefghij12!@3")).toBe(false);
    // Add one more special to satisfy every rule.
    expect(passwordMeetsPolicy("Abcdefghij12!@#3")).toBe(true);
  });

  it("requires at least three special characters", () => {
    expect(evaluatePassword("Abcdefghij123!@X").special).toBe(false); // 2 specials
    expect(evaluatePassword("Abcdefghij123!@#").special).toBe(true); // 3 specials
  });

  it("requires at least three digits", () => {
    expect(evaluatePassword("Abcdefghij12!@#$").digits).toBe(false); // 2 digits
    expect(evaluatePassword("Abcdefghi123!@#$").digits).toBe(true); // 3 digits
  });

  it("enforces the 14-character minimum", () => {
    expect(evaluatePassword("Ab1!Ab1!Ab1!").length).toBe(false); // 12
    expect(evaluatePassword("Ab1!Ab1!Ab1!22").length).toBe(true); // 14
  });
});
