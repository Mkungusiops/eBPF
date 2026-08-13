// Dashboard password policy — the browser-side mirror of the Go source of
// truth in engine/internal/api/passwordpolicy.go. The thresholds here MUST
// match that file (and the embedded fallback login.html) so the on-screen
// checklist agrees with what the engine enforces at startup.

export interface PasswordRule {
  id: string;
  label: string;
  test: (pw: string) => boolean;
}

// A "special character" is anything that is not an ASCII letter or digit —
// identical to the server's `default` branch in ValidatePasswordPolicy.
const countMatches = (pw: string, re: RegExp): number => (pw.match(re) ?? []).length;

export const PASSWORD_MIN_LENGTH = 14;
export const PASSWORD_MIN_DIGITS = 3;
export const PASSWORD_MIN_SPECIAL = 3;

export const PASSWORD_RULES: PasswordRule[] = [
  { id: "length", label: `At least ${PASSWORD_MIN_LENGTH} characters`, test: (pw) => pw.length >= PASSWORD_MIN_LENGTH },
  { id: "upper", label: "At least one uppercase letter", test: (pw) => /[A-Z]/.test(pw) },
  { id: "lower", label: "At least one lowercase letter", test: (pw) => /[a-z]/.test(pw) },
  { id: "digits", label: `At least ${PASSWORD_MIN_DIGITS} numbers`, test: (pw) => countMatches(pw, /[0-9]/g) >= PASSWORD_MIN_DIGITS },
  {
    id: "special",
    label: `At least ${PASSWORD_MIN_SPECIAL} special characters`,
    test: (pw) => countMatches(pw, /[^A-Za-z0-9]/g) >= PASSWORD_MIN_SPECIAL
  }
];

// evaluatePassword returns per-rule pass/fail keyed by rule id.
export function evaluatePassword(pw: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const rule of PASSWORD_RULES) out[rule.id] = rule.test(pw);
  return out;
}

// passwordMeetsPolicy is true only when every rule passes.
export function passwordMeetsPolicy(pw: string): boolean {
  return PASSWORD_RULES.every((rule) => rule.test(pw));
}
