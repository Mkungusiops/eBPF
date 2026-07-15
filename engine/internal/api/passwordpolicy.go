package api

import (
	"fmt"
	"strings"
)

// Dashboard password policy. These thresholds are the single source of truth
// for the credential strength requirement and are mirrored, verbatim, in the
// web login UI (web/src/lib/passwordPolicy.ts + LoginPage.tsx) and the embedded
// fallback login page (login.html). Keep the three in sync when changing them.
const (
	pwMinLength  = 14
	pwMinUpper   = 1
	pwMinLower   = 1
	pwMinDigits  = 3
	pwMinSpecial = 3
)

// PasswordPolicyRequirements returns the human-readable policy lines in the
// order the login UI renders them. Centralised so the server error text and
// the on-screen checklist never drift.
func PasswordPolicyRequirements() []string {
	return []string{
		fmt.Sprintf("At least %d characters", pwMinLength),
		"At least one uppercase letter",
		"At least one lowercase letter",
		fmt.Sprintf("At least %d numbers", pwMinDigits),
		fmt.Sprintf("At least %d special characters", pwMinSpecial),
	}
}

// ValidatePasswordPolicy checks a PLAINTEXT password against the dashboard
// policy. It returns nil when compliant, or an error naming every unmet
// requirement. A "special character" is any rune that is not an ASCII letter
// or digit — the same rule the browser checklist applies (/[^A-Za-z0-9]/).
//
// Pre-hashed (bcrypt) credentials cannot be composition-checked, so callers
// skip this for hashes (see IsBcryptHash) and trust the operator to have
// hashed a compliant password.
func ValidatePasswordPolicy(pw string) error {
	var upper, lower, digits, special int
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digits++
		default:
			special++
		}
	}

	var missing []string
	if len([]rune(pw)) < pwMinLength {
		missing = append(missing, fmt.Sprintf("at least %d characters", pwMinLength))
	}
	if upper < pwMinUpper {
		missing = append(missing, "at least one uppercase letter")
	}
	if lower < pwMinLower {
		missing = append(missing, "at least one lowercase letter")
	}
	if digits < pwMinDigits {
		missing = append(missing, fmt.Sprintf("at least %d numbers", pwMinDigits))
	}
	if special < pwMinSpecial {
		missing = append(missing, fmt.Sprintf("at least %d special characters", pwMinSpecial))
	}
	if len(missing) > 0 {
		return fmt.Errorf("password does not meet policy: needs %s", strings.Join(missing, ", "))
	}
	return nil
}

// IsBcryptHash reports whether s is already a bcrypt hash (as opposed to a
// plaintext password). Exported so the engine/agent entrypoints can decide
// whether ValidatePasswordPolicy applies before handing the credential to
// NewAuth.
func IsBcryptHash(s string) bool { return isBcryptHash(s) }
