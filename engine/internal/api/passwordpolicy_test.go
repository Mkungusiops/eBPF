package api

import (
	"strings"
	"testing"
)

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr bool
		// substrings expected in the error (when wantErr).
		needs []string
	}{
		{
			name: "compliant generated-style password",
			pw:   "A2pl9386&CCjp&@4U@15", // 20 chars, 4 upper, 4 digits+, 4 special
		},
		{
			name: "exactly at thresholds",
			pw:   "Abcdefghi123!@#", // 15 chars, 1 upper, many lower, 3 digits, 3 special
		},
		{
			name:    "the retired demo credential is rejected",
			pw:      "ebpf-soc-demo",
			wantErr: true,
			needs:   []string{"14 characters", "uppercase", "3 numbers", "3 special"},
		},
		{
			name:    "too short even if otherwise strong",
			pw:      "Ab1!Ab1!Ab1", // 11 chars
			wantErr: true,
			needs:   []string{"14 characters"},
		},
		{
			name:    "no uppercase",
			pw:      "abcdefghij123!@#",
			wantErr: true,
			needs:   []string{"uppercase"},
		},
		{
			name:    "no lowercase",
			pw:      "ABCDEFGHIJ123!@#",
			wantErr: true,
			needs:   []string{"lowercase"},
		},
		{
			name:    "only two digits",
			pw:      "Abcdefghijk12!@#",
			wantErr: true,
			needs:   []string{"3 numbers"},
		},
		{
			name:    "only two specials",
			pw:      "Abcdefghij123!@4",
			wantErr: true,
			needs:   []string{"3 special"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tc.pw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected policy error for %q, got nil", tc.pw)
				}
				for _, sub := range tc.needs {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q missing expected substring %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected %q to be compliant, got error: %v", tc.pw, err)
			}
		})
	}
}

func TestIsBcryptHashSkipsPolicy(t *testing.T) {
	// A bcrypt hash is not a plaintext password; the entrypoints must not run
	// ValidatePasswordPolicy against it. Assert the discriminator the
	// entrypoints rely on.
	hash := "$2a$10$tBh8PnMk3Mm/RJFQdhZyze1fSJTuTojPLp59lT2NdqqrSttqFEZLi"
	if !IsBcryptHash(hash) {
		t.Fatalf("expected %q to be recognised as a bcrypt hash", hash)
	}
	if IsBcryptHash("A2pl9386&CCjp&@4U@15") {
		t.Fatalf("plaintext password must not be treated as a bcrypt hash")
	}
}

func TestPasswordPolicyRequirementsStable(t *testing.T) {
	got := PasswordPolicyRequirements()
	if len(got) != 5 {
		t.Fatalf("expected 5 requirement lines, got %d: %v", len(got), got)
	}
	// The first line must state the length so operators see the headline rule.
	if !strings.Contains(got[0], "14") {
		t.Errorf("first requirement should mention the 14-character minimum, got %q", got[0])
	}
}
