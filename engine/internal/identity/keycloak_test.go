package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// TestKeycloakEndToEnd proves the human-identity path against a REAL Keycloak:
// bootstrap a realm/client/role/user, obtain a token, VERIFY it (discovery +
// JWKS + signature/issuer/expiry), map its claims to an authz.Principal, and
// enforce tenant scope. Set EBPF_TEST_KEYCLOAK_URL (e.g. http://localhost:8080)
// to run it; skipped otherwise.
func TestKeycloakEndToEnd(t *testing.T) {
	base := os.Getenv("EBPF_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("set EBPF_TEST_KEYCLOAK_URL to run the Keycloak integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin := kcToken(t, base+"/realms/master/protocol/openid-connect/token", url.Values{
		"client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"}, "grant_type": {"password"},
	})

	// Fresh realm each run.
	kcDo(t, "DELETE", base+"/admin/realms/ebpf-soc", admin, nil, 204, 404)
	kcDo(t, "POST", base+"/admin/realms", admin, map[string]any{"realm": "ebpf-soc", "enabled": true}, 201)

	// Allow unmanaged custom attributes — Keycloak 24+'s declarative user
	// profile drops undeclared attributes (like `tenant`) by default.
	var profile map[string]any
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/users/profile", admin, nil, 200), &profile)
	profile["unmanagedAttributePolicy"] = "ENABLED"
	kcDo(t, "PUT", base+"/admin/realms/ebpf-soc/users/profile", admin, profile, 200)

	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/roles", admin, map[string]any{"name": "tenant-analyst"}, 201)

	// Public client with direct-access grants + a mapper that puts the user's
	// `tenant` attribute into the token as a `tenant` claim.
	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/clients", admin, map[string]any{
		"clientId":                  "console",
		"publicClient":              true,
		"directAccessGrantsEnabled": true,
		"protocolMappers": []map[string]any{{
			"name":           "tenant",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-usermodel-attribute-mapper",
			"config": map[string]string{
				"user.attribute":     "tenant",
				"claim.name":         "tenant",
				"jsonType.label":     "String",
				"access.token.claim": "true",
				"id.token.claim":     "true",
			},
		}},
	}, 201)

	// Operator alice in tenant-a.
	// Full profile: Keycloak's declarative user profile (24+) requires
	// email/firstName/lastName, else the account is "not fully set up".
	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/users", admin, map[string]any{
		"username":      "alice",
		"enabled":       true,
		"emailVerified": true,
		"email":         "alice@example.test",
		"firstName":     "Alice",
		"lastName":      "Analyst",
		"attributes":    map[string]any{"tenant": []string{"tenant-a"}},
	}, 201)

	var users []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/users?username=alice", admin, nil, 200), &users)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	uid := users[0].ID

	// Permanent password via the dedicated endpoint (does not disturb the
	// user's attributes the way a full-user PUT would).
	kcDo(t, "PUT", base+"/admin/realms/ebpf-soc/users/"+uid+"/reset-password", admin, map[string]any{
		"type": "password", "value": "alicepw", "temporary": false,
	}, 204)

	var role map[string]any
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/roles/tenant-analyst", admin, nil, 200), &role)
	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/users/"+uid+"/role-mappings/realm", admin, []map[string]any{role}, 204)

	// Alice logs in (password grant) and gets a real signed token.
	rawToken := kcToken(t, base+"/realms/ebpf-soc/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"console"},
		"username": {"alice"}, "password": {"alicepw"}, "scope": {"openid"},
	})

	// The control plane verifies the token and maps it to a Principal.
	v, err := NewVerifier(ctx, base+"/realms/ebpf-soc")
	if err != nil {
		t.Fatalf("discovery/verifier: %v", err)
	}
	claims, err := v.Verify(ctx, rawToken)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}
	if claims.Tenant != "tenant-a" {
		t.Fatalf("tenant claim = %q, want tenant-a", claims.Tenant)
	}

	p := PrincipalFromClaims(claims)

	// Real end-to-end authorization: alice reaches tenant-a, not tenant-b.
	if !authz.Authorize(p, "tenant-a", authz.ActionRead, nil).Allowed {
		t.Fatal("alice denied her own tenant after real Keycloak login")
	}
	if authz.Authorize(p, "tenant-b", authz.ActionRead, nil).Allowed {
		t.Fatal("alice reached tenant-b — Layer 4 breach through the OIDC path")
	}

	// Tamper: a token with a flipped byte must fail verification.
	bad := []byte(rawToken)
	bad[len(bad)-2] ^= 0xff
	if _, err := v.Verify(ctx, string(bad)); err == nil {
		t.Fatal("a tampered token verified — signature check is not enforced")
	}
}

// --- Keycloak admin/token helpers ------------------------------------------

func kcToken(t *testing.T, tokenURL string, form url.Values) string {
	t.Helper()
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("token %s -> %d: %s", tokenURL, resp.StatusCode, data)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	tok, _ := m["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token in response: %s", data)
	}
	return tok
}

func kcDo(t *testing.T, method, u, bearer string, body any, ok ...int) []byte {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, s := range ok {
		if resp.StatusCode == s {
			return data
		}
	}
	t.Fatalf("%s %s -> %d: %s", method, u, resp.StatusCode, data)
	return nil
}
