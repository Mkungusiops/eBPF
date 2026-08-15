package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

// TestBFFAuthorizationCodeFlow drives the FULL browser-less Authorization Code +
// PKCE flow against a REAL Keycloak: /auth/login → Keycloak login form → submit
// credentials → /auth/callback → session cookie → /api/whoami. It asserts the
// browser only ever holds an opaque cookie (never a token) and that the mapped
// principal is correctly tenant-scoped. Set EBPF_TEST_KEYCLOAK_URL to run.
func TestBFFAuthorizationCodeFlow(t *testing.T) {
	base := os.Getenv("EBPF_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("set EBPF_TEST_KEYCLOAK_URL to run the BFF integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Bring up the BFF server first so we know its URL for the redirect URI.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bffURL := "http://" + lis.Addr().String()

	bootstrapKeycloak(t, base, bffURL+"/auth/callback")

	h, err := New(ctx, base+"/realms/ebpf-soc", "console-bff", "bff-secret", bffURL+"/auth/callback", bffURL+"/", false)
	if err != nil {
		t.Fatalf("bff New: %v", err)
	}
	mux := http.NewServeMux()
	h.Routes(mux)
	mux.Handle("/api/whoami", h.Require(http.HandlerFunc(h.Whoami)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app")) })
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second}

	// 1. Start login → follow to the Keycloak login page.
	resp, err := client.Get(bffURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// 2. Extract the login form action and submit alice's credentials.
	action := loginFormAction(t, string(body))
	resp, err = client.PostForm(action, url.Values{"username": {"alice"}, "password": {"alicepw"}})
	if err != nil {
		t.Fatalf("submit login: %v", err)
	}
	landing, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(landing) != "app" {
		t.Fatalf("post-login landing = %d %q, want 200 \"app\" (callback→app redirect chain)", resp.StatusCode, landing)
	}

	// 3. The browser now holds ONLY the opaque session cookie — no token.
	var sawSession, sawToken bool
	for _, c := range jar.Cookies(mustURL(t, bffURL)) {
		if c.Name == sessionCookie {
			sawSession = true
			if len(c.Value) > 200 { // a JWT would be long; the sid is 43 chars
				sawToken = true
			}
		}
	}
	if !sawSession {
		t.Fatal("no session cookie set after login")
	}
	if sawToken {
		t.Fatal("session cookie looks like a token — tokens must stay server-side")
	}

	// 4. /api/whoami with the session → the mapped, tenant-scoped principal.
	resp, err = client.Get(bffURL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	var who struct {
		Subject     string   `json:"subject"`
		Tenants     []string `json:"tenants"`
		CrossTenant bool     `json:"cross_tenant"`
	}
	json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who.Subject != "alice" {
		t.Fatalf("whoami subject = %q, want alice", who.Subject)
	}
	if len(who.Tenants) != 1 || who.Tenants[0] != "tenant-a" || who.CrossTenant {
		t.Fatalf("whoami tenants = %v cross=%v, want [tenant-a] false", who.Tenants, who.CrossTenant)
	}

	// 5. Unauthenticated request (fresh client) is rejected.
	if r, _ := http.Get(bffURL + "/api/whoami"); r == nil || r.StatusCode != 401 { //nolint:bodyclose // status-only probe
		t.Fatalf("unauthenticated whoami status = %v, want 401", r.StatusCode)
	}

	// 6. Logout invalidates the session server-side.
	if _, err := client.Get(bffURL + "/auth/logout"); err != nil { //nolint:bodyclose // status-only probe
		t.Fatal(err)
	}
	if r, _ := client.Get(bffURL + "/api/whoami"); r.StatusCode != 401 { //nolint:bodyclose // status-only probe
		t.Fatalf("whoami after logout = %d, want 401", r.StatusCode)
	}
}

var actionRE = regexp.MustCompile(`action="([^"]*login-actions/authenticate[^"]*)"`)

func loginFormAction(t *testing.T, page string) string {
	t.Helper()
	m := actionRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("could not find login form action in Keycloak page (len=%d)", len(page))
	}
	return html.UnescapeString(m[1])
}

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// --- Keycloak bootstrap (confidential client with the Auth Code flow) -------

func bootstrapKeycloak(t *testing.T, base, redirectURI string) {
	t.Helper()
	admin := kcToken(t, base+"/realms/master/protocol/openid-connect/token", url.Values{
		"client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"}, "grant_type": {"password"},
	})
	kcDo(t, "DELETE", base+"/admin/realms/ebpf-soc", admin, nil, 204, 404)
	kcDo(t, "POST", base+"/admin/realms", admin, map[string]any{"realm": "ebpf-soc", "enabled": true}, 201)

	var profile map[string]any
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/users/profile", admin, nil, 200), &profile)
	profile["unmanagedAttributePolicy"] = "ENABLED"
	kcDo(t, "PUT", base+"/admin/realms/ebpf-soc/users/profile", admin, profile, 200)

	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/roles", admin, map[string]any{"name": "tenant-analyst"}, 201)

	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/clients", admin, map[string]any{
		"clientId":                  "console-bff",
		"secret":                    "bff-secret",
		"publicClient":              false,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"redirectUris":              []string{redirectURI},
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

	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/users", admin, map[string]any{
		"username": "alice", "enabled": true, "emailVerified": true,
		"email": "alice@example.test", "firstName": "Alice", "lastName": "Analyst",
		"attributes": map[string]any{"tenant": []string{"tenant-a"}},
	}, 201)

	var users []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/users?username=alice", admin, nil, 200), &users)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	uid := users[0].ID
	kcDo(t, "PUT", base+"/admin/realms/ebpf-soc/users/"+uid+"/reset-password", admin, map[string]any{
		"type": "password", "value": "alicepw", "temporary": false,
	}, 204)
	var role map[string]any
	json.Unmarshal(kcDo(t, "GET", base+"/admin/realms/ebpf-soc/roles/tenant-analyst", admin, nil, 200), &role)
	kcDo(t, "POST", base+"/admin/realms/ebpf-soc/users/"+uid+"/role-mappings/realm", admin, []map[string]any{role}, 204)
}

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
	json.Unmarshal(data, &m)
	tok, _ := m["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token: %s", data)
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
