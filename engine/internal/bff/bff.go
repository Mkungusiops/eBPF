// Package bff is the Backend-For-Frontend / token-handler for the console
// (docs/plan/d4c-tech-decisions.md §3.6). It runs the OIDC Authorization Code +
// PKCE flow SERVER-SIDE: the SPA never sees a token. The browser gets only an
// opaque, HttpOnly session cookie; the OIDC tokens live in a server-side
// session. This is the right pattern for a security product — it removes token
// theft via XSS from the threat surface.
//
// On callback the verified claims are mapped (via internal/identity) to an
// authz.Principal, which internal/authz then uses for tenant-scoped decisions.
// Agents authenticate by mTLS; only humans traverse this path.
package bff

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/identity"
)

const (
	sessionCookie = "soc_session"
	stateCookie   = "soc_login_state"
	sessionTTL    = 8 * time.Hour
	loginTTL      = 5 * time.Minute
)

type session struct {
	principal authz.Principal
	expiry    time.Time
	// idToken is kept solely as the id_token_hint for RP-initiated logout, so
	// signing out also ends the IdP's SSO session (otherwise the next login is
	// silent and "sign out" is cosmetic). It never leaves the server.
	idToken string
}

type pendingLogin struct {
	verifier string // PKCE code verifier
	created  time.Time
}

// Handler serves the auth endpoints and gates protected routes. It keeps
// sessions and in-flight logins in memory — a single-node Phase 1 form; a shared
// store (Redis/DB) replaces the maps for HA without changing the surface.
type Handler struct {
	oauth2   *oauth2.Config
	verifier *identity.Verifier
	appURL   string // where to send the browser after login
	secure   bool   // Secure cookies (true behind TLS)

	// RP-initiated logout (OIDC front-channel). endSessionURL comes from
	// discovery; postLogoutURL is where the IdP returns the browser afterwards.
	// Empty endSessionURL degrades gracefully to a local-only logout.
	endSessionURL string
	postLogoutURL string

	mu       sync.Mutex
	sessions map[string]session
	pending  map[string]pendingLogin
}

// New performs OIDC discovery and builds a BFF for a confidential client.
func New(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL, appURL string, secure bool) (*Handler, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	v, err := identity.NewVerifier(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	// end_session_endpoint is not part of go-oidc's typed Endpoint(), so read it
	// off the raw discovery document.
	var disco struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&disco)

	return &Handler{
		oauth2: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:      v,
		appURL:        appURL,
		secure:        secure,
		endSessionURL: disco.EndSessionEndpoint,
		postLogoutURL: postLogoutFrom(redirectURL),
		sessions:      make(map[string]session),
		pending:       make(map[string]pendingLogin),
	}, nil
}

// postLogoutFrom derives the absolute URL the IdP returns the browser to after
// logout — the console origin, taken from the (absolute) OIDC redirect URL by
// dropping its /auth/callback path. The IdP must have this registered.
func postLogoutFrom(redirectURL string) string {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}

// Routes registers the auth endpoints.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/login", h.login)
	mux.HandleFunc("/auth/callback", h.callback)
	mux.HandleFunc("/auth/logout", h.logout)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	state := randToken()
	verifier := oauth2.GenerateVerifier()
	h.mu.Lock()
	h.pending[state] = pendingLogin{verifier: verifier, created: time.Now()}
	h.mu.Unlock()
	// Bind the state to a cookie (double-submit) to defeat login CSRF.
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/", HttpOnly: true,
		Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(loginTTL.Seconds()),
	})
	url := h.oauth2.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	sc, err := r.Cookie(stateCookie)
	if err != nil || sc.Value == "" || sc.Value != state {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	pl, ok := h.pending[state]
	delete(h.pending, state)
	h.mu.Unlock()
	if !ok || time.Since(pl.created) > loginTTL {
		http.Error(w, "unknown or expired login", http.StatusBadRequest)
		return
	}

	tok, err := h.oauth2.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(pl.verifier))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	claims, err := h.verifier.Verify(r.Context(), tok.AccessToken)
	if err != nil {
		http.Error(w, "token verification failed", http.StatusUnauthorized)
		return
	}

	// Keep the raw ID token as the id_token_hint for RP-initiated logout.
	rawIDToken, _ := tok.Extra("id_token").(string)

	sid := randToken()
	h.mu.Lock()
	h.sessions[sid] = session{
		principal: identity.PrincipalFromClaims(claims),
		expiry:    time.Now().Add(sessionTTL),
		idToken:   rawIDToken,
	}
	h.mu.Unlock()

	// Session cookie to the browser; the OIDC tokens stay here, server-side.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/", HttpOnly: true,
		Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	clearCookie(w, stateCookie)
	http.Redirect(w, r, h.appURL, http.StatusFound)
}

// logout ends the local session AND, via OIDC RP-initiated logout, the IdP's SSO
// session. Without the second step the IdP cookie survives and the next login is
// silent — "sign out" would only appear to work. The browser must NAVIGATE here
// (not fetch) so it can follow the redirect to the IdP and back.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var idToken string
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.mu.Lock()
		if s, ok := h.sessions[c.Value]; ok {
			idToken = s.idToken
		}
		delete(h.sessions, c.Value)
		h.mu.Unlock()
	}
	clearCookie(w, sessionCookie)

	// No discovered end_session_endpoint → local-only logout (degrade, don't fail).
	if h.endSessionURL == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	q := url.Values{}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	} else {
		// Without a hint the IdP needs the client to scope the logout.
		q.Set("client_id", h.oauth2.ClientID)
	}
	if h.postLogoutURL != "" {
		q.Set("post_logout_redirect_uri", h.postLogoutURL)
	}
	http.Redirect(w, r, h.endSessionURL+"?"+q.Encode(), http.StatusFound)
}

// Principal returns the authenticated principal for a request, or ok=false.
func (h *Handler) Principal(r *http.Request) (authz.Principal, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return authz.Principal{}, false
	}
	h.mu.Lock()
	s, ok := h.sessions[c.Value]
	h.mu.Unlock()
	if !ok || time.Now().After(s.expiry) {
		return authz.Principal{}, false
	}
	return s.principal, true
}

type ctxKey struct{}

// Require gates next: a valid session injects the principal into the context;
// otherwise 401. The server is the sole scope authority — the SPA's tenant
// switcher is UX only.
func (h *Handler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := h.Principal(r)
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// PrincipalFromContext retrieves the principal injected by Require.
func PrincipalFromContext(ctx context.Context) (authz.Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(authz.Principal)
	return p, ok
}

// Whoami is a convenience protected endpoint: it reports the caller's identity
// and authorized tenants (never a token).
func (h *Handler) Whoami(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":      p.Subject,
		"tenants":      authz.TenantScope(p),
		"cross_tenant": authz.HasCrossTenant(p),
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
