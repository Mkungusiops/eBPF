package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// serverIdentity is resolved once at startup. The IP comes from the kernel's
// route-selection for an arbitrary external destination — no packet is sent,
// we just read the local address the kernel would bind. This surfaces the
// engine host's primary IP even when the client reached it via a hostname,
// reverse proxy, or tunnel.
var (
	serverIdentityOnce sync.Once
	serverHostname     string
	serverIP           string
)

func resolveServerIdentity() {
	serverIdentityOnce.Do(func() {
		serverHostname, _ = os.Hostname()
		conn, err := net.Dial("udp", "1.1.1.1:80")
		if err != nil {
			return
		}
		defer conn.Close()
		if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			serverIP = a.IP.String()
		}
	})
}

// Auth gates the dashboard with a single admin user backed by bcrypt and
// stateless signed-cookie sessions.
//
// Session durability: sessions are HMAC-SHA256-signed cookies, no server
// state. The signing secret lives in a file (default /etc/ebpf-engine/secret,
// auto-generated 0600 on first start) so sessions survive engine restart.
//
// CSRF: a separate non-HttpOnly cookie carries a per-session CSRF token.
// State-changing requests (anything not GET/HEAD/OPTIONS) under /api/ must
// echo it back via X-CSRF-Token. The dashboard JS picks this up via a
// global fetch wrapper.
//
// Rate limiting: per-source-IP token bucket on /api/login, 5 attempts per
// rolling minute, 429 thereafter.
type Auth struct {
	user     string
	passHash []byte
	cookie   string
	csrfName string

	secret     []byte
	sessionTTL time.Duration

	mu        sync.Mutex
	loginRate map[string]*rateBucket
	// loginRateLimit is attempts per rolling minute per IP; 0 disables the
	// limit (dev/E2E). Defaults to defaultRateLimit.
	loginRateLimit int
}

// SetLoginRateLimit overrides the per-IP login rate limit (attempts/minute).
// 0 disables it — for dev / E2E harnesses that authenticate many times.
func (a *Auth) SetLoginRateLimit(n int) { a.loginRateLimit = n }

type rateBucket struct {
	count   int
	resetAt time.Time
}

// session is the signed-cookie payload. Tiny on purpose so the cookie
// stays small. Issued is included so we can revoke older-than-X
// blanket-style by raising a server-side cutoff in the future.
type session struct {
	User   string `json:"u"`
	Exp    int64  `json:"e"` // unix seconds
	Issued int64  `json:"i"`
	CSRF   string `json:"c"` // tied to the cookie that goes alongside
}

const (
	defaultSessionTTL = 24 * time.Hour
	defaultRateLimit  = 5 // attempts per rolling minute per IP
	defaultRateWindow = time.Minute
	// /var/lib not /etc so the systemd unit's ProtectSystem=strict lets
	// the auto-bootstrap write 32 random bytes on first start. Operators
	// can override via -secret or `secret_path:` in engine.yaml.
	defaultSecretPath = "/var/lib/ebpf-engine/secret"
)

// NewAuth builds an Auth from a credential pair plus a signing-secret path.
//
// passOrHash is interpreted as a bcrypt hash if it starts with "$2a$" /
// "$2b$" / "$2y$"; otherwise it's hashed once at startup (so a plaintext
// password from config gets bcrypted in memory immediately, but we still
// support pre-hashed strings in /etc/ebpf-engine/engine.yaml).
//
// secretPath is auto-created with a fresh 32-byte random secret if missing,
// 0600. Pass "" to use the default path.
func NewAuth(user, passOrHash, secretPath string) (*Auth, error) {
	var hash []byte
	if isBcryptHash(passOrHash) {
		hash = []byte(passOrHash)
		// Validate: bcrypt rejects malformed hashes when verifying, but
		// catch the obvious case at startup so the operator sees the
		// error before login attempts begin.
		if _, err := bcrypt.Cost(hash); err != nil {
			return nil, fmt.Errorf("auth: invalid bcrypt hash in config: %w", err)
		}
	} else {
		h, err := bcrypt.GenerateFromPassword([]byte(passOrHash), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		hash = h
	}

	if secretPath == "" {
		secretPath = defaultSecretPath
	}
	secret, err := loadOrCreateSecret(secretPath)
	if err != nil {
		return nil, err
	}

	return &Auth{
		user:           user,
		passHash:       hash,
		cookie:         "soc_session",
		csrfName:       "csrf_token",
		secret:         secret,
		sessionTTL:     defaultSessionTTL,
		loginRate:      make(map[string]*rateBucket),
		loginRateLimit: defaultRateLimit,
	}, nil
}

func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

// loadOrCreateSecret reads the HMAC signing secret from disk; if missing,
// it generates 32 fresh random bytes, writes them with 0600, and returns
// them. Best-effort mkdir of the parent dir for first-install ergonomics.
func loadOrCreateSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("auth: read secret %s: %w", path, err)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("auth: write secret %s: %w", path, err)
	}
	return b, nil
}

// Username exposes the configured username for display in the dashboard.
func (a *Auth) Username() string { return a.user }

// Login validates credentials. Returns a fresh signed-cookie payload + the
// matching CSRF token on success.
func (a *Auth) Login(user, pass string) (sessionCookie, csrf string, ok bool) {
	if subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) != 1 {
		// Run bcrypt anyway to keep timing constant against username probes.
		_ = bcrypt.CompareHashAndPassword(a.passHash, []byte(pass))
		return "", "", false
	}
	if err := bcrypt.CompareHashAndPassword(a.passHash, []byte(pass)); err != nil {
		return "", "", false
	}
	csrf = newToken()
	now := time.Now()
	s := session{
		User:   a.user,
		Exp:    now.Add(a.sessionTTL).Unix(),
		Issued: now.Unix(),
		CSRF:   csrf,
	}
	cookie, err := a.signSession(s)
	if err != nil {
		return "", "", false
	}
	return cookie, csrf, true
}

// signSession produces "<base64(json)>.<base64(hmac)>". HMAC covers the
// payload; verification rejects any tampered byte.
func (a *Auth) signSession(s session) (string, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

// verifySession parses the signed-cookie payload and returns the inner
// session struct. Errors on tamper, expiry, or malformed input.
func (a *Auth) verifySession(cookie string) (session, error) {
	var s session
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return s, errors.New("malformed session cookie")
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return s, errors.New("session signature mismatch")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return s, err
	}
	if time.Now().Unix() > s.Exp {
		return s, errors.New("session expired")
	}
	return s, nil
}

// rateAllowed enforces a sliding-minute bucket per remote address.
func (a *Auth) rateAllowed(remote string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginRateLimit <= 0 { // disabled (dev/E2E)
		return true
	}
	b, ok := a.loginRate[remote]
	now := time.Now()
	if !ok || now.After(b.resetAt) {
		a.loginRate[remote] = &rateBucket{count: 1, resetAt: now.Add(defaultRateWindow)}
		return true
	}
	b.count++
	return b.count <= a.loginRateLimit
}

// Middleware authenticates and CSRF-checks every request. Public paths
// (login, login submit, favicon) pass through unguarded.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(a.cookie)
		if err != nil {
			a.unauthorized(w, r)
			return
		}
		s, err := a.verifySession(c.Value)
		if err != nil {
			a.unauthorized(w, r)
			return
		}
		// CSRF: require X-CSRF-Token (or _csrf form field) on unsafe methods
		// for /api/* paths (skip for static dashboard fetches which are GET).
		if isUnsafeMethod(r.Method) && strings.HasPrefix(r.URL.Path, "/api/") {
			if !a.checkCSRF(r, s) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "csrf token missing or invalid",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func (a *Auth) checkCSRF(r *http.Request, s session) bool {
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" {
		// Form-encoded fallback for HTML <form> submissions that don't run JS.
		_ = r.ParseForm()
		tok = r.PostForm.Get("_csrf")
	}
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.CSRF)) == 1
}

func (a *Auth) unauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":    "unauthorized",
			"redirect": "/login",
		})
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func isPublicPath(p string) bool {
	switch p {
	// /api/logout is public so signing out always works — it only clears the
	// session cookies (idempotent). Gating it behind auth means an expired
	// session dead-ends on logout instead of clearing.
	// /healthz and /readyz are public so a load balancer or uptime check —
	// which holds no session — can actually use them. A probe behind auth is
	// not a probe.
	case "/login", "/api/login", "/api/logout", "/favicon.svg", "/favicon.ico", "/favicon-light.svg",
		"/healthz", "/readyz":
		return true
	}
	return isBuiltAssetPath(p) || isPWARootPath(p)
}

// HandleLogin parses form-encoded credentials and sets the session cookie.
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.rateAllowed(remoteIP(r)) {
		http.Error(w, "too many attempts; try again in a minute", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user := r.PostForm.Get("user")
	pass := r.PostForm.Get("pass")
	cookie, csrf, ok := a.Login(user, pass)
	if !ok {
		http.Redirect(w, r, "/login?err=1", http.StatusSeeOther)
		return
	}
	a.setAuthCookies(w, cookie, csrf)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) setAuthCookies(w http.ResponseWriter, sessionCookie, csrf string) {
	maxAge := int(a.sessionTTL.Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookie,
		Value:    sessionCookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	// CSRF cookie: NOT HttpOnly so the dashboard JS can read it and
	// echo back as X-CSRF-Token. Same SameSite=Lax binds it to first-party.
	http.SetCookie(w, &http.Cookie{
		Name:     a.csrfName,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// HandleLogout clears both cookies. With stateless sessions there's
// nothing server-side to invalidate; the cookies just stop being sent.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{a.cookie, a.csrfName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name == a.cookie,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleLoginPage serves the embedded HTML form. ?err=1 surfaces the failure
// message inline.
func (a *Auth) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	page := loginHTML
	if r.URL.Query().Get("err") == "1" {
		page = strings.Replace(page, "<!--ERR-->", `<div class="err">Invalid credentials</div>`, 1)
	}
	_, _ = w.Write([]byte(page))
}

// HandleWhoami exposes the current session's username for the dashboard
// header. Returns 401 if not logged in.
func (a *Auth) HandleWhoami(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(a.cookie)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s, err := a.verifySession(c.Value)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resolveServerIdentity()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"user":      s.User,
		"hostname":  serverHostname,
		"server_ip": serverIP,
		"csrf":      s.CSRF,
	})
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func remoteIP(r *http.Request) string {
	// Honor X-Forwarded-For for nginx-fronted deployments. nginx sends
	// the real client IP as the leftmost entry.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
