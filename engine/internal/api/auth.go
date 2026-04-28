package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Auth gates the dashboard with a single admin user backed by bcrypt and
// HttpOnly session cookies. Sessions live in-memory (lost on restart, which
// is fine for a single-instance PoC).
type Auth struct {
	user     string
	passHash []byte
	cookie   string

	mu         sync.Mutex
	sessions   map[string]time.Time // token -> expiry
	loginRate  map[string]*rateBucket
	sessionTTL time.Duration
}

type rateBucket struct {
	count    int
	resetAt  time.Time
}

// NewAuth builds an Auth from a plaintext credential pair. The password is
// bcrypt-hashed once at startup so the plaintext doesn't linger in memory.
func NewAuth(user, plaintext string) (*Auth, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Auth{
		user:       user,
		passHash:   hash,
		cookie:     "soc_session",
		sessions:   make(map[string]time.Time),
		loginRate:  make(map[string]*rateBucket),
		sessionTTL: 24 * time.Hour,
	}, nil
}

// Username exposes the configured username for display in the dashboard.
func (a *Auth) Username() string { return a.user }

// Login validates credentials. Returns a session token on success.
func (a *Auth) Login(user, pass string) (string, bool) {
	if subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) != 1 {
		// Still run bcrypt to keep timing constant against username probes.
		_ = bcrypt.CompareHashAndPassword(a.passHash, []byte(pass))
		return "", false
	}
	if err := bcrypt.CompareHashAndPassword(a.passHash, []byte(pass)); err != nil {
		return "", false
	}
	tok := newToken()
	a.mu.Lock()
	a.sessions[tok] = time.Now().Add(a.sessionTTL)
	a.mu.Unlock()
	return tok, true
}

// Logout invalidates a session token.
func (a *Auth) Logout(tok string) {
	a.mu.Lock()
	delete(a.sessions, tok)
	a.mu.Unlock()
}

// validate checks a session token, sweeping expired entries opportunistically.
func (a *Auth) validate(tok string) bool {
	if tok == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sessions, tok)
		return false
	}
	return true
}

// rateAllowed enforces a simple sliding-minute bucket per remote address.
func (a *Auth) rateAllowed(remote string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.loginRate[remote]
	now := time.Now()
	if !ok || now.After(b.resetAt) {
		a.loginRate[remote] = &rateBucket{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	b.count++
	return b.count <= 10
}

// Middleware redirects unauthenticated browser requests to /login and rejects
// API calls with 401. Public paths (login page, login submit, static probes)
// pass through unguarded.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(a.cookie)
		if err != nil || !a.validate(c.Value) {
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
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(p string) bool {
	switch p {
	case "/login", "/api/login", "/favicon.svg", "/favicon.ico":
		return true
	}
	return false
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
	tok, ok := a.Login(user, pass)
	if !ok {
		// 303 back to login page with a flag.
		http.Redirect(w, r, "/login?err=1", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleLogout clears the session.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cookie); err == nil {
		a.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
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
	if err != nil || !a.validate(c.Value) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"user": a.user})
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func remoteIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
