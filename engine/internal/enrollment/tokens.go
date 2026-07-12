// Package enrollment implements the agent enrollment handshake
// (docs/plan/wire-contract.md §3): one-time, tenant-scoped bootstrap tokens are
// exchanged (with a CSR) for a client certificate whose subject binds the
// tenant. It is the control-plane side of the trust root behind the tenant
// isolation invariant, plus the agent-side client helper.
package enrollment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// TokenStore holds one-time, tenant-scoped bootstrap tokens. Tokens are minted
// by an operator action and burned on first use (threat-model.md SC-7). This
// in-memory store is the Phase 1 form; a durable store lands with the fleet
// service.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry
}

type tokenEntry struct {
	tenant  string
	expires time.Time
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]tokenEntry)}
}

// Mint creates a random one-time token bound to tenantID, valid for ttl.
func (ts *TokenStore) Mint(tenantID string, ttl time.Duration) (string, error) {
	if tenantID == "" {
		return "", errors.New("enrollment: tenant required to mint token")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	ts.mu.Lock()
	ts.tokens[tok] = tokenEntry{tenant: tenantID, expires: time.Now().Add(ttl)}
	ts.mu.Unlock()
	return tok, nil
}

// Redeem consumes a token, returning its tenant. It is strictly one-time: a
// successful redeem deletes the token, and an expired token is rejected (and
// swept). A spent, expired, or unknown token returns ok=false.
func (ts *TokenStore) Redeem(token string) (tenantID string, ok bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	e, found := ts.tokens[token]
	if !found {
		return "", false
	}
	delete(ts.tokens, token) // one-time regardless of outcome
	if time.Now().After(e.expires) {
		return "", false
	}
	return e.tenant, true
}
