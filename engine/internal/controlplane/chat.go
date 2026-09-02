package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
)

// Assistant chat history — step 2 of docs/plan/platform-assistant.md.
//
//	GET    /api/assistant/chats            list (or ?q= to search)
//	POST   /api/assistant/chats            create
//	GET    /api/assistant/chats/{id}       messages
//	PATCH  /api/assistant/chats/{id}       rename / pin
//	DELETE /api/assistant/chats/{id}       delete
//
// Everything here is CRUD. The one part that carries weight is scopeFor.

// scopeFor derives the caller's chatstore.Scope from the VERIFIED session.
//
// This is the security boundary of the whole feature, so it is small and it is
// the only place a Scope is constructed for a request:
//
//   - UserID comes from the principal's Subject. Never from a payload, never
//     from a query parameter. Chat history is per-operator, and a user id a
//     caller can choose is a user id a caller can impersonate.
//   - TenantID comes from the principal's grants, not from the request. On this
//     control plane tenant is derived from the session upstream; re-deriving it
//     here from anything the client sent would reintroduce exactly the class of
//     bug the mTLS tenant derivation exists to prevent.
//   - CrossTenant is set only for a genuine cross-tenant role, and it widens
//     which of the CALLER'S OWN chats are visible. It never changes whose chats
//     they are, and it has NO effect on what the assistant can read when
//     answering — that is governed by the forwarded session
//     (platform-assistant.md §1).
func scopeFor(p authz.Principal) (chatstore.Scope, error) {
	if strings.TrimSpace(p.Subject) == "" {
		return chatstore.Scope{}, chatstore.ErrNoScope
	}
	s := chatstore.Scope{UserID: p.Subject}
	for _, g := range p.Grants {
		if g.Role.IsCrossTenant() {
			s.CrossTenant = true
			continue
		}
		if s.TenantID == "" && g.TenantID != "" {
			s.TenantID = g.TenantID
		}
	}
	// A cross-tenant operator has no single tenant; rows they create are
	// stamped with the platform scope rather than a tenant they do not own.
	if s.TenantID == "" && s.CrossTenant {
		s.TenantID = crossTenantScopeID
	}
	if err := s.Validate(); err != nil {
		return chatstore.Scope{}, err
	}
	return s, nil
}

// crossTenantScopeID stamps rows authored by a cross-tenant operator.
//
// A sentinel rather than "" so the RLS predicate still matches a concrete value
// — current_setting('app.tenant_id') returning empty would make the policy
// compare against NULL and match nothing, which would look like data loss.
const crossTenantScopeID = "__msoc__"

func (s *Server) registerChatRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/assistant/chats", s.handleChats)
	mux.HandleFunc("/api/assistant/chats/", s.handleChatByID)
}

// chatScope resolves the caller or writes the failure. Returns ok=false when
// the response has already been written.
func (s *Server) chatScope(w http.ResponseWriter, r *http.Request) (chatstore.Scope, bool) {
	p, ok := s.principal(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return chatstore.Scope{}, false
	}
	sc, err := scopeFor(p)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no chat scope for this principal"})
		return chatstore.Scope{}, false
	}
	if s.chats == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "chat history is not enabled"})
		return chatstore.Scope{}, false
	}
	return sc, true
}

func (s *Server) handleChats(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.chatScope(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		q := r.URL.Query().Get("q")
		// Search and list are the same endpoint: an empty query IS the list,
		// so the sidebar has one code path and cannot show different shapes.
		chats, err := s.chats.Search(sc, q, limit)
		if err != nil {
			chatError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"chats": chats})
	case http.MethodPost:
		var body struct{ Title, Mode string }
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body)
		// Every chat is a SIDEBAR conversation: the drill panels ask
		// incognito and never create one. So this is the point at which a
		// deployment running two models commits this thread to the deeper of
		// them, once, for the conversation's whole life. With one model
		// configured, ModelFor returns it and nothing changes.
		c, err := s.chats.CreateChat(sc, body.Title, body.Mode, s.cfg.Assistant.ModelFor(true))
		if err != nil {
			chatError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleChatByID(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.chatScope(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/assistant/chats/")
	// One segment only: an id carrying a slash would let a caller address a
	// path this handler never intended to serve.
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad chat id"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		msgs, err := s.chats.ListMessages(sc, id, limit)
		if err != nil {
			chatError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
	case http.MethodPatch:
		var body struct {
			Title  *string `json:"title"`
			Pinned *bool   `json:"pinned"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
			return
		}
		if body.Title != nil {
			if err := s.chats.RenameChat(sc, id, *body.Title); err != nil {
				chatError(w, err)
				return
			}
		}
		if body.Pinned != nil {
			if err := s.chats.PinChat(sc, id, *body.Pinned); err != nil {
				chatError(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if err := s.chats.DeleteChat(sc, id); err != nil {
			chatError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// chatError maps store errors to responses.
//
// ErrNotFound becomes a plain 404 with no detail: absent and not-yours must be
// indistinguishable, or the endpoint becomes a cross-tenant existence oracle.
func chatError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, chatstore.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, chatstore.ErrNoScope):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no chat scope"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chat store unavailable"})
	}
}
