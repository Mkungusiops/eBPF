package controlplane

import (
	"net/http"
	"strconv"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Who accessed what — the operator access trail, served.
//
// # The half that was missing
//
// operator_audit is now written on every authorization outcome that crosses a
// tenant boundary or is refused. Written and unreadable is only half a control:
// a trail nobody can query is indistinguishable from no trail at all until the
// day someone needs it, which is the worst possible day to discover the gap.
//
// # Two audiences, one table
//
// A cross-tenant operator sees the whole trail. A tenant-bound analyst sees
// only the rows naming their tenant — which is the more important of the two
// views, because it is the customer asking who from the provider opened their
// estate. An MSSP that cannot answer that has asked its customers to take
// provider access on faith.
//
// # What it deliberately does not contain
//
// Own-tenant allowed reads. An operator reading their own tenant is the system
// working, and recording every one would bury the entries that matter and
// amplify writes on the read path. The response says so, because a view of an
// access log that silently omits a category invites the reader to conclude the
// omitted access never happened.
const operatorAuditDefaultLimit = 200

func (s *Server) registerOperatorAuditRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/operator-audit", s.handleOperatorAudit)
}

func (s *Server) handleOperatorAudit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	limit := operatorAuditDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	pg, hasPG := s.pgStore()
	if !hasPG {
		// The memory ring is a debugging aid, not the trail. Serving it as
		// though it were would present a list erased by the last restart as an
		// audit record.
		writeJSON(w, 200, map[string]any{
			"supported": false,
			"records":   []any{},
			"detail": "this deployment has no durable operator-audit store, so access records " +
				"live only in memory and are lost on restart. Nothing is being claimed about " +
				"who accessed what before now.",
		})
		return
	}

	crossTenant := authz.HasCrossTenant(p)
	scope := ""
	if !crossTenant {
		// A tenant-bound analyst reads their own tenant's rows and no others.
		// Falling back to "everything" for a principal with no grants would
		// expose the whole trail to the least privileged caller.
		tenants := authz.TenantScope(p)
		if len(tenants) == 0 {
			http.NotFound(w, r)
			return
		}
		scope = tenants[0]
		if q := r.URL.Query().Get("tenant"); q != "" {
			if !authz.Authorize(p, q, authz.ActionRead, s.auditor).Allowed {
				http.NotFound(w, r)
				return
			}
			scope = q
		}
	} else if q := r.URL.Query().Get("tenant"); q != "" {
		scope = q // a cross-tenant operator may narrow to one customer
	}

	var (
		records []centralstore.OperatorAudit
		err     error
	)
	if scope == "" {
		records, err = pg.OperatorAuditRecent(limit)
	} else {
		records, err = pg.OperatorAuditForTenant(scope, limit)
	}
	if err != nil {
		// Absent is not empty: rendering an empty trail on a failed read would
		// state that no one accessed anything.
		writeJSON(w, 200, map[string]any{
			"supported": true,
			"records":   []any{},
			"error":     "the operator access trail could not be read: " + err.Error(),
		})
		return
	}
	total, _ := pg.OperatorAuditCount(scope)

	writeJSON(w, 200, map[string]any{
		"supported": true,
		"records":   records,
		"scope":     scope,
		"viewing":   map[bool]string{true: "all tenants", false: "this tenant only"}[scope == ""],
		"returned":  len(records),
		// Stated so a view of the newest N never reads as the whole trail.
		"total":        total,
		"truncated":    total > len(records),
		"cross_tenant": crossTenant,
		"records_kept": "cross-tenant access and every refused attempt. Ordinary own-tenant reads " +
			"are not recorded — their absence here does not mean they did not happen.",
	})
}
