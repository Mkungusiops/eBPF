package controlplane

import (
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// The engine's quick-fire Attacks + Honeypots panels, re-served tenant-scoped.
// Attacks/honeypots are a demo/lab surface (to be removed later); here /api/attacks
// and /api/honeypots list the catalog, and /api/run-attack injects a synthetic
// alert into the tenant's store so the operator sees the dashboard react.

type simAttack struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Desc   string `json:"description"`
	Sev    string `json:"severity"`
	mitre  string
	tactic string
}

var simAttacks = []simAttack{
	{"01-suid-abuse", "SUID privilege escalation", "Abuse a setuid binary to escalate privileges", "high", "T1548", "privilege-escalation"},
	{"02-credential-read", "Credential store read", "Read /etc/shadow and credential files", "critical", "T1003", "credential-access"},
	{"03-reverse-shell", "Reverse shell", "Shell dials out to a C2 endpoint", "critical", "T1059", "execution"},
	{"04-sensitive-file", "Sensitive file access", "Touch a monitored honeypot decoy", "medium", "T1005", "collection"},
	{"05-container-escape", "Container escape attempt", "Break out of a container namespace", "high", "T1611", "privilege-escalation"},
}

func (s *Server) registerAttackRoutes(mux *http.ServeMux) {
	// Lab-only. The file header has said "to be removed later" since it was
	// written; this is that removal, made reversible by a flag instead of a
	// delete because the e2e suite and lab demos still want them.
	//
	// The control-plane variants are the more dangerous half of the pair:
	// handleRunAttack does not run anything, it FABRICATES an alert and writes
	// it into the tenant's real telemetry table, where /api/alert-stats, the
	// MITRE coverage panel and every exported report count it as a genuine
	// finding. handleHoneypots reports decoy hits from Go constants that no
	// host produced. An analyst investigating either is investigating nothing,
	// and an auditor reading the export is reading a fiction.
	mux.HandleFunc("/api/attacks", s.labOnly(s.handleAttacks))
	mux.HandleFunc("/api/honeypots", s.labOnly(s.handleHoneypots))
	mux.HandleFunc("/api/run-attack", s.labOnly(s.handleRunAttack))
}

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, simAttacks)
}

func (s *Server) handleHoneypots(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	type honeypot struct {
		Path string `json:"path"`
		Desc string `json:"description"`
		Hits int    `json:"hits"`
	}
	writeJSON(w, 200, []honeypot{
		{"/etc/ssh/ssh_host_ed25519_key.decoy", "Fake SSH host key", 3},
		{"/root/.aws/credentials.decoy", "Fake AWS credentials", 1},
		{"/var/backups/passwd.decoy", "Fake password backup", 0},
		{"/opt/app/.env.decoy", "Fake application secrets", 2},
	})
}

// handleRunAttack fires a quick-fire attack scenario: it stamps a synthetic
// alert into the tenant's store so the dashboard + live feed react. Form-encoded
// {id}. RBAC ActionRespond (firing an attack is an operator action).
func (s *Server) handleRunAttack(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	atk := simAttacks[0]
	for _, a := range simAttacks {
		if a.ID == id {
			atk = a
			break
		}
	}
	rec := &ebpfsocv1.TelemetryRecord{
		DedupKey: "attack-" + atk.ID + "-" + time.Now().Format(time.RFC3339Nano),
		Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
			OccurredAt:  timestamppb.Now(),
			Severity:    atk.Sev,
			Title:       "Quick-fire attack: " + atk.Name,
			Description: "Operator-triggered scenario " + atk.ID + " — " + atk.Desc,
			ExecId:      "attack-" + atk.ID,
			Score:       80,
			MitreId:     atk.mitre,
			Tactic:      atk.tactic,
		}},
	}
	if err := s.cfg.Store.Put(ingest.StampedRecord{TenantID: tenant, AgentID: "console", Record: rec}); err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": atk.ID, "fired": atk.Name})
}


// labOnly answers 404 when this deployment is not a lab. 404 rather than 403:
// a 403 confirms the endpoint exists, and one of the endpoints behind this gate
// writes to the evidence store.
func (s *Server) labOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.LabMode {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}
