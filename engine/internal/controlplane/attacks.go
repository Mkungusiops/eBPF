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
	mux.HandleFunc("/api/attacks", s.handleAttacks)
	mux.HandleFunc("/api/honeypots", s.handleHoneypots)
	mux.HandleFunc("/api/run-attack", s.handleRunAttack)
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
