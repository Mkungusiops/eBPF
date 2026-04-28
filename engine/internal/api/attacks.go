package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// allowlistedAttacks is the closed set of script names the dashboard may
// trigger. Anything else is rejected — we don't accept arbitrary paths.
var allowlistedAttacks = map[string]string{
	"01-webshell":             "exec(curl) + chmod +x + cat /etc/shadow",
	"02-credential-theft":     "reads of shadow, sudoers, ~/.ssh/*",
	"03-reverse-shell":        "bash opens TCP socket (loopback)",
	"04-privilege-escalation": "setuid(0) + root reads of credentials",
	"05-living-off-the-land":  "curl|sh + base64 decode",
	"06-persistence":          "chmod +x staged script + dotfile recon",
}

var (
	attackDirMu  sync.RWMutex
	attackDir    string
	attackRateMu sync.Mutex
	attackLast   = make(map[string]time.Time) // simple per-script throttle
)

func SetAttackDir(dir string) {
	attackDirMu.Lock()
	attackDir = dir
	attackDirMu.Unlock()
}

type attackInfo struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

func (s *Server) handleAttackList(w http.ResponseWriter, r *http.Request) {
	out := make([]attackInfo, 0, len(allowlistedAttacks))
	for id, desc := range allowlistedAttacks {
		out = append(out, attackInfo{ID: id, Description: desc})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleAttackRun executes one of the allowlisted attack scripts in the
// background. The script is bash-executed against the server's local
// attacks/ directory. Returns 202 Accepted on launch.
func (s *Server) handleAttackRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("id")
	if _, ok := allowlistedAttacks[id]; !ok {
		http.Error(w, "unknown attack id", http.StatusBadRequest)
		return
	}

	// Per-script throttle: 5s minimum between runs of the same script.
	attackRateMu.Lock()
	if last, ok := attackLast[id]; ok && time.Since(last) < 5*time.Second {
		attackRateMu.Unlock()
		http.Error(w, "throttled — wait a few seconds", http.StatusTooManyRequests)
		return
	}
	attackLast[id] = time.Now()
	attackRateMu.Unlock()

	attackDirMu.RLock()
	dir := attackDir
	attackDirMu.RUnlock()
	if dir == "" {
		http.Error(w, "attack dir not configured", http.StatusServiceUnavailable)
		return
	}
	scriptPath := filepath.Join(dir, id+".sh")
	abs, err := filepath.Abs(scriptPath)
	if err != nil {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	// Defense in depth: ensure the resolved path is still under dir.
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		http.Error(w, "bad attack dir", http.StatusInternalServerError)
		return
	}
	if !filepath.IsAbs(abs) || !hasPrefix(abs, dirAbs) {
		http.Error(w, "path traversal rejected", http.StatusForbidden)
		return
	}

	go func() {
		log.Printf("[attack-run] starting %s", id)
		cmd := exec.Command("bash", abs)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[attack-run] %s failed: %v\n%s", id, err, string(out))
			return
		}
		log.Printf("[attack-run] %s ok", id)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "launched", "id": id})
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
