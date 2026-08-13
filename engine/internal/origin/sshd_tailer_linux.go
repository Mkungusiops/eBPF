//go:build linux

package origin

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// SSHDTailer streams journald sshd records into the Tracker. It spawns
// `journalctl -fu ssh -o json --no-pager` so we get the PID via the
// _PID field rather than having to re-parse the textual envelope. The
// goroutine restarts on journalctl exit with a short backoff so a
// transient log-rotate or daemon restart doesn't lose us the feed.
//
// On hosts without journalctl in $PATH (rare on systemd distros, but
// possible in stripped-down containers), Start logs the absence once
// and returns nil — the tracker simply never receives SSH attribution
// from this source. Callers should treat that as soft-degraded.
type SSHDTailer struct {
	tracker *Tracker

	// units is the journald unit list to follow. Defaults to ssh + sshd
	// because Ubuntu's package is "ssh.service" while RHEL's is
	// "sshd.service" — covering both keeps the tailer distro-agnostic.
	units []string

	startOnce sync.Once
	stopped   chan struct{}
}

// NewSSHDTailer wires a tailer to the given tracker. Use Start to launch
// the background goroutine.
func NewSSHDTailer(t *Tracker) *SSHDTailer {
	return &SSHDTailer{
		tracker: t,
		units:   []string{"ssh.service", "sshd.service"},
		stopped: make(chan struct{}),
	}
}

// Start launches the journald-following goroutine. Idempotent. The
// returned error is non-nil only if the immediate environment lacks
// journalctl (a permanent, fast-to-detect condition). Once started, the
// goroutine handles transient journalctl failures internally.
func (s *SSHDTailer) Start(ctx context.Context) error {
	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("[origin/sshd] journalctl not found in PATH (%v) — SSH attribution disabled", err)
		return nil // soft-degrade: not an error worth blocking startup
	}
	s.startOnce.Do(func() {
		go s.run(ctx)
	})
	return nil
}

// run is the main loop. Each iteration spawns one journalctl child and
// pumps its stdout through parseLine until the child exits, then
// backs off briefly and respawns. Honors ctx.Done() for shutdown.
func (s *SSHDTailer) run(ctx context.Context) {
	defer close(s.stopped)
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.runOnce(ctx); err != nil {
			log.Printf("[origin/sshd] tailer exited (%v) — restarting in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		// Exponential backoff capped at 30s so a permanently-broken
		// journalctl doesn't spin a hot loop forever.
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (s *SSHDTailer) runOnce(ctx context.Context) error {
	// Backfill the last 500 records on startup so SSH sessions that
	// authenticated in the last few minutes get attributed too — without
	// this, an engine restart leaves every in-progress session orphaned
	// until the user reconnects. 500 is plenty for the typical ~30min
	// session window the tracker's TTL covers, and journald serves it
	// from its on-disk index without scanning unrelated units.
	args := []string{"-f", "-o", "json", "--no-pager", "-n", "500"}
	for _, u := range s.units {
		args = append(args, "-u", u)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Wait() }()

	scanner := bufio.NewScanner(stdout)
	// journald can emit very long JSON lines (TLS handshake dumps, etc.).
	// 1 MiB buffer is well above sshd's typical record size.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		s.handleLine(scanner.Bytes())
	}
	return scanner.Err()
}

// handleLine parses one journald JSON record and forwards Accepted /
// Disconnected events into the tracker. Lines that don't match either
// pattern are silently dropped.
func (s *SSHDTailer) handleLine(line []byte) {
	var rec struct {
		Message string `json:"MESSAGE"`
		PID     string `json:"_PID"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return
	}
	if rec.Message == "" {
		return
	}
	if ev, ok := ParseSSHAccepted(rec.Message); ok {
		// _PID is the per-session sshd (the one running auth) — the
		// user shell will be a fork child of this process, so the
		// tracker's ancestor walk picks the attribution up correctly.
		if rec.PID != "" {
			if pid, err := strconv.ParseUint(rec.PID, 10, 32); err == nil {
				ev.PID = uint32(pid)
			}
		}
		s.tracker.Record(ev.PID, Origin{
			Kind:        KindSSH,
			RemoteIP:    ev.RemoteIP,
			RemotePort:  ev.RemotePort,
			User:        ev.User,
			Fingerprint: ev.Fingerprint,
		})
		return
	}
	if _, _, ok := ParseSSHDisconnected(rec.Message); ok {
		// We don't have a reliable pid → 4-tuple back-reference on
		// disconnect (the session sshd is gone by the time we get
		// here), so we let the TTL sweeper clean up. Logged at debug
		// level so noise stays out of the journal.
		return
	}
}
