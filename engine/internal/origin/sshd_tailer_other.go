//go:build !linux

package origin

import (
	"context"
	"log"
)

// SSHDTailer is a no-op on non-Linux builds so the engine still compiles
// in dev mode (macOS development against -fake or local Tetragon-less
// boxes). Start logs once and returns; the tracker simply never receives
// SSH attribution from this source.
type SSHDTailer struct{ tracker *Tracker }

func NewSSHDTailer(t *Tracker) *SSHDTailer { return &SSHDTailer{tracker: t} }

func (s *SSHDTailer) Start(_ context.Context) error {
	log.Printf("[origin/sshd] non-linux build — SSH attribution disabled (run on Linux for real journald tailer)")
	return nil
}
