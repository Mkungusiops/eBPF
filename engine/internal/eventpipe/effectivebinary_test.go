package eventpipe

import (
	"os"
	"runtime"
	"testing"
)

// An ordinary path is returned untouched, and costs nothing to check. This is
// the overwhelmingly common case on the event path.
func TestEffectiveBinaryLeavesRealPathsAlone(t *testing.T) {
	for _, bin := range []string{"/usr/bin/bash", "/usr/sbin/unix_chkpwd", "", "/tmp/dropper"} {
		if got := effectiveBinary(bin, 1); got != bin {
			t.Errorf("effectiveBinary(%q) = %q, want it unchanged", bin, got)
		}
	}
}

// A /proc path for a process that no longer exists must fall back to what the
// kernel reported, never to a guess or an empty string. An event attributed to
// "" is worse than one attributed to an fd path.
func TestEffectiveBinaryFallsBackWhenUnresolvable(t *testing.T) {
	// PID 0 is never a live process, so the readlink cannot succeed.
	const fd = "/proc/self/fd/9"
	if got := effectiveBinary(fd, 0); got != fd {
		t.Fatalf("effectiveBinary(%q, 0) = %q, want the kernel-reported path back", fd, got)
	}
}

// On Linux the resolution must actually work — that is the whole point. Our own
// PID is guaranteed to be live and to have a readable /proc/<pid>/exe.
func TestEffectiveBinaryResolvesALiveProcessOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("resolution reads /proc; the fallback path is covered above")
	}
	self := uint32(os.Getpid())
	got := effectiveBinary("/proc/self/fd/9", self)
	if got == "/proc/self/fd/9" {
		t.Fatal("a live process must resolve to its real executable, not the fd path")
	}
	if got == "" {
		t.Fatal("resolution must never yield an empty binary")
	}
}
