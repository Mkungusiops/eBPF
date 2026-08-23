//go:build unix

package intel

import (
	"os"
	"syscall"
)

// inodeOf completes the cache key so a file replaced in place — same path, same
// size, same mtime, different content — is not served a stale hash. That is not
// paranoia: it is precisely what an attacker overwriting a system binary tries
// to look like.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
