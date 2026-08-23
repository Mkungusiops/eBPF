//go:build !unix

package intel

import "os"

// inodeOf has no portable equivalent off unix; the rest of the cache key still
// detects the changes that matter there.
func inodeOf(os.FileInfo) uint64 { return 0 }
