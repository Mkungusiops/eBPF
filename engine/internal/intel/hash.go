package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// Hashing executed binaries, so a hash feed has something to match.
//
// # Why this is gated rather than always on
//
// Tetragon reports a binary's PATH, not its content. Matching a hash feed
// therefore means reading the file — and doing that for every exec on a busy
// host means megabytes of disk reads on the event path, which is the one path
// that must never be slowed down (it is what containment latency is made of).
//
// So hashing is bounded three ways:
//
//   - The CALLER decides when to ask. In the pipeline that means hashing only
//     binaries the behavioural baseline has flagged as novel — which is both
//     the cheap set and exactly the interesting set. A binary this host has run
//     ten thousand times does not need its hash checked on run ten thousand
//     and one.
//   - Results are cached by (path, size, mtime, inode). A rehash happens only
//     when the file on disk actually changed, which is itself worth knowing.
//   - Files above maxHashBytes are skipped. A 400MB binary is not what a
//     dropper looks like, and reading one on the event path is a stall.
//
// The cache is bounded like everything else in this codebase that maps
// unbounded input.

// maxHashBytes is the largest file that will be hashed. 64MB comfortably
// covers real executables including statically linked Go binaries.
const maxHashBytes = 64 << 20

// maxCacheEntries bounds the hash cache.
const maxCacheEntries = 8192

type cacheKey struct {
	path  string
	size  int64
	mtime int64
	inode uint64
}

// Hasher computes and caches file digests.
type Hasher struct {
	mu    sync.Mutex
	cache map[cacheKey]string
	// hits and misses are reported so an operator can see whether the cache is
	// doing its job before concluding the feature is expensive.
	hits, misses uint64
}

func NewHasher() *Hasher { return &Hasher{cache: map[cacheKey]string{}} }

// Hash returns the lowercase hex SHA-256 of the file at path.
//
// Returns "" and false for anything it declines to hash — missing, too large,
// not a regular file, or unreadable. Never an error: a hash that cannot be
// computed is a missing signal, not a failure of the event that triggered it,
// and propagating an error here would put file-permission noise into the
// detection path.
func (h *Hasher) Hash(path string) (string, bool) {
	if h == nil || path == "" {
		return "", false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxHashBytes || fi.Size() == 0 {
		return "", false
	}
	key := cacheKey{path: path, size: fi.Size(), mtime: fi.ModTime().UnixNano(), inode: inodeOf(fi)}

	h.mu.Lock()
	if got, ok := h.cache[key]; ok {
		h.hits++
		h.mu.Unlock()
		return got, true
	}
	h.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", false
	}
	digest := hex.EncodeToString(sum.Sum(nil))

	h.mu.Lock()
	defer h.mu.Unlock()
	// Bounded: drop the whole cache rather than implementing an LRU. The cache
	// exists to stop repeat work within a busy period, and a host with more
	// than 8k distinct changed binaries in one window has bigger problems than
	// a cold cache.
	if len(h.cache) >= maxCacheEntries {
		h.cache = map[cacheKey]string{}
	}
	h.cache[key] = digest
	h.misses++
	return digest, true
}

// Stats reports cache effectiveness.
func (h *Hasher) Stats() (entries int, hits, misses uint64) {
	if h == nil {
		return 0, 0, 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cache), h.hits, h.misses
}
