package api

import (
	"fmt"
	"hash"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
)

const (
	htmlCacheControl        = "no-cache, no-store, must-revalidate"
	staticAssetCacheControl = "public, max-age=31536000, immutable"
)

func embeddedWebDist() (fs.FS, bool) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, false
	}
	info, err := fs.Stat(sub, "index.html")
	if err != nil || info.IsDir() {
		return sub, false
	}
	return sub, true
}

func serveHTMLBytes(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", htmlCacheControl)
	_, _ = w.Write(b)
}

func serveMissingEmbeddedWeb(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", htmlCacheControl)
	http.Error(w, "embedded frontend assets are missing; run make build or make build-linux from the repository root", http.StatusInternalServerError)
}

func (s *Server) serveEmbeddedWebPage(w http.ResponseWriter, name string) bool {
	web, ok := embeddedWebDist()
	if !ok {
		return false
	}
	b, err := fs.ReadFile(web, name)
	if err != nil {
		return false
	}
	serveHTMLBytes(w, b)
	return true
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.serveEmbeddedWebPage(w, "login.html") {
		return
	}
	serveMissingEmbeddedWeb(w)
}

// pwaRootFiles are the PWA support files Vite emits at the dist root (not
// under /assets/). They must be served from the site root: the service worker
// needs root scope to control every page, and the manifest/icons resolve from
// "/". Each entry carries its own content type and cache policy.
var pwaRootFiles = map[string]struct {
	contentType  string
	cacheControl string
}{
	// The worker itself must never be long-cached or browsers won't pick up
	// new builds; revalidate every load.
	"sw.js":                    {"text/javascript; charset=utf-8", htmlCacheControl},
	"pwa-install-bridge.js":    {"text/javascript; charset=utf-8", htmlCacheControl},
	"manifest.webmanifest":     {"application/manifest+json; charset=utf-8", "public, max-age=3600"},
	"pwa-192x192.png":          {"image/png", staticAssetCacheControl},
	"pwa-512x512.png":          {"image/png", staticAssetCacheControl},
	"pwa-maskable-512x512.png": {"image/png", staticAssetCacheControl},
	"apple-touch-icon.png":     {"image/png", staticAssetCacheControl},
}

func isPWARootPath(p string) bool {
	clean := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "/")), "/")
	_, ok := pwaRootFiles[clean]
	return ok
}

// handlePWAFile serves a single PWA support file from the embedded build. It is
// public (registered for unauthenticated access) so the manifest, icons, and
// worker load on the login page and before a session exists.
func (s *Server) handlePWAFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")), "/")
	meta, ok := pwaRootFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	web, ok := embeddedWebDist()
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(web, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", meta.contentType)
	w.Header().Set("Cache-Control", meta.cacheControl)
	if name == "sw.js" {
		// Permit root scope explicitly so the worker controls the whole origin.
		w.Header().Set("Service-Worker-Allowed", "/")
	}
	_, _ = w.Write(b)
}

func (s *Server) handleWebAssets(w http.ResponseWriter, r *http.Request) {
	web, ok := embeddedWebDist()
	if !ok {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")), "/")
	info, err := fs.Stat(web, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", staticAssetCacheControl)
	http.FileServerFS(web).ServeHTTP(w, r)
}

func hashEmbeddedWebDist(h hash.Hash) (int, error) {
	web, ok := embeddedWebDist()
	if !ok {
		return 0, nil
	}
	var names []string
	if err := fs.WalkDir(web, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if path.Base(name) == ".keep" {
			return nil
		}
		names = append(names, name)
		return nil
	}); err != nil {
		return 0, err
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := fs.ReadFile(web, name)
		if err != nil {
			return 0, err
		}
		writeVersionHashEntry(h, "web/"+name, b)
	}
	return len(names), nil
}

func writeVersionHashEntry(h hash.Hash, name string, data []byte) {
	_, _ = fmt.Fprintf(h, "%s\n%d\n", name, len(data))
	_, _ = h.Write(data)
	_, _ = h.Write([]byte{0})
}

func isBuiltAssetPath(p string) bool {
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	return strings.HasPrefix(clean, "/assets/")
}
