// Package edge answers one question about an inbound request: did it come
// through the public nginx edge, or did it originate on the box itself?
//
// It exists so build identity can be read without an operator login while
// staying off the public internet. Both deployments got that wrong in opposite
// directions: the single-tenant engine gated /api/version behind a session, so
// the one endpoint whose job is reporting the running revision could not verify
// a deploy (the fallback was md5-ing binaries over SSH); the multi-tenant
// control plane left it entirely ungated, publishing revision, dirty flag and
// build time of an enterprise security console to anyone who asked.
//
// This lives in its own package rather than being copied into both because it
// is a security predicate. Two copies drift, and the copy that drifts is the
// one nobody re-reads.
package edge

import (
	"net"
	"net/http"
)

// proxyHeaders are set by nginx on every request it forwards to either
// deployment (see the proxy_set_header lines in scripts/deploy/lib.sh).
var proxyHeaders = []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto"}

// LocalUnproxied reports whether r reached this process directly.
//
// The test is deliberately negative, so it fails CLOSED. A caller cannot strip
// a header the proxy adds, so the absence of every proxy header — from a
// loopback peer — is positive evidence the edge was not involved. Forging
// Host: localhost or X-Forwarded-For: 127.0.0.1 through the edge does not help:
// nginx still stamps its own headers, and their presence alone is
// disqualifying regardless of value.
//
// A loopback peer address on its own proves nothing, because nginx itself
// proxies from loopback. That is the trap this function is shaped around.
func LocalUnproxied(r *http.Request) bool {
	for _, h := range proxyHeaders {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
