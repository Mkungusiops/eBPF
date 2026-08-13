// Package fleetprobe answers one question for the console's Fleet view: is
// that peer host answering HTTP right now?
//
// It exists because the browser cannot answer it. A Fleet panel served from
// https://console.example.io that fetches a peer directly is blocked three
// different ways — mixed content on http:// peers, absent CORS headers, and
// SameSite=Lax session cookies that are never sent cross-site. The result is
// a peer that is demonstrably up being rendered DOWN. Probing from the server
// removes all three constraints at once and keeps the engine's first-party
// CSRF posture intact.
//
// Reachability here means "the peer completed an HTTP exchange", NOT "we are
// authorised on it". A 401 proves a healthy peer that simply does not know
// this caller, so it counts as reachable and the status code is reported. The
// panel must never imply we probed further than we did.
package fleetprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// MaxTargets caps one request. The Fleet directory is hand-maintained;
	// anything beyond this is misuse, not a fleet.
	MaxTargets   = 32
	probeTimeout = 5 * time.Second
)

// Result is one peer's reachability, shaped for direct JSON return to the UI.
type Result struct {
	URL string `json:"url"`
	// Reachable is true when the peer completed an HTTP exchange, whatever
	// the status. See the package comment: this is not an authz claim.
	Reachable bool   `json:"reachable"`
	Status    int    `json:"status,omitempty"`
	RTTMs     int64  `json:"rtt_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Prober probes peers over a fixed http.Client. The zero value is unusable;
// call New.
type Prober struct {
	client *http.Client
}

// New builds a Prober. Redirects are never followed: a redirect to a blocked
// address would otherwise walk straight past the dial guard below.
func New() *Prober {
	return &Prober{client: &http.Client{
		Timeout:       probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// ErrBlocked is returned for targets the guard refuses to dial.
var ErrBlocked = errors.New("blocked target")

// checkTarget validates the URL itself before any DNS or dial happens. The
// scheme check is what stops the endpoint reading local files or speaking
// non-HTTP protocols; blockedIP handles the address-level guard afterwards.
func checkTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable url", ErrBlocked)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q is not http or https", ErrBlocked, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: missing host", ErrBlocked)
	}
	return u, nil
}

// blockedIP reports addresses the prober must never dial.
//
// Loopback and RFC1918 are both permitted on purpose. Probing 192.168.x.y and
// 127.0.0.1 peers is the panel's actual job — the local development stack runs
// exactly there — and for an already-authenticated operator, learning that a
// port on a box they administer is open is not an escalation. Link-local is
// different in kind: 169.254.169.254 is the instance-metadata service on AWS,
// GCP and Azure alike, and reaching it would turn a status panel into a path
// to the host's cloud credentials. Because the check runs on the resolved IP,
// hostname aliases for metadata (metadata.google.internal) are covered too.
func blockedIP(ip net.IP) (bool, string) {
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return true, "link-local address (cloud metadata range)"
	case ip.IsUnspecified():
		return true, "unspecified address"
	case ip.IsMulticast():
		return true, "multicast address"
	}
	return false, ""
}

// dialGuard rejects blocked addresses at connect time. Doing it in the dialer
// rather than by pre-resolving the hostname closes the DNS-rebinding window:
// the address checked is the exact one being connected to.
func (p *Prober) dialGuard(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	var lastErr error = fmt.Errorf("%w: no permitted address for %s", ErrBlocked, host)
	for _, ipa := range ips {
		if blocked, why := blockedIP(ipa.IP); blocked {
			lastErr = fmt.Errorf("%w: %s", ErrBlocked, why)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// probeOne performs the exchange for a single peer. It asks for /healthz —
// which the control plane serves unauthenticated — and falls back to the base
// URL when the peer has no such route, so engines and control planes are both
// covered without the caller needing to know which it is talking to.
func (p *Prober) probeOne(ctx context.Context, raw string) Result {
	res := Result{URL: raw}
	u, err := checkTarget(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	base := strings.TrimRight(u.String(), "/")

	client := *p.client
	client.Transport = &http.Transport{
		DialContext:         p.dialGuard,
		TLSHandshakeTimeout: probeTimeout,
		DisableKeepAlives:   true,
	}

	started := time.Now()
	status, err := p.exchange(ctx, &client, base+"/healthz")
	if err == nil && status == http.StatusNotFound {
		// No /healthz on this peer — the base URL still proves liveness.
		if s2, err2 := p.exchange(ctx, &client, base+"/"); err2 == nil {
			status = s2
		}
	}
	res.RTTMs = time.Since(started).Milliseconds()
	if err != nil {
		res.Error = trimDialError(err)
		return res
	}
	res.Reachable = true
	res.Status = status
	return res
}

func (p *Prober) exchange(ctx context.Context, client *http.Client, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "ebpf-soc-fleet-probe/1")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	// The body is never read: this is a liveness check, and not forwarding
	// peer response bodies is what keeps the endpoint from being a general
	// purpose fetch proxy.
	resp.Body.Close()
	return resp.StatusCode, nil
}

// trimDialError keeps operator-facing errors readable. Go wraps dial failures
// in several layers of URL and transport context that add no diagnostic value
// in a status column.
func trimDialError(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && len(msg)-i < 60 {
		return strings.TrimSpace(msg[i+2:])
	}
	return msg
}

// Probe checks every target concurrently and returns results in input order.
// Targets beyond MaxTargets are dropped rather than erroring the whole call,
// so one over-long directory cannot blank the panel.
func (p *Prober) Probe(ctx context.Context, targets []string) []Result {
	if len(targets) > MaxTargets {
		targets = targets[:MaxTargets]
	}
	out := make([]Result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			out[i] = p.probeOne(ctx, t)
		}(i, t)
	}
	wg.Wait()
	return out
}
