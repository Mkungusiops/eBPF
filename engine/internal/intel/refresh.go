package intel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Optional feed refresh.
//
// OFF BY DEFAULT, and that default is the security decision. A security product
// must not acquire an outbound dependency because someone upgraded it — the
// same rule the assistant config already follows. An operator who wants feeds
// refreshed says so, and an air-gapped deployment keeps working by dropping
// files into the directory by hand.
//
// The refresher only ever fetches FEEDS. It never sends an observable anywhere;
// see doc.go for why that is the whole point.

// Feed is one refreshable source.
type Feed struct {
	// Name becomes the filename, and therefore the source attributed to every
	// indicator in it.
	Name string `yaml:"name"`
	// URL is fetched verbatim. Must be https in production; http is permitted
	// for an on-premises mirror and logged loudly.
	URL string `yaml:"url"`
	// Confidence applied to every indicator in this feed unless a line
	// overrides it.
	Confidence string `yaml:"confidence"`
}

// RefreshConfig configures the optional refresher.
type RefreshConfig struct {
	// Dir is the feed directory, shared with the hand-dropped files.
	Dir string `yaml:"dir"`
	// Interval between refreshes. Zero disables the refresher entirely.
	Interval time.Duration `yaml:"interval"`
	// Feeds to fetch.
	Feeds []Feed `yaml:"feeds"`
	// Timeout bounds one fetch.
	Timeout time.Duration `yaml:"timeout"`
	// MaxBytes bounds one feed's download, so a redirected or compromised feed
	// URL cannot fill the disk.
	MaxBytes int64 `yaml:"max_bytes"`
}

// DefaultRefresh has no feeds and no interval: disabled.
func DefaultRefresh() RefreshConfig {
	return RefreshConfig{Interval: 0, Timeout: 30 * time.Second, MaxBytes: 32 << 20}
}

// Enabled reports whether the refresher should run.
func (c RefreshConfig) Enabled() bool {
	return c.Interval > 0 && len(c.Feeds) > 0 && strings.TrimSpace(c.Dir) != ""
}

// Refresher periodically fetches feeds into the feed directory and reloads the
// set.
type Refresher struct {
	cfg    RefreshConfig
	set    *Set
	client *http.Client

	lastRun time.Time
	lastErr string
}

func NewRefresher(cfg RefreshConfig, set *Set) *Refresher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 32 << 20
	}
	return &Refresher{cfg: cfg, set: set, client: &http.Client{Timeout: cfg.Timeout}}
}

// Run refreshes on the configured interval until ctx is done. It performs one
// refresh immediately so a restart picks up feed changes without waiting a full
// interval.
func (r *Refresher) Run(ctx context.Context) {
	if !r.cfg.Enabled() {
		return
	}
	r.RefreshOnce(ctx)
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.RefreshOnce(ctx)
		}
	}
}

// RefreshOnce fetches every feed, then reloads the set from disk.
//
// A feed that fails leaves its PREVIOUS FILE IN PLACE. This is the single most
// important behaviour here: the alternative — truncating the file, or writing a
// partial download — silently reduces coverage to zero while every health check
// still passes, and "matched nothing" is indistinguishable from "estate is
// clean". Failing loudly and keeping the last good copy is the only safe
// degradation for this component.
func (r *Refresher) RefreshOnce(ctx context.Context) {
	if err := os.MkdirAll(r.cfg.Dir, 0o755); err != nil {
		r.lastErr = err.Error()
		slog.Warn("intel: feed directory unavailable", "dir", r.cfg.Dir, "error", err)
		return
	}
	var failures []string
	for _, f := range r.cfg.Feeds {
		if err := r.fetch(ctx, f); err != nil {
			failures = append(failures, f.Name+": "+err.Error())
			slog.Warn("intel: feed refresh failed, keeping the last good copy",
				"feed", f.Name, "error", err)
		}
	}
	r.lastRun = time.Now()
	r.lastErr = strings.Join(failures, "; ")
	if err := r.set.LoadDir(r.cfg.Dir); err != nil {
		slog.Warn("intel: reload after refresh failed", "error", err)
		return
	}
	st := r.set.Status()
	slog.Info("intel: feeds reloaded", "indicators", st.Indicators, "sources", len(st.Sources),
		"failed_feeds", len(failures))
}

// fetch downloads one feed to a temporary file and renames it into place.
//
// Write-then-rename, not write-in-place: a process reading the directory while
// a feed is half-written would load a truncated indicator set, and rename is
// atomic on the same filesystem.
func (r *Refresher) fetch(ctx context.Context, f Feed) error {
	name := sanitiseFeedName(f.Name)
	if name == "" {
		return fmt.Errorf("feed has no usable name")
	}
	conf := strings.ToLower(strings.TrimSpace(f.Confidence))
	switch conf {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		conf = ConfidenceMedium
	}
	target := filepath.Join(r.cfg.Dir, name+"."+conf+".txt")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ebpf-soc-intel/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(r.cfg.Dir, ".feed-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, r.cfg.MaxBytes))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n == 0 {
		// An empty feed is a failure, not an empty set. Accepting it would
		// replace a working indicator list with nothing.
		return fmt.Errorf("feed returned no data")
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, target)
}

// sanitiseFeedName keeps a configured name from escaping the feed directory or
// colliding with allow.txt.
func sanitiseFeedName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	var b strings.Builder
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "allow" {
		return "" // the operator allowlist is never overwritten by a feed
	}
	return out
}

// RefreshStatus reports the refresher's last run for the API.
type RefreshStatus struct {
	Enabled  bool      `json:"enabled"`
	Feeds    int       `json:"feeds"`
	Interval string    `json:"interval,omitempty"`
	LastRun  time.Time `json:"last_run,omitempty"`
	LastErr  string    `json:"last_error,omitempty"`
}

func (r *Refresher) Status() RefreshStatus {
	if r == nil {
		return RefreshStatus{}
	}
	st := RefreshStatus{Enabled: r.cfg.Enabled(), Feeds: len(r.cfg.Feeds), LastRun: r.lastRun, LastErr: r.lastErr}
	if r.cfg.Interval > 0 {
		st.Interval = r.cfg.Interval.String()
	}
	return st
}

// FeedFile is the refresher's configuration, read from the FEED DIRECTORY
// itself rather than from each binary's own config.
//
// One file, `feeds.yaml`, sitting beside the indicator files it produces. That
// placement is the whole design: all three binaries already know where the feed
// directory is, so enabling refresh needs no new flag, no config plumbing
// through two settings structs, and no third place for the engine and the agent
// to disagree. An operator adding a feed edits the same directory they already
// drop files into.
//
//	interval: 6h
//	feeds:
//	  - name: feodo-c2
//	    url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
//	    confidence: medium
type FeedFile struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	MaxBytes int64         `yaml:"max_bytes"`
	Feeds    []Feed        `yaml:"feeds"`
}

// FeedFileName is the fixed name looked for inside the feed directory.
const FeedFileName = "feeds.yaml"

// LoadRefreshConfig reads <dir>/feeds.yaml, returning a DISABLED config when it
// is absent.
//
// Absent means off, and that is the default state of every deployment: a
// security product must not acquire an outbound dependency because someone
// upgraded it. A malformed file is also off, and loudly — the alternative is a
// deployment that believes it is refreshing feeds and is not, which is the
// silent-coverage-loss failure this package spends most of its care avoiding.
func LoadRefreshConfig(dir string) (RefreshConfig, error) {
	cfg := DefaultRefresh()
	cfg.Dir = dir
	if strings.TrimSpace(dir) == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, FeedFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no file, no refresh — the normal case
		}
		return cfg, fmt.Errorf("intel: reading %s: %w", FeedFileName, err)
	}
	var ff FeedFile
	if err := yaml.Unmarshal(raw, &ff); err != nil {
		return cfg, fmt.Errorf("intel: %s is not readable YAML: %w", FeedFileName, err)
	}
	cfg.Feeds = ff.Feeds
	if ff.Interval > 0 {
		cfg.Interval = ff.Interval
	}
	if ff.Timeout > 0 {
		cfg.Timeout = ff.Timeout
	}
	if ff.MaxBytes > 0 {
		cfg.MaxBytes = ff.MaxBytes
	}
	// A file that lists feeds but no interval means "refresh these", not
	// "never refresh these". Defaulted rather than left at zero, because zero
	// silently disables the very thing the file was written to enable.
	if cfg.Interval <= 0 && len(cfg.Feeds) > 0 {
		cfg.Interval = 6 * time.Hour
	}
	return cfg, nil
}
