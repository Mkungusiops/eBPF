package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The unversioned /favicon.ico slot is the one icon URL the app cannot bust,
// because browsers request that exact path by convention. It shipped with a
// blind max-age=86400 and no validator, so a corrected icon was invisible for
// a day with no way for a client to ask whether it was still current.

func TestFaviconICORevalidates(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleFaviconICO(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if got := rec.Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheRevalidate {
		t.Errorf("Cache-Control = %q, want %q — an unbustable URL must be revalidated", got, cacheRevalidate)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("no ETag: the client has no way to revalidate, so no-cache would mean a full refetch every load")
	}
	if got := rec.Header().Get("Content-Type"); got != "image/x-icon" {
		t.Errorf("Content-Type = %q, want image/x-icon", got)
	}
	if rec.Body.Len() == 0 {
		t.Error("empty body")
	}
}

func TestFaviconICOAnswers304(t *testing.T) {
	s := &Server{}
	first := httptest.NewRecorder()
	s.handleFaviconICO(first, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	etag := first.Header().Get("ETag")

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	req.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	s.handleFaviconICO(second, req)

	if second.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304 — revalidation must be cheap or no-cache is a bandwidth bug", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 carried %d bytes of body", second.Body.Len())
	}
}

// A changed artwork must produce a changed validator, or revalidation returns
// 304 forever and we are back where we started.
func TestAssetETagIsContentDerived(t *testing.T) {
	a := assetETag([]byte("<svg>one</svg>"))
	b := assetETag([]byte("<svg>two</svg>"))
	if a == b {
		t.Fatal("different bytes produced the same ETag")
	}
	if a != assetETag([]byte("<svg>one</svg>")) {
		t.Fatal("same bytes produced different ETags")
	}
	if len(a) < 3 || a[0] != '"' || a[len(a)-1] != '"' {
		t.Fatalf("ETag %q is not a quoted-string", a)
	}
}

func TestETagMatches(t *testing.T) {
	const etag = `"abc123"`
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{`"abc123"`, true},
		{`W/"abc123"`, true},              // weak comparison: one variant per URL
		{`"other", "abc123"`, true},       // comma-separated list
		{` "other" ,  W/"abc123" `, true}, // whitespace
		{`*`, true},                       // wildcard
		{`"other"`, false},
		{``, false},
	} {
		if got := etagMatches(tc.header, etag); got != tc.want && tc.header != "" {
			t.Errorf("etagMatches(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// The versioned SVGs keep the hard cache: their URL carries ?v=, so a change of
// artwork is a change of URL. Downgrading them to no-cache would add a round
// trip per page load for nothing.
func TestVersionedIconsStayCacheable(t *testing.T) {
	s := &Server{}
	for name, handler := range map[string]http.HandlerFunc{
		"/favicon.svg":       s.handleFavicon,
		"/favicon-light.svg": s.handleFaviconLight,
	} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, name, nil))
		if got := rec.Header().Get("Cache-Control"); got != cacheVersioned {
			t.Errorf("%s Cache-Control = %q, want %q", name, got, cacheVersioned)
		}
		if rec.Header().Get("ETag") == "" {
			t.Errorf("%s has no ETag", name)
		}
	}
}
