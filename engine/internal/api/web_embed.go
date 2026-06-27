package api

import "embed"

// webFS is populated by the Makefile's web staging target from web/dist.
// The .keep placeholder keeps the directory embeddable for direct go builds,
// but page handlers intentionally fail closed when built HTML is missing.
//
//go:embed all:web
var webFS embed.FS
