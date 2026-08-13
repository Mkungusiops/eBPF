package api

import _ "embed"

// This file used to embed five standalone HTML consoles — index, login, choke,
// fleet and devices, 983,910 bytes in total. Every one of them was unreachable:
// the console has been served from the Vite bundle in internal/api/web since
// that migration, /login included (see handleLoginPage in web_assets.go), and
// the only consumer of the legacy login page was Auth.HandleLoginPage, which
// nothing ever called. They were compiled into every engine binary regardless.
//
// They are not kept "just in case". Four parallel copies of a console that no
// request can reach do not fail loudly when they drift — they get maintained by
// mistake, which is exactly what happened: a favicon fix earlier in this line of
// work carefully updated icon links in all five, to no effect whatsoever.

//go:embed favicon.svg
var faviconSVG []byte

//go:embed favicon-light.svg
var faviconLightSVG []byte

// The /favicon.ico slot is not decoration. Browsers request it by convention
// even when a <link> names an SVG, and several surfaces — vertical tab strips,
// bookmark and history lists — prefer it. This route used to answer with the
// SVG bytes under image/svg+xml, so anything trusting the extension got an
// icon it could not use.
//
//go:embed favicon.ico
var faviconICO []byte
