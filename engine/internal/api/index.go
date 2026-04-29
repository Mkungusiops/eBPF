package api

import _ "embed"

//go:embed index.html
var indexHTML string

//go:embed login.html
var loginHTML string

//go:embed favicon.svg
var faviconSVG []byte

//go:embed favicon-light.svg
var faviconLightSVG []byte
