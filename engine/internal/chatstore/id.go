package chatstore

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// newID is a random, unguessable chat/message id.
//
// Random, not sequential: chat ids appear in URLs and request bodies, and a
// sequential id lets a caller probe for the existence of other conversations by
// counting — a cross-tenant existence oracle of exactly the kind ErrNotFound is
// written to avoid.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}
