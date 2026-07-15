// Package identity authenticates human operators via OIDC (Keycloak) and maps
// their token claims onto an authz.Principal. It is the "humans only" identity
// path (architecture.md §3.6): agents authenticate by mTLS (internal/mtls);
// operators authenticate here.
//
// Keycloak is the OIDC provider/broker (docs/plan/d4c-tech-decisions.md §3.5),
// but this package is deliberately IdP-agnostic in shape: it verifies a
// standard OIDC token (discovery + JWKS + signature/issuer/expiry) and reads
// standard-ish claims. internal/authz remains the RBAC authority — this package
// only proves WHO the caller is and hands authz the role grants.
package identity

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// Claims are the token fields the platform consumes. `tenant` is a custom claim
// (a Keycloak user-attribute protocol mapper); roles come from
// realm_access.roles. Unknown realm roles map to authz roles with no capability,
// so they are harmlessly ignored.
type Claims struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Tenant            string `json:"tenant"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// Verifier validates OIDC tokens and extracts claims. Thin wrapper over go-oidc.
type Verifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewVerifier runs OIDC discovery against issuerURL (e.g.
// https://kc.example/realms/ebpf-soc) and builds a token verifier. Audience
// varies between ID and access tokens across IdPs, so audience checking is
// skipped; issuer, signature, and expiry are always enforced.
func NewVerifier(ctx context.Context, issuerURL string) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	return &Verifier{verifier: provider.Verifier(&oidc.Config{SkipClientIDCheck: true})}, nil
}

// Verify checks the raw token's signature/issuer/expiry and returns its claims.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := tok.Claims(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// PrincipalFromClaims maps verified claims onto an authz.Principal. Each realm
// role becomes a grant bound to the user's tenant; authz ignores the tenant for
// cross-tenant roles, so an MSOC operator is not accidentally confined. Roles
// the platform does not recognise carry no capability in authz and are inert.
func PrincipalFromClaims(c *Claims) authz.Principal {
	subject := c.Subject
	if c.PreferredUsername != "" {
		subject = c.PreferredUsername
	}
	grants := make([]authz.Grant, 0, len(c.RealmAccess.Roles))
	for _, r := range c.RealmAccess.Roles {
		grants = append(grants, authz.Grant{Role: authz.Role(r), TenantID: c.Tenant})
	}
	return authz.Principal{Subject: subject, Grants: grants}
}
