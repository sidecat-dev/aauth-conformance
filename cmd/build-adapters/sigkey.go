package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// Both Signature-Key roles share one Go launcher source and one Rust feature,
// which links the Signature-Key crate for the further-scheme verifiers and the
// signer.
func init() {
	for _, role := range []string{conformance.SigkeyVerifierRole, conformance.SigkeySignerRole} {
		goRoleSources[role] = []string{"sigkey.go"}
		rustRoleFeatures[role] = "sigkey"
		rustRoleCrates[role] = []string{"aauth-rust-signature-key"}
	}
}

// Schemes and algorithms an implementation does not offer stay unclaimed, and
// their scenarios are not run for it.
func init() {
	unofferedClaims[conformance.SigkeyVerifierRole] = map[string][]string{
		// resource.FurtherSchemesConfig takes hwk, jkt-jwt, jwks_uri, jwks, x509
		// and cached; signaturekey.VerifySelfJWT is not reachable from a Resource.
		"aauth-go": {"sigkey.v.self-jwt"},
		// The module verifies jwt (VerifyAndExtractAgent) and jwks_uri
		// (VerifyServerRequest) at a Resource; hwk and jkt-jwt are verified only
		// inside its Agent Provider, and jwks and self-jwt not at all.
		"aauth-go-community": {"sigkey.v.hwk-ed25519", "sigkey.v.hwk-es256", "sigkey.v.hwk-es384", "sigkey.v.hwk-rs256", "sigkey.v.hwk-ps256", "sigkey.v.uncovered-hwk", "sigkey.v.missing-member-hwk", "sigkey.v.hwk-kid", "sigkey.v.hwk-eddsa", "sigkey.v.hwk-kty-mismatch", "sigkey.v.hwk-crv-mismatch", "sigkey.v.hwk-symmetric", "sigkey.v.jwks", "sigkey.v.self-jwt", "sigkey.v.jkt-jwt"},
	}
	unofferedClaims[conformance.SigkeySignerRole] = map[string][]string{
		// The module signs hwk with Ed25519 or ES256 keys, and jwt, jwks_uri and
		// jkt-jwt; it has no jwks or self-jwt signer and takes no clock.
		"aauth-go-community": {"sigkey.s.hwk-es384", "sigkey.s.hwk-rs256", "sigkey.s.hwk-ps256", "sigkey.s.jwks", "sigkey.s.self-jwt", "sigkey.s.created"},
	}
}
