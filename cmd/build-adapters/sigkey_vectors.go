package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The Signature-Key vectors role has one Go launcher source and one Rust
// feature, which links the Signature-Key crate for the signer and the
// further-scheme verifiers.
func init() {
	role := conformance.SigvecRole
	goRoleSources[role] = []string{"sigkey_vectors.go"}
	rustRoleFeatures[role] = "sigkey-vectors"
	rustRoleCrates[role] = []string{"aauth-rust-signature-key"}
	generatedRoles[role] = true
	unofferedClaims[role] = map[string][]string{
		// aauth-rust keeps jkt-jwt at Ed25519, for the identity key and the
		// delegated request key (its ACCEPTED_SIGNATURE_ALGS documentation).
		"aauth-rust": {"sigvec.jkt-jwt.es256"},
	}
	if unavailableRoles[role] == nil {
		unavailableRoles[role] = map[string]string{}
	}
	unavailableRoles[role]["aauth-go-community"] = "no launcher for this role: the vectors are generated and cross-checked with aauth-rust and aauth-go"
}
