package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The vectors role has one Go launcher source and one Rust feature, which
// links the Signature-Key crate for its request and Signature-Error parsers.
func init() {
	goRoleSources[conformance.VectorsRole] = []string{"vectors.go"}
	rustRoleFeatures[conformance.VectorsRole] = "vectors"
	rustRoleCrates[conformance.VectorsRole] = []string{"aauth-rust-signature-key"}
}
