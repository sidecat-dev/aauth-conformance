package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The R3 roles share one Go launcher source. The Rust issuer roles each have
// a feature; the federated issuer also needs the native Access Server.
func init() {
	for _, role := range []string{conformance.R3ResourceRole, conformance.R3IssuerRole, conformance.R3FederatedIssuerRole} {
		goRoleSources[role] = []string{"r3.go"}
	}
	for _, role := range []string{conformance.R3ResourceRole, conformance.R3IssuerRole} {
		rustRoleFeatures[role] = "r3"
		rustRoleCrates[role] = []string{"aauth-rust-r3"}
	}
	rustRoleFeatures[conformance.R3FederatedIssuerRole] = "r3-federated"
	rustRoleCrates[conformance.R3FederatedIssuerRole] = []string{"aauth-rust-r3", "aauth-rust-access-server"}
}
