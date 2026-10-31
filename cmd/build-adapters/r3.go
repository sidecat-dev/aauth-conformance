package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The R3 roles share one Go launcher source and one Rust feature.
func init() {
	for _, role := range []string{conformance.R3ResourceRole, conformance.R3IssuerRole, conformance.R3FederatedIssuerRole} {
		goRoleSources[role] = []string{"r3.go"}
	}
	for _, role := range []string{conformance.R3ResourceRole, conformance.R3IssuerRole} {
		rustRoleFeatures[role] = "r3"
		rustRoleCrates[role] = []string{"aauth-rust-r3"}
	}
	unavailableRoles[conformance.R3FederatedIssuerRole] = map[string]string{"aauth-rust": "aauth-rust-access-server offers no R3 issuance; its crate documentation says full R3 is outside its profile and refused"}
}
