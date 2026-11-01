package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// Both Supervision roles share one Go launcher source and one Rust feature,
// which links the supervision server crate.
func init() {
	for _, role := range []string{conformance.SupervisionServerRole, conformance.SupervisionPersonServerRole} {
		goRoleSources[role] = []string{"supervision.go"}
		rustRoleFeatures[role] = "supervision"
		rustRoleCrates[role] = []string{"aauth-rust-supervision-server"}
	}
}
