package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The mission roles share one Go launcher source; the Rust feature links the
// four-party bundle and the Signature-Key crate for the PS's approval proof.
func init() {
	for _, role := range []string{conformance.MissionServerRole, conformance.MissionResourceRole} {
		goRoleSources[role] = []string{"mission.go"}
		rustRoleFeatures[role] = "mission"
		rustRoleCrates[role] = []string{"aauth-rust-access-server", "aauth-rust-signature-key"}
	}
}
