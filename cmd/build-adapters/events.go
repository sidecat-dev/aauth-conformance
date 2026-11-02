package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The Events roles share one Go launcher source and one Rust feature; the
// Rust launcher also links the Agent Provider crate for the inbox.
func init() {
	for _, role := range []string{conformance.EventsSubscriptionRole, conformance.EventsProviderRole, conformance.EventsAgentRole, conformance.EventsDeliveryRole} {
		goRoleSources[role] = []string{"events.go"}
		rustRoleFeatures[role] = "events"
		rustRoleCrates[role] = []string{"aauth-rust-agent-provider"}
	}
}
