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
	// agentprovider.EventInboxStore and EventInboxReader assign the
	// subscription's Resource and Agent comparisons, the use count and the
	// retained delivery bytes to the host store.
	unofferedClaims[conformance.EventsProviderRole] = map[string][]string{"aauth-go": {"events.ap.resource-match", "events.ap.audience", "events.ap.max-uses", "events.ap.remaining-uses", "events.ap.unchanged"}}
	// resource.ProtectedSubscriptionStore consumes a ticket when it commits.
	unofferedClaims[conformance.EventsSubscriptionRole] = map[string][]string{"aauth-go": {"events.sub.ticket-single-use"}}
}
