package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// communityID names the community github.com/aauth-dev/aauth-go target.
const communityID = "aauth-go-community"

// The community module (v0.3.0) implements the core protocol and
// Signature-Key only. Roles for the drafts it does not implement are
// declared unavailable; clauses its API leaves unobservable stay unclaimed.
func init() {
	for role, reason := range map[string]string{
		conformance.EventsSubscriptionRole:      "the module implements no AAuth Events",
		conformance.EventsProviderRole:          "the module implements no AAuth Events",
		conformance.EventsAgentRole:             "the module implements no AAuth Events",
		conformance.EventsDeliveryRole:          "the module implements no AAuth Events",
		conformance.R3ResourceRole:              "the module implements no R3 (its roadmap lists it as planned)",
		conformance.R3IssuerRole:                "the module implements no R3 (its roadmap lists it as planned)",
		conformance.R3FederatedIssuerRole:       "the module implements no R3 (its roadmap lists it as planned)",
		conformance.SupervisionServerRole:       "the module implements no AAuth Supervision",
		conformance.SupervisionPersonServerRole: "the module implements no AAuth Supervision",
		// The profile's host control advances PS-to-AS polling once per
		// reference; the module's PS polls its AS on each Agent poll and has
		// no such entry point, and its AS never answers 402 itself.
		conformance.SubagentRole: "the module's PS polls the Access Server on each Agent poll and offers no host-advanced poll, which this profile's deferred child outcomes require",
		conformance.DeferredRole: "the module's PS polls the Access Server on each Agent poll and offers no host-advanced poll, and its Access Server never answers 402 itself; this profile's settlement and approval controls have no entry point",
	} {
		if unavailableRoles[role] == nil {
			unavailableRoles[role] = map[string]string{}
		}
		unavailableRoles[role][communityID] = reason
	}
	// The module implements no Budgets draft: its federated bundle offers
	// none of the budget rows inside the four-party role.
	communityUnoffered(conformance.FederatedRole, "budget.four-party-grant", "budget.four-party-omission",
		"budget.hard-cap", "budget.header", "budget.trailer", "budget.usage", "budget.usage-request", "budget.consumption")
	// SignRequest takes created from the wall clock and has no clock input,
	// so the fixed-clock equality cannot be observed for this signer.
	communityUnoffered(conformance.AgentRole, "core.agent-created")
	// The module derives each directed subject itself (personserver
	// DirectedSubject, an HMAC over resource and person); a host cannot bind
	// the fixture's configured subject, which this adapter contract names.
	communityUnoffered(conformance.PersonServerRole, "ps.host-person-profile")
}

func communityUnoffered(role string, clauses ...string) {
	if unofferedClaims[role] == nil {
		unofferedClaims[role] = map[string][]string{}
	}
	unofferedClaims[role][communityID] = append(unofferedClaims[role][communityID], clauses...)
}
