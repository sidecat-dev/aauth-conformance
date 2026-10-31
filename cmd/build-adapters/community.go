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
}

func communityUnoffered(role string, clauses ...string) {
	if unofferedClaims[role] == nil {
		unofferedClaims[role] = map[string][]string{}
	}
	unofferedClaims[role][communityID] = append(unofferedClaims[role][communityID], clauses...)
}
