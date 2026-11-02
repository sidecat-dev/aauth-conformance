package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The Bootstrap roles share one Go launcher source. aauth-go serves them
// natively: agentprovider.EnrollmentService (enrollment, two-key and
// single-key refresh), Server.SubagentHandler, Server.Issue,
// Server.IssueSubagent and SelfHostedAgent for the APs, and
// agent.BootstrapClient with agent.Client for the Agent. Its single-key
// refresh handler implements the optional single-key pattern, so aauth-go
// claims that out-of-slice clause.
//
// The Rust launcher serves all three roles under one feature, which links
// the Agent Provider crate: its bootstrap::BootstrapService (enrollment,
// two-key and single-key refresh, sub-agent issuance) for the hosted AP,
// AgentProvider::issue_to and issue_subagent_to for the self-hosted domain,
// and the Agent crate's BootstrapClient and Agent::subagent_request for the
// enrolling Agent. Its single-key refresh implements the optional
// single-key pattern, so aauth-rust claims that out-of-slice clause too.
//
// On the Agent side both libraries send the single-key refresh natively
// (aauth-go BootstrapClient.RefreshSingleKey, aauth-rust
// BootstrapClient::single_key_refresh_request), so both claim
// bootstrap.agent.single-key.
//
// The refresh margin (core line 1301, Bootstrap line 291) is aauth-rust's
// BootstrapClient::needs_refresh with REFRESH_MARGIN. aauth-go has no
// refresh-margin decision: its BootstrapClient performs one exchange when
// called and "does not discover endpoints, retry, or mutate an authenticated
// Client", and no aauth-go API says when a token is due. A launcher-coded
// margin would grade the launcher, not the library, so aauth-go leaves
// bootstrap.agent.refresh-margin unclaimed until it has that decision.
func init() {
	for _, role := range []string{conformance.BootstrapProviderRole, conformance.BootstrapAgentRole, conformance.BootstrapSelfHostedRole} {
		goRoleSources[role] = []string{"bootstrap.go"}
		rustRoleFeatures[role] = "bootstrap"
		rustRoleCrates[role] = []string{"aauth-rust-agent-provider"}
	}
	if adoptedClaims[conformance.BootstrapProviderRole] == nil {
		adoptedClaims[conformance.BootstrapProviderRole] = map[string][]string{}
	}
	adoptedClaims[conformance.BootstrapProviderRole]["aauth-go"] = []string{"bootstrap.ap.single-key"}
	adoptedClaims[conformance.BootstrapProviderRole]["aauth-rust"] = []string{"bootstrap.ap.single-key"}
	adoptedClaims[conformance.BootstrapAgentRole] = map[string][]string{
		"aauth-go":   {"bootstrap.agent.single-key"},
		"aauth-rust": {"bootstrap.agent.single-key"},
	}
	if unofferedClaims[conformance.BootstrapAgentRole] == nil {
		unofferedClaims[conformance.BootstrapAgentRole] = map[string][]string{}
	}
	unofferedClaims[conformance.BootstrapAgentRole]["aauth-go"] = []string{"bootstrap.agent.refresh-margin"}
}
