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
}
