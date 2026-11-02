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
// aauth-rust has no launcher yet and is reported not offered, with the reason.
func init() {
	reasons := map[string]string{
		"aauth-rust": "aauth-rust implements no Bootstrap enrollment or refresh; its CONFORMANCE.md says Bootstrap behavior is absent",
	}
	for _, role := range []string{conformance.BootstrapProviderRole, conformance.BootstrapAgentRole, conformance.BootstrapSelfHostedRole} {
		goRoleSources[role] = []string{"bootstrap.go"}
		if unavailableRoles[role] == nil {
			unavailableRoles[role] = map[string]string{}
		}
		for library, reason := range reasons {
			unavailableRoles[role][library] = reason
		}
	}
	if adoptedClaims[conformance.BootstrapProviderRole] == nil {
		adoptedClaims[conformance.BootstrapProviderRole] = map[string][]string{}
	}
	adoptedClaims[conformance.BootstrapProviderRole]["aauth-go"] = []string{"bootstrap.ap.single-key"}
}
