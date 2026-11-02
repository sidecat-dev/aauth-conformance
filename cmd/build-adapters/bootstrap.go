package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// The Bootstrap roles have scenarios and runners but no launcher yet. Both
// libraries are reported not offered, with the reason, until one is written.
func init() {
	reasons := map[string]string{
		"aauth-go":   "no Bootstrap launcher yet: the aauth-go agentprovider enrollment, refresh, sub-agent and self-hosted APIs and agent.BootstrapClient are not wired to this role's adapter contract",
		"aauth-rust": "aauth-rust implements no Bootstrap enrollment or refresh; its CONFORMANCE.md says Bootstrap behavior is absent",
	}
	for _, role := range []string{conformance.BootstrapProviderRole, conformance.BootstrapAgentRole, conformance.BootstrapSelfHostedRole} {
		if unavailableRoles[role] == nil {
			unavailableRoles[role] = map[string]string{}
		}
		for library, reason := range reasons {
			unavailableRoles[role][library] = reason
		}
	}
}
