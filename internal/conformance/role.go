package conformance

import "fmt"

const ResourceRole = "resource.agent-identity"
const AgentRole = "agent.signing"
const FederatedRole = "authorization.federated"
const PersonServerRole = "person-server.direct"

func targetRole(role string) string {
	if role == "" {
		return ResourceRole
	}
	return role
}
func clauseRole(c Clause) string { return targetRole(c.Role) }
func (s Suite) ForRole(role string) (Suite, error) {
	role = targetRole(role)
	if role != ResourceRole && role != AgentRole && role != PersonServerRole && role != FederatedRole {
		return Suite{}, fmt.Errorf("unsupported role %q", role)
	}
	selected := s
	selected.Scenarios = nil
	selected.Catalog.Clauses = nil
	for _, scenario := range s.Scenarios {
		if scenario.Role == role {
			selected.Scenarios = append(selected.Scenarios, scenario)
		}
	}
	for _, clause := range s.Catalog.Clauses {
		if clauseRole(clause) == role {
			selected.Catalog.Clauses = append(selected.Catalog.Clauses, clause)
		}
	}
	if len(selected.Scenarios) == 0 {
		return Suite{}, fmt.Errorf("no scenarios for role %s", role)
	}
	return selected, nil
}
func Claims(s Suite, role string) []string {
	result := []string{}
	for _, c := range s.Catalog.Clauses {
		if clauseRole(c) == targetRole(role) && c.Scope != "out-of-slice" {
			result = append(result, c.ID)
		}
	}
	return result
}
