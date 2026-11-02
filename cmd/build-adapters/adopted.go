package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// aauth-rust implements these out-of-slice clauses through its public API:
// PersonIdentityResource answers requirement=person-token, Agent::person_request
// and Agent::verify_person_delivery obtain the Person token an agent retries
// with, Jwk::rfc7638_thumbprint takes a key without alg, and its token and
// signature verifiers settle the four unsettled vector readings
// (INTERPRETATIONS.md in aauth-rust).
func init() {
	adoptedClaims[conformance.ResourceRole] = map[string][]string{
		"aauth-rust": {"core.person-token-required"},
	}
	adoptedClaims[conformance.AgentRole] = map[string][]string{
		"aauth-rust": {"agent.person-flow"},
	}
	adoptedClaims[conformance.VectorsRole] = map[string][]string{
		"aauth-rust": {"vector.jwk-thumbprint.no-alg", "vector.jwt.aud-array", "vector.jwt.iat-absent", "vector.jwt.person-scope", "vector.http-sig.body-digest"},
	}
}
