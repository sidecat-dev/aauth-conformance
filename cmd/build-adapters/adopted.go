package main

import "gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"

// aauth-rust implements these out-of-slice clauses through its public API:
// PersonIdentityResource answers requirement=person-token, Agent::person_request
// and Agent::verify_person_delivery obtain the Person token an agent retries
// with, Jwk::rfc7638_thumbprint takes a key without alg, and its token and
// signature verifiers settle the four unsettled vector readings
// (INTERPRETATIONS.md in aauth-rust).
//
// aauth-go implements them too: resource.NewPersonIdentity answers
// requirement=person-token, agent.Client.PersonToken obtains the Person token
// from the Person Server its Agent token names and agent.Client.Begin retries
// with it, jose.JWK.RFC7638Thumbprint takes a key without alg, and its token
// and signature verifiers accept a one-element aud array (INTERPRETATIONS.md
// in aauth-go), refuse a token without iat and a person token with scope, and
// check Content-Digest against the body.
func init() {
	adoptedClaims[conformance.ResourceRole] = map[string][]string{
		"aauth-rust": {"core.person-token-required"},
		"aauth-go":   {"core.person-token-required"},
	}
	adoptedClaims[conformance.AgentRole] = map[string][]string{
		"aauth-rust": {"agent.person-flow"},
		"aauth-go":   {"agent.person-flow"},
	}
	vectors := []string{"vector.jwk-thumbprint.no-alg", "vector.jwt.aud-array", "vector.jwt.iat-absent", "vector.jwt.person-scope", "vector.http-sig.body-digest"}
	adoptedClaims[conformance.VectorsRole] = map[string][]string{
		"aauth-rust": vectors,
		"aauth-go":   vectors,
	}
}
