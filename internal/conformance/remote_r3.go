package conformance

import (
	"context"
	"encoding/json"
)

// Remote drivers for the R3 roles. The suite keeps playing every party but
// the one under test: for r3.resource the Agent, the Person Server and the
// Access Server that mint the Person and Auth tokens, and a further trusted
// server no document entitles; for the two issuer roles the Agent and the
// Resource, whose R3 documents the harness serves at the suite Resource's
// origin and whose fetches it captures.
func init() {
	registerRemote(R3ResourceRole, remoteDriver{
		requires: []string{partyResource},
		discover: map[string]remoteDocument{
			partyResource:   {"aauth-resource.json", true},
			partyThreeParty: {"aauth-resource.json", true},
		},
		parties: r3Parties,
		gap: func(s Scenario, r RemoteRole) string {
			var in R3ResourceInput
			DecodeInput(s, &in)
			if in.Topology == "three-party" && r.ThreePartyResource == "" {
				return "needs a three-party R3 Resource, and the deployment names no three_party_resource"
			}
			return ""
		},
		fixture: r3ResourceFixture,
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			r, _ := r3Fixture(f)
			var in R3ResourceInput
			DecodeInput(s, &in)
			c := runR3ResourceCase(ctx, f, r, s, in, t, "", o, nil)
			if remote := remoteFrom(ctx); remote != nil && remote.Role.Control == "" {
				markUnobserved(&c, s, []string{"executions"}, controlGap(remote.Role, "/__fixture/r3/executions"))
			}
			return c
		},
	})
	registerRemote(R3IssuerRole, remoteDriver{
		requires: []string{partyPerson},
		discover: map[string]remoteDocument{partyPerson: {"aauth-person.json", true}},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			r, _ := r3Fixture(f)
			var in R3IssuerInput
			DecodeInput(s, &in)
			documents := &r3DocumentServer{}
			defer remoteFrom(ctx).Harness.Handle(f.Origin+"/r3/", documents)()
			return runR3IssuerCase(ctx, f, r, s, in, t, "", o, documents, nil)
		},
	})
	registerRemote(R3FederatedIssuerRole, remoteDriver{
		requires: []string{partyPerson, partyAccess},
		discover: map[string]remoteDocument{partyPerson: {"aauth-person.json", true}, partyAccess: {"aauth-access.json", true}},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			r, _ := r3Fixture(f)
			var in R3FederatedInput
			DecodeInput(s, &in)
			documents := &r3SignerDocuments{}
			defer remoteFrom(ctx).Harness.Handle(f.Origin+"/r3/", documents)()
			return runR3FederatedCase(ctx, f, r, s, in, t, "", o, documents, nil)
		},
	})
}

// r3Parties are the suite parties a deployed R3 Resource discovers beyond
// the fixture's Person Server: the Access Server that mints four-party Auth
// tokens and fetches documents, and the further trusted server.
func r3Parties(f Fixture) []harnessParty {
	r, err := r3Fixture(f)
	if err != nil {
		return nil
	}
	return []harnessParty{
		party(f.Access.Issuer, "aauth-access.json", f.Access.Seed, f.Access.Kid),
		party(r.Other.Issuer, "aauth-access.json", r.Other.Seed, r.Other.Kid),
	}
}

// r3ResourceFixture rebases the fixture onto the deployed Resource of the
// scenario's topology: resource for four-party, three_party_resource for
// three-party. The suite's Person Server and Access Server stay.
func r3ResourceFixture(base Fixture, s Scenario, remote *RemoteRun) Fixture {
	var in R3ResourceInput
	DecodeInput(s, &in)
	role, party := remote.Role, partyResource
	if in.Topology == "three-party" {
		role.Resource, party = role.ThreePartyResource, partyThreeParty
	}
	role.PersonServer, role.AccessServer = "", ""
	return role.fixture(base, s, map[string]keySet{partyResource: remote.Servers[party].Keys}, personEndpoints{}, remote.Skew)
}

// r3AuthorizationEndpoint returns the authorization_endpoint a deployed
// Resource's metadata names on its own origin, or "".
func r3AuthorizationEndpoint(metadata Response, origin string) string {
	var document map[string]any
	if metadata.Status != 200 || json.Unmarshal(metadata.Body, &document) != nil {
		return ""
	}
	endpoint, _ := document["authorization_endpoint"].(string)
	if !endpointURL(endpoint) || resourceIdentifier(endpoint) != origin {
		return ""
	}
	return endpoint
}

// verifyKid checks a signature by the key kid names, under that key's own
// algorithm.
func (k keySet) verifyKid(kid string, message, signature []byte) bool {
	alg, _ := k[kid]["alg"].(string)
	return alg != "" && k.verify(kid, alg, message, signature)
}
