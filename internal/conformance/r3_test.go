package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

// Catches an R3 scenario whose stage, fetch mode or kind the runner would
// silently never observe.
func TestR3ScenariosLoadOnlyObservableStages(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	var resource, issuer Scenario
	for _, s := range suite.Scenarios {
		switch s.ID {
		case "r3-resource-class":
			resource = s
		case "r3-issuer-class":
			issuer = s
		}
	}
	if resource.ID == "" || issuer.ID == "" {
		t.Fatal("R3 scenarios missing from the suite")
	}
	for _, mutate := range []func(*Scenario){
		func(s *Scenario) { s.Assertions[0].Stage = "fetch-access-3" },
		func(s *Scenario) {
			s.Input = json.RawMessage(strings.Replace(string(s.Input), `"person"`, `"anonymous"`, 1))
		},
		func(s *Scenario) { s.Assertions[1].Stage = "metadata" },
		func(s *Scenario) { s.Assertions[1].Equals = json.RawMessage(`"yes"`) },
		func(s *Scenario) { s.Input = json.RawMessage(`{"topology":"two-party","operations":["records.read"]}`) },
		func(s *Scenario) {
			s.Input = json.RawMessage(`{"topology":"four-party","operations":["records.read"],"calls":["records.read"]}`)
			s.Assertions = s.Assertions[:1]
		},
		func(s *Scenario) {
			s.Input = json.RawMessage(`{"topology":"three-party","operations":["records.delete"],"per_call":["records.delete"],"calls":["records.delete"],"per_call_flow":"complete"}`)
			s.Assertions = s.Assertions[:1]
		},
		func(s *Scenario) {
			s.Input = json.RawMessage(`{"topology":"four-party","operations":["records.delete"],"grant":["records.read"],"calls":["records.read"],"per_call_flow":"complete"}`)
			s.Assertions = s.Assertions[:1]
		},
	} {
		changed := resource
		changed.Assertions = append([]Assertion(nil), resource.Assertions...)
		mutate(&changed)
		if err := validateR3ResourceScenario(suite.Fixture, changed); err == nil {
			t.Fatalf("invalid Resource scenario accepted: %s", changed.Input)
		}
	}
	changed := issuer
	changed.Assertions = append([]Assertion(nil), issuer.Assertions...)
	changed.Assertions[0].Kind = "status"
	if err := validateR3IssuerScenario(suite.Fixture, changed); err == nil {
		t.Fatal("a generic assertion on the request-only fetch stage was accepted")
	}
	noExtension := suite.Fixture
	noExtension.Extensions = nil
	if err := validateR3IssuerScenario(noExtension, issuer); err == nil {
		t.Fatal("R3 scenario accepted without extensions.r3")
	}
}

// Catches a document oracle that accepts re-serialized bytes, an unadvertised
// vocabulary or a document missing a requested operation.
func TestR3DocumentOracleHashesServedBytes(t *testing.T) {
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.export"}]}`)
	digest := r3Digest(exact)
	advertised := map[string]any{"urn:aauth:vocabulary:mcp": "https://resource.conformance.test/mcp"}
	requested := r3Operations("urn:aauth:vocabulary:mcp", []string{"records.read", "records.export"})
	good := observeR3Document(Response{Status: 200, Body: exact}, digest, advertised, "urn:aauth:vocabulary:mcp", requested)
	if !good.Matches || !good.Fields || !good.Covers {
		t.Fatalf("%+v", good)
	}
	reserialized := []byte(`{"operations":[{"tool":"records.read"},{"tool":"records.export"}],"vocabulary":"urn:aauth:vocabulary:mcp"}`)
	if observeR3Document(Response{Status: 200, Body: reserialized}, digest, advertised, "urn:aauth:vocabulary:mcp", requested).Matches {
		t.Fatal("re-serialized bytes matched r3_s256")
	}
	if observeR3Document(Response{Status: 200, Body: exact}, digest, map[string]any{}, "urn:aauth:vocabulary:mcp", requested).Fields {
		t.Fatal("unadvertised vocabulary accepted")
	}
	narrow := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)
	if observeR3Document(Response{Status: 200, Body: narrow}, r3Digest(narrow), advertised, "urn:aauth:vocabulary:mcp", requested).Covers {
		t.Fatal("document without a requested operation covered the request")
	}
	if observeR3Document(Response{Status: 404, Body: exact}, digest, advertised, "urn:aauth:vocabulary:mcp", requested).Matches {
		t.Fatal("a refusal carrying the document bytes counted as serving it")
	}
	if _, ok := r3Vocabularies(Response{Status: 200, Body: []byte(`{"r3_vocabularies":{"mcp":"https://x"}}`)}, "urn:aauth:vocabulary:mcp"); ok {
		t.Fatal("a vocabulary key that is not a URI was accepted")
	}
	if _, ok := r3Vocabularies(Response{Status: 200, Body: []byte(`{"r3_vocabularies":{"urn:aauth:vocabulary:mcp":"https://x","urn:aauth:vocabulary:soap":"https://y"}}`)}, "urn:aauth:vocabulary:mcp"); ok {
		t.Fatal("an undefined standard-namespace vocabulary was accepted")
	}
}

// Catches token oracles that accept a missing R3 claim, a different reference
// or a grant wider than the document.
func TestR3TokenOraclesCheckReferenceAndGrant(t *testing.T) {
	f := r3TestFixture(t)
	p := *f.Person
	resource := func(claims map[string]any) Response {
		compact, _ := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", claims)
		body, _ := json.Marshal(map[string]string{"resource_token": compact})
		return Response{Status: 200, Body: body}
	}
	digest := r3Digest([]byte("{}"))
	claims := map[string]any{"iss": f.Origin, "aud": f.Access.Issuer, "r3_uri": f.Origin + "/r3/c.x", "r3_s256": digest}
	if !observeR3ResourceToken(f, resource(claims), f.Access.Issuer).Valid {
		t.Fatal("valid Resource token refused")
	}
	if observeR3ResourceToken(f, resource(claims), p.Issuer).Valid {
		t.Fatal("wrong topology audience accepted")
	}
	delete(claims, "r3_s256")
	if observeR3ResourceToken(f, resource(claims), f.Access.Issuer).Valid {
		t.Fatal("Resource token without r3_s256 accepted")
	}
	document := r3Operations("urn:aauth:vocabulary:mcp", []string{"records.read"})
	auth := func(grant []string, uri string) Response {
		compact, _ := mintJWT(p.Seed, p.Kid, "aa-auth+jwt", map[string]any{
			"iss": p.Issuer, "ps": p.Issuer, "aud": f.Origin, "r3_uri": uri, "r3_s256": digest,
			"r3_granted": map[string]any{"vocabulary": "urn:aauth:vocabulary:mcp", "operations": r3Operations("urn:aauth:vocabulary:mcp", grant)},
		})
		body, _ := json.Marshal(map[string]string{"auth_token": compact})
		return Response{Status: 200, Body: body}
	}
	uri := f.Origin + "/r3/c.x"
	if !observeR3AuthToken(f, auth([]string{"records.read"}, uri), uri, digest, document, "urn:aauth:vocabulary:mcp").Valid {
		t.Fatal("valid Auth token refused")
	}
	if observeR3AuthToken(f, auth([]string{"records.read", "records.purge"}, uri), uri, digest, document, "urn:aauth:vocabulary:mcp").Valid {
		t.Fatal("grant wider than the document accepted")
	}
	if observeR3AuthToken(f, auth([]string{"records.read"}, f.Origin+"/r3/c.y"), uri, digest, document, "urn:aauth:vocabulary:mcp").Valid {
		t.Fatal("another document's reference accepted")
	}
	if noR3Token(auth([]string{"records.read"}, uri), "auth_token") || !noR3Token(Response{Body: []byte("not json")}, "auth_token") {
		t.Fatal("no-token oracle disagrees with the body")
	}
}

func r3TestFixture(t *testing.T) Fixture {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	return suite.Fixture
}
