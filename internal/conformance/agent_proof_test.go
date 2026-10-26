package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Independently stated query/header base catches an oracle that omits fields.
func TestAgentOracleVerifiesActualWireComponents(t *testing.T) {
	f := fixture()
	token, err := MintToken(f, TokenSpec{IATOffset: -10, EXPOffset: 300}, "agent-oracle")
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{"Signature-Key": []string{`out=jwt;jwt="` + token + `"`}, "Authorization": []string{"AAuth fixture-session"}}
	params := `("@method" "@authority" "@path" "@query" "authorization" "signature-key");created=1800000000`
	base := `"@method": GET` + "\n" + `"@authority": resource.conformance.test` + "\n" + `"@path": /whoami` + "\n" + `"@query": ?view=full%2Fdetail` + "\n" + `"authorization": AAuth fixture-session` + "\n" + `"signature-key": ` + header.Get("Signature-Key") + "\n" + `"@signature-params": ` + params
	header.Set("Signature-Input", "out="+params)
	header.Set("Signature", "out=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(f.AgentSeed), []byte(base)))+":")
	capture := Captured{Method: "GET", URL: f.Origin + "/whoami?view=full%2Fdetail", Headers: header}
	observed := ObserveAgent(f, capture)
	if !observed.ValidProof || !observed.ValidToken || observed.Created != 1800000000 || observed.Base != base {
		t.Fatalf("%+v", observed)
	}
	job := AgentJob{Method: "GET", URL: capture.URL, Headers: map[string]string{"Authorization": "AAuth fixture-session"}, Token: token}
	a := Assertion{Kind: "wire-preserved", Equals: json.RawMessage(`true`)}
	if CheckAgent(a, observed, capture, job).State != "pass" {
		t.Fatal("valid input refused")
	}
	for _, mutate := range []func(*Captured){
		func(c *Captured) { c.URL = f.Origin + "/different?view=full%2Fdetail" },
		func(c *Captured) { c.Headers.Set("Authorization", "AAuth changed") },
		func(c *Captured) { c.Headers.Set("Signature", `out=:AAAA:`) },
		func(c *Captured) { c.Headers.Set("Signature-Key", `out=jwt;jwt="changed"`) },
	} {
		bad := capture
		bad.Headers = capture.Headers.Clone()
		mutate(&bad)
		if ObserveAgent(f, bad).ValidProof {
			t.Fatal("altered wire request verified")
		}
	}
	// A valid signature on a different request is still the wrong operation.
	job.URL = f.Origin + "/different"
	if CheckAgent(a, observed, capture, job).State != "fail" {
		t.Fatal("wrong operation passed")
	}
	a = Assertion{Kind: "wire-covers", Equals: json.RawMessage(`["@query","missing"]`)}
	if CheckAgent(a, observed, capture, job).State != "fail" {
		t.Fatal("missing coverage passed")
	}
	if strings.Contains(base, "\r") {
		t.Fatal("base contains transport line endings")
	}
}

func TestAgentAndResourceRolesSelectSeparateClaimsAndCases(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := suite.ForRole(AgentRole)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := suite.ForRole(ResourceRole)
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.Scenarios) != 3 || len(resource.Scenarios) != 6 {
		t.Fatal("role mixing")
	}
	for _, c := range agent.Catalog.Clauses {
		if clauseRole(c) != AgentRole {
			t.Fatal("mixed claims")
		}
	}
	if _, err := suite.ForRole("unknown"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestAgentInputPreservesAbsentAuthorization(t *testing.T) {
	capture := Captured{Method: "GET", URL: "https://resource.conformance.test/whoami", Headers: http.Header{"Authorization": []string{"AAuth invented"}}}
	job := AgentJob{Method: capture.Method, URL: capture.URL, Headers: map[string]string{}, Token: "fixture"}
	result := CheckAgent(Assertion{Kind: "wire-preserved", Equals: json.RawMessage(`true`)}, Observation{Token: "fixture"}, capture, job)
	if result.State != "fail" {
		t.Fatal("an invented Authorization header changed the requested call")
	}
}
