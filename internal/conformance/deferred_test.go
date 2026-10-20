package conformance

import (
	"net/http"
	"strings"
	"testing"
)

func TestDeferredProfileAndPendingOracle(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := suite.ForRole("authorization.deferred")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Scenarios) != 5 {
		t.Fatalf("deferred scenarios = %d", len(selected.Scenarios))
	}
	endpoint := suite.Fixture.Access.Issuer + "/token"
	valid := Response{Status: 202, Header: http.Header{"Location": {endpoint + "/pending/opaque"}, "Retry-After": {"0"}, "Cache-Control": {"no-store"}, "Content-Type": {"application/json"}}, Body: []byte(`{"status":"pending"}`)}
	if !validDeferredPending(valid, endpoint, "") {
		t.Fatal("valid pending response refused")
	}
	for _, mutation := range []func(*Response){
		func(r *Response) { r.Header.Set("Location", "https://foreign.example/pending") },
		func(r *Response) { r.Header.Del("Retry-After") },
		func(r *Response) { r.Header.Set("Retry-After", "-1") },
		func(r *Response) { r.Header.Del("Cache-Control") },
		func(r *Response) { r.Body = []byte(`{}`) },
		func(r *Response) { r.Body = []byte(`{"status":42}`) },
	} {
		changed := valid
		changed.Header = valid.Header.Clone()
		mutation(&changed)
		if validDeferredPending(changed, endpoint, "") {
			t.Fatal("malformed pending response accepted")
		}
	}
	if validDeferredPending(valid, endpoint, endpoint+"/different") {
		t.Fatal("changed pending URL accepted")
	}
}
func TestDeferredPSPollProofOracle(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	location := f.Access.Issuer + "/token/pending/random"
	req, _, err := signedFixtureRequest(f, f.Person.Seed, "GET", location, `sig=jwks_uri;id="`+f.Person.Issuer+`";dwk="aauth-person.json";kid="`+f.Person.Kid+`"`, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := Captured{Method: "GET", URL: location, Headers: req.Header.Clone()}
	if !observePSPollProof(f, c, location).ValidProof {
		t.Fatal("valid PS GET proof refused")
	}
	c.Body = []byte("added")
	if observePSPollProof(f, c, location).ValidProof {
		t.Fatal("poll with body accepted")
	}
	c.Body = nil
	c.URL = location + "-other"
	if observePSPollProof(f, c, location).ValidProof {
		t.Fatal("wrong pending path accepted")
	}
}

func TestDeferredAssertionsRequireObservedKindAndStage(t *testing.T) {
	for _, pair := range []struct{ kind, stage string }{
		{"deferred-proof", "token"}, {"deferred-proof", "pending"},
		{"deferred-forwarded", "waiting"}, {"deferred-stable", "token"},
		{"deferred-pending", "result"},
	} {
		if validDeferredAssertion(Assertion{Kind: pair.kind, Stage: pair.stage, Equals: []byte("false")}) {
			t.Errorf("accepted unobserved %s at %s", pair.kind, pair.stage)
		}
	}
}

func TestDeferredReportNamesItsRole(t *testing.T) {
	var output strings.Builder
	if err := (Report{Role: DeferredRole}).Markdown(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "# Deferred four-party authorization report\n") {
		t.Fatal("report names the wrong role")
	}
}
