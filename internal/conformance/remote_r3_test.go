package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// Catches a three-party R3 scenario run against the four-party Resource, a
// rebase that hands the suite's Person Server or Access Server to the
// deployment, or a missing control reported as anything but its gap.
func TestR3RemoteResourceTopologyAndGaps(t *testing.T) {
	suite := loadSuite(t)
	selected, _ := suite.ForRole(R3ResourceRole)
	r := RemoteRole{Resource: "https://r3.example/authorize"}
	driver := remoteDrivers[R3ResourceRole]
	gapped := []string{}
	for _, s := range selected.Scenarios {
		if reason := driver.gap(s, r); reason != "" {
			gapped = append(gapped, s.ID)
			if !strings.Contains(reason, "three_party_resource") {
				t.Fatalf("%s: %s", s.ID, reason)
			}
		}
	}
	if !slices.Equal(gapped, []string{"r3-resource-three-party"}) {
		t.Fatalf("gapped %v", gapped)
	}
	r.ThreePartyResource = "https://r3-direct.example/authorize"
	remote := &RemoteRun{Role: r, Skew: 4, Servers: map[string]RemoteServer{
		partyResource: {Keys: keySet{"four": nil}}, partyThreeParty: {Keys: keySet{"three": nil}},
	}}
	for _, s := range selected.Scenarios {
		if driver.gap(s, r) != "" {
			t.Fatalf("%s gapped with both Resources named", s.ID)
		}
		f := driver.fixture(suite.Fixture, s, remote)
		want, kid := "https://r3.example", "four"
		if s.ID == "r3-resource-three-party" {
			want, kid = "https://r3-direct.example", "three"
		}
		if _, ok := f.Person.resourceKeys()[kid]; f.Origin != want || !ok || f.Person.Issuer != suite.Fixture.Person.Issuer || f.Access.Issuer != suite.Fixture.Access.Issuer || f.Skew != 4 {
			t.Fatalf("%s: origin %s keys %v ps %s as %s", s.ID, f.Origin, f.Person.ResourcePublished, f.Person.Issuer, f.Access.Issuer)
		}
	}
	names := HarnessNames(suite.Fixture)
	if !slices.Contains(names, "access.conformance.test") || !slices.Contains(names, "other.conformance.test") {
		t.Fatalf("suite does not serve the R3 Resource's Access Server and other server: %v", names)
	}
	metadata := Response{Status: 200, Body: []byte(`{"authorization_endpoint":"https://r3.example/v1/authorize"}`)}
	if r3AuthorizationEndpoint(metadata, "https://r3.example") != "https://r3.example/v1/authorize" || r3AuthorizationEndpoint(metadata, "https://other.example") != "" {
		t.Fatal("authorization endpoint not taken from the Resource's own metadata")
	}
}

// Catches the R3 issuer driver failing to serve the document at the suite
// Resource's origin, to capture the deployed PS's fetch, or to verify the
// fetch proof and tokens under the keys the PS publishes, at its own clock.
func TestRemoteR3IssuerAgainstDeployedPersonServer(t *testing.T) {
	suite := loadSuite(t)
	harness := NewHarness(suite.Fixture)
	seed, kid, issuer := strings.Repeat("0c", 32), "deployed-1", "https://ps.example"
	var network *Network
	ps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().Unix() + 2 // a server clock a little ahead
		switch r.URL.Path {
		case "/.well-known/aauth-person.json":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys",
				"person_token_endpoint": issuer + "/v1/person", "auth_token_endpoint": issuer + "/v1/token"})
		case "/keys":
			key := publicJWK(seed)
			key["kid"] = kid
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
		case "/v1/person":
			token, _ := mintJWT(seed, kid, "aa-person+jwt", map[string]any{"iss": issuer, "sub": "directed-person-1", "jti": "p-1", "iat": now, "exp": now + 60})
			json.NewEncoder(w).Encode(map[string]string{"person_token": token})
		case "/v1/token":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			claims := unverifiedClaims(body["resource_token"])
			uri, _ := claims["r3_uri"].(string)
			at := suite.Fixture
			at.Now = now
			fetch, _, _ := signedFixtureRequest(at, seed, "GET", uri, fmt.Sprintf("sig=jwks_uri;id=%q;dwk=%q;kid=%q", issuer, "aauth-person.json", kid), nil)
			document, err := Exchange(WithNetwork(context.Background(), network), fetch, "", time.Second)
			if err != nil || document.Status != 200 {
				http.Error(w, `{"error":"invalid_request"}`, 400)
				return
			}
			var parsed map[string]any
			json.Unmarshal(document.Body, &parsed)
			token, _ := mintJWT(seed, kid, "aa-auth+jwt", map[string]any{"iss": issuer, "dwk": "aauth-person.json", "ps": issuer, "aud": claims["iss"],
				"sub": "directed-person-1", "jti": "a-1", "iat": now, "exp": now + 60, "r3_uri": uri, "r3_s256": claims["r3_s256"],
				"r3_granted": map[string]any{"vocabulary": parsed["vocabulary"], "operations": parsed["operations"]}})
			io.WriteString(w, `{"auth_token":"`+token+`"}`)
		default:
			http.NotFound(w, r)
		}
	})
	network = testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "ps.example" {
			ps.ServeHTTP(w, r)
			return
		}
		harness.ServeHTTP(w, r)
	}), append(HarnessNames(suite.Fixture), "ps.example")...)
	ctx := WithHarness(WithNetwork(context.Background(), network), harness)
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{R3IssuerRole: {PersonServer: issuer}}}
	reports, err := RunRemote(ctx, suite, d, RemoteOptions{Timeout: 2 * time.Second, Skew: 5})
	if err != nil {
		t.Fatal(err)
	}
	var class *Case
	for i, c := range reports[0].Runs[0].Cases {
		if c.ID == "r3-issuer-class" {
			class = &reports[0].Runs[0].Cases[i]
		}
	}
	if class == nil {
		t.Fatal("no class case")
	}
	for _, result := range class.Results {
		if result.State != "pass" {
			t.Fatalf("%s: %s %s (case error %q)", result.Assertion, result.State, result.Detail, class.Error)
		}
	}
	// The document handler is the case's only: it is gone afterwards.
	request, _ := http.NewRequest("GET", suite.Fixture.Origin+"/r3/c.x", nil)
	if response, err := Exchange(ctx, request, "", time.Second); err != nil || response.Status != http.StatusNotFound {
		t.Fatalf("R3 document handler outlived its case: %v %v", response.Status, err)
	}
}
