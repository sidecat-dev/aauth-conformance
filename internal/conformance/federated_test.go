package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The independent-PS profile must reach the AS even when the implementation has
// no available PS endpoints. This is a runner transport test, not a SUT result.
func TestHarnessPSDoesNotCallNativePersonServer(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	var scenario Scenario
	for _, s := range suite.Scenarios {
		if s.ID == "fixture-ps-as-proof" {
			scenario = s
		}
	}
	if scenario.ID == "" {
		t.Fatal("independent PS scenario missing")
	}
	var personRequests, resourceRequests, accessRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch "https://" + r.Host {
		case f.Person.Issuer:
			personRequests.Add(1)
			http.Error(w, "native PS is deliberately unavailable", 503)
		case f.Origin:
			if resourceRequests.Add(1) == 1 {
				w.Header().Set("AAuth-Requirement", "requirement=person-token")
				w.WriteHeader(401)
				return
			}
			person := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Signature-Key"), `sig=jwt;jwt="`), `"`)
			_, claims, err := verifyJWT(person, f.Person.Seed, f.Person.Kid, "aa-person+jwt")
			if err != nil {
				t.Errorf("harness did not present its signed Person token: %v", err)
				http.Error(w, "bad harness Person token", 400)
				return
			}
			token, err := mintJWT(f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt", map[string]any{
				"iss": f.Origin, "dwk": "aauth-resource.json", "aud": f.Access.Issuer,
				"ps": f.Person.Issuer, "sub": claims["sub"], "presented_jti": claims["jti"],
				"agent_jkt": thumbprint(f.AgentSeed), "scope": "read",
				"jti": "fixture-resource", "iat": f.Now, "exp": f.Now + 300,
			})
			if err != nil {
				t.Error(err)
			}
			w.Header().Set("AAuth-Requirement", `requirement=auth-token;resource-token="`+token+`"`)
			w.WriteHeader(401)
		case f.Access.Issuer:
			accessRequests.Add(1)
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["presented_token"] == "" ||
				body["agent_token"] == "" || body["resource_token"] == "" {
				t.Error("missing exact required AS parameters")
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_request"}`)
		default:
			http.Error(w, "unknown host", 404)
		}
	}))
	defer server.Close()
	var claims []string
	for _, clause := range suite.Catalog.Clauses {
		if clause.Role == FederatedRole {
			claims = append(claims, clause.ID)
		}
	}
	c := runFederatedCase(context.Background(), f, scenario, Target{Claims: claims},
		server.URL, Options{Timeout: time.Second}, &federationRelay{fixture: f}, nil)
	if c.Error != "" || personRequests.Load() != 0 || accessRequests.Load() != 1 {
		t.Fatalf("native PS calls=%d, AS calls=%d, error=%q", personRequests.Load(), accessRequests.Load(), c.Error)
	}
	for _, result := range c.Results {
		if result.State != "pass" {
			t.Errorf("%s: %s", result.Assertion, result.State)
		}
	}
	for _, exchange := range c.Exchanges {
		if exchange.Stage == "person" || exchange.Stage == "token" {
			t.Fatal("harness PS output was recorded as native implementation evidence")
		}
	}
}

func TestFederatedAssertionsRejectIncompatibleStages(t *testing.T) {
	for _, tc := range []struct{ stage, kind string }{
		{"handoff", "ps-jwt"}, {"token", "fed-ps-proof"}, {"access", "fed-forwarded"},
		{"protected", "ps-jwt"}, {"initial", "fed-challenge"}, {"person", "fed-challenge"},
	} {
		t.Run(tc.stage+"/"+tc.kind, func(t *testing.T) {
			s, err := Load("../..")
			if err != nil {
				t.Fatal(err)
			}
			s, err = s.ForRole(FederatedRole)
			if err != nil {
				t.Fatal(err)
			}
			s.Scenarios[0].Assertions = []Assertion{{
				ID: "bad-profile", Clause: "fed.delivery", Stage: tc.stage,
				Kind: tc.kind, Equals: json.RawMessage("true"),
			}}
			if s.validate() == nil {
				t.Fatal("accepted an assertion that the stage cannot evaluate")
			}
		})
	}
}

func TestHarnessPSCannotClaimNativePSBehavior(t *testing.T) {
	for _, stage := range []string{"person", "handoff", "token", "grant-mutation"} {
		t.Run(stage, func(t *testing.T) {
			s, err := Load("../..")
			if err != nil {
				t.Fatal(err)
			}
			s, err = s.ForRole(FederatedRole)
			if err != nil {
				t.Fatal(err)
			}
			s.Scenarios = s.Scenarios[:1]
			s.Scenarios[0].Federated.HarnessPS = true
			if stage == "grant-mutation" {
				s.Scenarios[0].Federated.Mutation = "grant-sub"
				s.Scenarios[0].Assertions = s.Scenarios[0].Assertions[:1]
			} else {
				kind := "status"
				value := json.RawMessage("200")
				if stage == "handoff" {
					kind, value = "fed-ps-proof", json.RawMessage("true")
				}
				s.Scenarios[0].Assertions = []Assertion{{
					ID: "false-native-claim", Clause: "fed.delivery",
					Stage: stage, Kind: kind, Equals: value,
				}}
			}
			if s.validate() == nil {
				t.Fatal("harness PS cannot supply native PS conformance evidence")
			}
		})
	}
}

func TestGrantFaultInjectionRejectsMalformedNativeExpiration(t *testing.T) {
	f := federationFixture()
	token, err := mintJWT(f.Access.Seed, f.Access.Kid, "aa-auth+jwt",
		map[string]any{"exp": "tomorrow"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"auth_token": token})
	_, err = mutateASResponse(f, "grant-sub", Response{Status: 200, Body: body})
	if err == nil {
		t.Fatal("fault injection accepted malformed native expiration")
	}
}

func TestFederatedSuiteKeepsMissingAdapterAnExecutionError(t *testing.T) {
	s, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := s.ForRole("authorization.federated")
	if err != nil || len(selected.Scenarios) != 34 {
		t.Fatalf("four-party scenarios: %d, %v", len(selected.Scenarios), err)
	}
	report, err := RunSuite(context.Background(), s, Targets{Version: 1, Role: "authorization.federated",
		Implementations: []Target{{ID: "missing", Revision: "test", Command: []string{"/no-federation-adapter"}}}},
		Options{Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if report.Success() || report.Runs[0].Error == "" || len(report.Runs[0].Cases) != 34 {
		t.Fatal("missing, unclaimed implementation was hidden")
	}
}

func federationFixture() Fixture {
	f := fixture()
	p := defaultPersonFixture()
	f.Person = &p
	f.Access = &AccessFixture{
		Issuer: "https://access.conformance.test",
		Seed:   strings.Repeat("05", 32), Kid: "as-1",
	}
	return f
}

// Core Auth Token Delivery and Auth Token Structure: a valid AS signature is
// insufficient if the grant changes the intended recipient or exceeds a parent.
func TestFederatedAuthOracleChecksEveryDeliveryBinding(t *testing.T) {
	f := federationFixture()
	parent := map[string]any{"sub": f.Person.Subject, "jti": "person-1", "exp": float64(f.Now + 60)}
	good := map[string]any{
		"iss": f.Access.Issuer, "dwk": "aauth-access.json", "aud": f.Origin,
		"ps": f.Person.Issuer, "sub": f.Person.Subject, "jti": "auth-1",
		"iat": f.Now, "exp": f.Now + 60, "scope": "read",
		"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
	}
	sign := func(claims map[string]any) string {
		token, err := mintJWT(f.Access.Seed, f.Access.Kid, "aa-auth+jwt", claims)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	token := sign(good)
	if o := observeFederatedAuth(f, token, parent, f.Now+600); !o.Valid {
		t.Fatal(o)
	}
	for name, value := range map[string]any{
		"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": "https://foreign.test",
		"ps": "https://foreign.test", "sub": "another-person", "jti": "",
		"exp": f.Now + 61, "scope": "read admin",
		"cnf":          map[string]any{"jwk": publicJWK(f.Person.Seed)},
		"mission_s256": "unexpected-mission", "account": "unexpected-account",
	} {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string]any)
			for k, v := range good {
				changed[k] = v
			}
			changed[name] = value
			if observeFederatedAuth(f, sign(changed), parent, f.Now+600).Valid {
				t.Fatalf("accepted changed %s under a valid AS signature", name)
			}
		})
	}
	if observeFederatedAuth(f, token, parent, f.Now+59).Valid {
		t.Fatal("ignored independent Agent expiry ceiling")
	}
	wrongSignature, _ := mintJWT(f.Person.Seed, f.Access.Kid, "aa-auth+jwt", good)
	if observeFederatedAuth(f, wrongSignature, parent, f.Now+600).Valid {
		t.Fatal("accepted non-AS signature")
	}
}

// A Resource challenge must preserve the actually presented Person identity and
// select the AS, not silently collapse federation to a direct PS exchange.
func TestFederatedResourceOracleChecksChallengeLineage(t *testing.T) {
	f := federationFixture()
	parent := map[string]any{"sub": f.Person.Subject, "jti": "actual-person-jti"}
	good := map[string]any{
		"iss": f.Origin, "dwk": "aauth-resource.json", "aud": f.Access.Issuer,
		"ps": f.Person.Issuer, "sub": f.Person.Subject, "presented_jti": "actual-person-jti",
		"agent_jkt": thumbprint(f.AgentSeed), "scope": "read",
		"jti": "resource-1", "iat": f.Now, "exp": f.Now + 300,
	}
	for name, value := range map[string]any{
		"valid": nil, "aud": f.Person.Issuer, "iss": f.Access.Issuer,
		"ps": "https://foreign.test", "sub": "another-person",
		"presented_jti": "other-jti", "agent_jkt": thumbprint(f.Person.Seed),
		"exp": f.Now, "scope": "read admin", "dwk": "aauth-access.json",
	} {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string]any)
			for k, v := range good {
				changed[k] = v
			}
			if name != "valid" {
				changed[name] = value
			}
			token, _ := mintJWT(f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt", changed)
			got := observeFederatedResource(f, token, parent).Valid
			if got != (name == "valid") {
				t.Fatalf("valid = %v", got)
			}
		})
	}
}

// The AS request proof must authenticate the actual body bytes and PS identity.
// This fixture spells out a signature base independently of the harness signer.
func TestPSProofOracleChecksDigestBytesIdentityAndCoverage(t *testing.T) {
	f := federationFixture()
	body := []byte(`{"resource_token":"r","agent_token":"a","presented_token":"p"}`)
	digest := sha256.Sum256(body)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	headers.Set("Signature-Key", `sig=jwks_uri;id="`+f.Person.Issuer+`";dwk="aauth-person.json";kid="`+f.Person.Kid+`"`)
	params := fmt.Sprintf(`("@method" "@authority" "@path" "signature-key" "content-type" "content-digest");created=%d`, f.Now)
	base := "\"@method\": POST\n\"@authority\": access.conformance.test\n\"@path\": /token\n" +
		"\"signature-key\": " + headers.Get("Signature-Key") + "\n\"content-type\": application/json\n\"content-digest\": " +
		headers.Get("Content-Digest") + "\n\"@signature-params\": " + params
	headers.Set("Signature-Input", "sig="+params)
	headers.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(f.Person.Seed), []byte(base)))+":")
	good := Captured{Method: "POST", URL: f.Access.Issuer + "/token", Headers: headers, Body: body}
	if got := observePSProof(f, good); !got.ValidProof {
		t.Fatal(got)
	}
	for _, mutation := range []string{"body", "authority", "path", "signature", "identity", "coverage", "signed-identity", "signed-uncovered-digest"} {
		t.Run(mutation, func(t *testing.T) {
			bad := good
			bad.Headers = headers.Clone()
			switch mutation {
			case "body":
				bad.Body = []byte(`{"resource_token":"x","agent_token":"a","presented_token":"p"}`)
			case "authority":
				bad.URL = "https://foreign.test/token"
			case "path":
				bad.URL = f.Access.Issuer + "/foreign"
			case "signature":
				bad.Headers.Set("Signature", "sig=:AAAA:")
			case "identity":
				bad.Headers.Set("Signature-Key", `sig=jwks_uri;id="https://foreign.test";dwk="aauth-person.json";kid="`+f.Person.Kid+`"`)
			case "coverage":
				bad.Headers.Set("Signature-Input", strings.Replace(headers.Get("Signature-Input"), ` "content-digest"`, "", 1))
			case "signed-identity", "signed-uncovered-digest":
				changedBase := base
				if mutation == "signed-identity" {
					old := headers.Get("Signature-Key")
					foreign := strings.Replace(old, f.Person.Issuer, "https://foreign.test", 1)
					bad.Headers.Set("Signature-Key", foreign)
					changedBase = strings.Replace(changedBase, old, foreign, 1)
				} else {
					newParams := strings.Replace(params, ` "content-digest"`, "", 1)
					bad.Headers.Set("Signature-Input", "sig="+newParams)
					changedBase = strings.Replace(changedBase, `"content-digest": `+headers.Get("Content-Digest")+"\n", "", 1)
					changedBase = strings.Replace(changedBase, params, newParams, 1)
				}
				signature := ed25519.Sign(seedKey(f.Person.Seed), []byte(changedBase))
				bad.Headers.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
			}
			if observePSProof(f, bad).ValidProof {
				t.Fatal("accepted", mutation)
			}
		})
	}
}
