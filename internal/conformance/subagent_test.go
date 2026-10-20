package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Removing role selection must not silently omit the child authorization slice.
func TestSubagentRoleSelectsOnlyItsScenariosAndClaims(t *testing.T) {
	suite := Suite{Scenarios: []Scenario{{ID: "child", Role: "authorization.subagent"}, {ID: "old", Role: DeferredRole}}, Catalog: Catalog{Clauses: []Clause{{ID: "child.binding", Role: "authorization.subagent"}, {ID: "old", Role: DeferredRole}}}}
	selected, err := suite.ForRole("authorization.subagent")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Scenarios) != 1 || selected.Scenarios[0].ID != "child" || len(selected.Catalog.Clauses) != 1 || selected.Catalog.Clauses[0].ID != "child.binding" {
		t.Fatalf("incorrect role selection: %+v", selected)
	}
}

// Exercises real HTTP fixture responses and independent Ed25519 verification.
// A parent-bound Person credential must stop the driver before /token.
func TestSubagentDriverRequiresChildBoundNativePerson(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprint(wrong), func(t *testing.T) {
			holder := strings.Repeat("06", 32)
			if wrong {
				holder = f.AgentSeed
			}
			person, _ := mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": f.Person.Subject, "jti": "fixture-person", "cnf": map[string]any{"jwk": publicJWK(holder)}, "iat": f.Now, "exp": f.Now + 60})
			auth, _ := mintJWT(f.Person.Seed, f.Person.Kid, "aa-auth+jwt", map[string]any{"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": f.Person.Subject, "ps": f.Person.Issuer, "jti": "fixture-auth", "cnf": map[string]any{"jwk": publicJWK(holder)}, "iat": f.Now, "exp": f.Now + 60, "scope": "read"})
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/person" {
					json.NewEncoder(w).Encode(map[string]any{"person_token": person, "expires_in": 60})
					return
				}
				if r.URL.Path == "/token" {
					json.NewEncoder(w).Encode(map[string]any{"auth_token": auth, "expires_in": 60})
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			scenario := Scenario{ID: "driver-test", Token: TokenSpec{IATOffset: -10, EXPOffset: 600}, Subagent: &SubagentSpec{Outcome: "direct"}, Assertions: []Assertion{{ID: "holder", Clause: "child", Stage: "person", Kind: "subagent-jwt", Equals: []byte("true")}, {ID: "auth", Clause: "child", Stage: "token", Kind: "subagent-jwt", Equals: []byte("true")}}}
			result := runSubagentCase(context.Background(), f, scenario, Target{Claims: []string{"child"}}, server.URL, Options{Timeout: time.Second}, &deferredRelay{fixture: f, timeout: time.Second}, nil)
			if len(result.Results) != 2 {
				t.Fatalf("driver produced %d assertions", len(result.Results))
			}
			if wrong {
				if result.Results[0].State != "fail" || calls != 1 {
					t.Fatalf("parent-bound credential escaped oracle: %+v calls=%d", result, calls)
				}
			} else if result.Error != "" || result.Results[0].State != "pass" || result.Results[1].State != "pass" || calls != 2 {
				t.Fatalf("valid child Person failed: %+v", result)
			}
		})
	}
}

// The PS signature can be valid while it forwards a different child compact.
// The relay must retain that distinction instead of repairing or trusting it.
func TestSubagentRelayChecksExactChildAndNativeProofSeparately(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer native.Close()
	relay := &deferredRelay{fixture: f, timeout: time.Second}
	listener := httptest.NewServer(relay)
	defer listener.Close()
	expected := map[string]string{"agent_token": "parent-compact", "subagent_token": "child-compact", "resource_token": "resource-compact", "presented_token": "person-compact"}
	for _, mutation := range []string{"none", "child", "missing", "proof"} {
		relay.reset(native.URL, "none", expected)
		input := map[string]string{}
		for k, v := range expected {
			input[k] = v
		}
		if mutation == "child" {
			input["subagent_token"] = "other-child"
		}
		if mutation == "missing" {
			delete(input, "subagent_token")
		}
		body, _ := json.Marshal(input)
		r, _, err := signedFixtureRequest(f, f.Person.Seed, "POST", f.Access.Issuer+"/token", fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-person.json";kid=%q`, f.Person.Issuer, f.Person.Kid), body)
		if err != nil {
			t.Fatal(err)
		}
		if mutation == "proof" {
			r.Header.Set("Signature", "sig=:AAAA:")
		}
		if _, err := Exchange(context.Background(), r, listener.URL, time.Second); err != nil {
			t.Fatal(err)
		}
		h := relay.snapshot()
		if len(h) != 1 {
			t.Fatal("missing native wire capture")
		}
		if h[0].Forwarded != (mutation == "none" || mutation == "proof") {
			t.Fatalf("%s forwarding=%v", mutation, h[0].Forwarded)
		}
		if h[0].Proof.ValidProof != (mutation != "proof") {
			t.Fatalf("%s proof=%+v", mutation, h[0].Proof)
		}
	}
}

func TestSubagentCancellationAndStageContract(t *testing.T) {
	if !validSubagentAssertion(Assertion{Stage: "cancel", Kind: "subagent-cancelled", Equals: []byte("true")}) {
		t.Fatal("protocol-successful cancellation is unsupported")
	}
	for _, a := range []Assertion{{Stage: "gone", Kind: "subagent-jwt", Equals: []byte("false")}, {Stage: "token", Kind: "subagent-proof", Equals: []byte("false")}, {Stage: "waiting", Kind: "subagent-forwarded", Equals: []byte("false")}, {Stage: "token", Kind: "subagent-cancelled", Equals: []byte("true")}} {
		if validSubagentAssertion(a) {
			t.Fatalf("unobserved stage accepted: %+v", a)
		}
	}
}

// A declaration of unavailable adapter support must stay unmeasured and must
// never launch, invent refusals, or make an all-unclaimed report green.
func TestSubagentUnavailableAdapterIsExplicitlyNotClaimed(t *testing.T) {
	var targets Targets
	if err := Decode([]byte(`{"version":1,"role":"authorization.subagent","implementations":[{"id":"aauth-go","revision":"not_measured","command":[],"claims":[],"unavailable":"full child role adapter unqualified"}]}`), &targets); err != nil {
		t.Fatal(err)
	}
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	report, err := RunSuite(context.Background(), suite, targets, Options{Timeout: time.Second, StartupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Success() || len(report.Runs) != 1 || len(report.Runs[0].Cases) != 18 {
		t.Fatalf("unmeasured target became successful: %+v", report)
	}
	for _, c := range report.Runs[0].Cases {
		if c.Error != "" {
			t.Fatalf("unavailable adapter executed: %s", c.Error)
		}
		for _, r := range c.Results {
			if r.State != "not_claimed" {
				t.Fatalf("unavailable assertion: %+v", r)
			}
		}
	}
}

func TestSubagentTerminalResultStillBelongsToParent(t *testing.T) {
	if !validSubagentAssertion(Assertion{Stage: "child-final", Kind: "subagent-refused", Equals: []byte("true")}) {
		t.Fatal("terminal child-poll ownership is unsupported")
	}
}

func TestSubagentKindsCannotEscapeTheirRoleOrInventASObservation(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	suite.Scenarios[0].Assertions[0].Kind = "subagent-refused"
	suite.Scenarios[0].Assertions[0].Equals = []byte("true")
	if err := suite.validate(); err == nil {
		t.Fatal("child assertion accepted in Resource role")
	}
	if validSubagentAssertion(Assertion{Stage: "access", Kind: "subagent-jwt", Equals: []byte("false")}) {
		t.Fatal("unobserved AS JWT was accepted")
	}
}

// Removing only the same-provider relationship check must be the decisive
// mutation: each AP token must already be valid under its own distinct key.
func TestWrongProviderUsesValidForeignAgentAndDistinctAPSignature(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	var scenario Scenario
	for _, s := range suite.Scenarios {
		if s.ID == "subagent-wrong-provider" {
			scenario = s
		}
	}
	var received map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"invalid_subagent_token"}`)
	}))
	defer server.Close()
	result := runSubagentCase(context.Background(), f, scenario, Target{Claims: Claims(suite, SubagentRole)}, server.URL, Options{Timeout: time.Second}, &deferredRelay{fixture: f, timeout: time.Second}, nil)
	if result.Error != "" || len(result.Exchanges) != 1 {
		t.Fatalf("wrong-provider fixture did not reach PS: %+v", result)
	}
	_, claims, err := verifyJWT(received["subagent_token"], strings.Repeat("07", 32), "foreign-ap-1", "aa-agent+jwt")
	if err != nil {
		t.Fatalf("foreign AP token not independently valid: %v", err)
	}
	if claims["iss"] != "https://foreign.conformance.test" || claims["sub"] != "aauth:Agent+child@foreign.conformance.test" || claims["parent_agent"] != f.Subject {
		t.Fatalf("foreign subject/issuer relationship malformed: %+v", claims)
	}
	if _, _, err := verifyJWT(received["subagent_token"], f.APSeed, "foreign-ap-1", "aa-agent+jwt"); err == nil {
		t.Fatal("foreign token also accepted under original AP key")
	}
	parentHeader := result.Exchanges[0].Headers.Get("Signature-Key")
	marker := `jwt="`
	start := strings.Index(parentHeader, marker)
	if start < 0 {
		t.Fatal("missing parent credential")
	}
	parent := strings.TrimSuffix(parentHeader[start+len(marker):], `"`)
	_, parentClaims, err := verifyJWT(parent, f.APSeed, f.Kid, "aa-agent+jwt")
	if err != nil || parentClaims["iss"] != f.Issuer || parentClaims["sub"] != f.Subject {
		t.Fatalf("original parent was changed: %+v %v", parentClaims, err)
	}
}

func TestSubagentBootstrapAdmitsForeignAPWithoutPrivateMaterial(t *testing.T) {
	t.Setenv("AAUTH_TEST_ADAPTER", "subagent-trust")
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suite.Scenarios {
		if s.ID == "subagent-wrong-provider" {
			suite.Scenarios = []Scenario{s}
			break
		}
	}
	targets := Targets{Version: 1, Role: SubagentRole, Implementations: []Target{{ID: "bootstrap-observer", Revision: "fixture", Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}, Claims: Claims(suite, SubagentRole)}}}
	report, err := RunSuite(context.Background(), suite, targets, Options{Timeout: time.Second, StartupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Cases) != 1 || len(report.Runs[0].Cases[0].Exchanges) != 1 {
		t.Fatalf("bootstrap observation missing: %+v", report)
	}
	var aps []struct {
		Issuer    string         `json:"issuer"`
		Transport string         `json:"transport"`
		Kid       string         `json:"kid"`
		JWK       map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(report.Runs[0].Cases[0].Exchanges[0].Response.Body, &aps); err != nil {
		t.Fatal(err)
	}
	if len(aps) != 1 || aps[0].Issuer != "https://foreign.conformance.test" || !strings.HasPrefix(aps[0].Transport, "http://127.0.0.1:") || aps[0].Kid != "foreign-ap-1" || aps[0].JWK["x"] != "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw" {
		t.Fatalf("foreign AP not independently admitted: %+v", aps)
	}
	if _, private := aps[0].JWK["d"]; private {
		t.Fatal("adapter bootstrap disclosed private AP material")
	}
}

func runSubagentBootstrapTestProcess(config Bootstrap) {
	var admitted []map[string]any
	for _, provider := range config.AdditionalAgentProviders {
		metadata, err := http.Get(provider.Transport + "/.well-known/aauth-agent.json")
		if err != nil {
			os.Exit(21)
		}
		var document map[string]any
		err = json.NewDecoder(metadata.Body).Decode(&document)
		metadata.Body.Close()
		if err != nil || document["issuer"] != provider.Issuer {
			os.Exit(22)
		}
		response, err := http.Get(provider.Transport + "/.well-known/jwks.json")
		if err != nil {
			os.Exit(23)
		}
		var keys struct {
			Keys []map[string]any `json:"keys"`
		}
		err = json.NewDecoder(response.Body).Decode(&keys)
		response.Body.Close()
		if err != nil || len(keys.Keys) != 1 {
			os.Exit(24)
		}
		admitted = append(admitted, map[string]any{"issuer": provider.Issuer, "transport": provider.Transport, "kid": keys.Keys[0]["kid"], "jwk": keys.Keys[0]})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(admitted)
	}))
	json.NewEncoder(os.Stdout).Encode(Ready{Version: 1, URL: server.URL + "/whoami"})
	select {}
}

// A child with 600 seconds must not let a 45-second parent obtain a 60-second
// Person credential, even though that response has a valid PS signature.
func TestShortParentLongChildRejectsOverlongPersonBeforeAuthorization(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	person, _ := mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": f.Person.Subject, "jti": "overlong-person", "cnf": map[string]any{"jwk": publicJWK(strings.Repeat("06", 32))}, "iat": f.Now, "exp": f.Now + 60})
	var input map[string]string
	var parentHeader string
	personCalls, authorizationCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__fixture/subagent" {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path != "/person" {
			authorizationCalls++
			w.WriteHeader(500)
			return
		}
		personCalls++
		parentHeader = r.Header.Get("Signature-Key")
		json.NewDecoder(r.Body).Decode(&input)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"person_token": person, "expires_in": 60})
	}))
	defer server.Close()
	s := Scenario{ID: "short-parent-fixture", Token: TokenSpec{IATOffset: -10, EXPOffset: 600}, Subagent: &SubagentSpec{Outcome: "short-parent"}, Assertions: []Assertion{{ID: "holder-and-lifetime", Clause: "child", Stage: "person", Kind: "subagent-jwt", Equals: []byte("true")}}}
	result := runSubagentCase(context.Background(), f, s, Target{Claims: []string{"child"}}, server.URL, Options{Timeout: time.Second}, &deferredRelay{fixture: f, timeout: time.Second}, nil)
	if len(result.Results) != 1 || result.Results[0].State != "fail" || personCalls != 1 || authorizationCalls != 0 {
		t.Fatalf("longer-child credential escaped parent ceiling: results=%+v person=%d auth=%d", result.Results, personCalls, authorizationCalls)
	}
	marker := `jwt="`
	start := strings.Index(parentHeader, marker)
	if start < 0 {
		t.Fatal("missing parent")
	}
	parent := strings.TrimSuffix(parentHeader[start+len(marker):], `"`)
	_, p, err := verifyJWT(parent, f.APSeed, f.Kid, "aa-agent+jwt")
	if err != nil || p["exp"] != float64(f.Now+45) {
		t.Fatalf("parent fixture did not isolate45-second boundary: %+v %v", p, err)
	}
	_, child, err := verifyJWT(input["subagent_token"], f.APSeed, f.Kid, "aa-agent+jwt")
	if err != nil || child["exp"] != float64(f.Now+600) {
		t.Fatalf("child must outlive parent: %+v %v", child, err)
	}
}

func TestForeignProviderFixtureCannotReusePrimaryAPKeyThroughHexCase(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suite.Scenarios {
		if s.ID == "subagent-wrong-provider" {
			s.Subagent.ForeignProvider.Seed = strings.ToUpper(suite.Fixture.APSeed)
			if err := validateSubagentScenario(suite.Fixture, s); err == nil {
				t.Fatal("foreign fixture reused original AP key through uppercase hex")
			}
			return
		}
	}
	t.Fatal("wrong-provider scenario absent")
}
