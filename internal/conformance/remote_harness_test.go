package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Catches remote token checks that accept only Ed25519, or that let a key
// verify under an algorithm other than its own.
func TestRemoteKeysVerifyES256(t *testing.T) {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := private.PublicKey.ECDH()
	raw := point.Bytes()
	b64 := base64.RawURLEncoding.EncodeToString
	published := map[string]any{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:]), "kid": "es-1"}
	jwks := map[string]any{"keys": []any{published, map[string]any{"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA", "kid": "p384"}}}
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := any(map[string]any{"issuer": "https://as.example", "jwks_uri": "https://as.example/jwks"})
		if r.URL.Path == "/jwks" {
			body = jwks
		}
		json.NewEncoder(w).Encode(body)
	}), "as.example")
	keys, _, err := publishedKeys(WithNetwork(context.Background(), network), "https://as.example", "aauth-access.json", time.Second)
	if err != nil || len(keys) != 1 || keys["es-1"]["alg"] != "ES256" {
		t.Fatalf("%v %v", keys, err)
	}
	sign := func(alg string) string {
		head, _ := json.Marshal(map[string]any{"alg": alg, "typ": "aa-auth+jwt", "kid": "es-1"})
		body, _ := json.Marshal(map[string]any{"iss": "https://as.example"})
		input := b64(head) + "." + b64(body)
		digest := sha256.Sum256([]byte(input))
		r, s, _ := ecdsa.Sign(rand.Reader, private, digest[:])
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return input + "." + b64(signature)
	}
	if _, claims, err := verifyJWTWith(sign("ES256"), keys, "aa-auth+jwt"); err != nil || claims["iss"] != "https://as.example" {
		t.Fatalf("ES256 token refused: %v", err)
	}
	if _, _, err := verifyJWTWith(sign("Ed25519"), keys, "aa-auth+jwt"); err == nil {
		t.Fatal("an ES256 key verified a token claiming Ed25519")
	}
	if signingJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": published["x"], "y": published["y"], "alg": "ES384"}) != nil {
		t.Fatal("accepted a P-256 key naming another alg")
	}
	if signingJWK(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": publicJWK(strings.Repeat("01", 32))["x"], "d": "x"}) != nil {
		t.Fatal("accepted a private key")
	}
}

// Catches per-case handlers that leak into later cases, lose to the fixed
// documents, or do not record what a deployed server sent.
func TestHarnessHandlersOverrideAndCapture(t *testing.T) {
	suite := loadSuite(t)
	h := NewHarness(suite.Fixture)
	network := testServer(t, h, HarnessNames(suite.Fixture)...)
	ctx := WithNetwork(context.Background(), network)
	get := func(target string) Response {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		response, err := Exchange(ctx, request, "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	metadata := suite.Fixture.Issuer + "/.well-known/aauth-agent.json"
	if get(metadata).Status != http.StatusOK {
		t.Fatal("fixed document not served")
	}
	remove := h.Handle(suite.Fixture.Issuer+"/.well-known/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	if get(metadata).Status != http.StatusTeapot {
		t.Fatal("handler did not take precedence")
	}
	remove()
	if get(metadata).Status != http.StatusOK {
		t.Fatal("handler outlived its case")
	}
	captured, stop := h.Capture(suite.Fixture.Issuer+"/events", func(Inbound) (int, http.Header, []byte) { return http.StatusAccepted, nil, nil })
	defer stop()
	request, _ := http.NewRequest(http.MethodPost, suite.Fixture.Issuer+"/events", strings.NewReader(`{"x":1}`))
	request.Header.Set("Signature-Key", "sig=self-jwt")
	response, err := Exchange(ctx, request, "", time.Second)
	if err != nil || response.Status != http.StatusAccepted {
		t.Fatalf("%v %v", response.Status, err)
	}
	in := <-captured
	if in.Method != http.MethodPost || string(in.Body) != `{"x":1}` || in.Header.Get("Signature-Key") != "sig=self-jwt" || in.Header.Get("Host") != "ap.conformance.test" {
		t.Fatalf("%+v", in)
	}
}

// Catches a deployment whose control, agent or new servers break the
// identifier rules, and controls whose absence is not given as the reason.
func TestRemoteControlAndAgentValidation(t *testing.T) {
	suite := loadSuite(t)
	base := RemoteRole{Resource: "https://records.example/records", AccessServer: "https://as.example"}
	for name, change := range map[string]func(*RemoteRole){
		"control query": func(r *RemoteRole) { r.Control = "https://control.example/?x" },
		"control http":  func(r *RemoteRole) { r.Control = "http://control.example" },
		"suite control": func(r *RemoteRole) { r.Control = "https://ap.conformance.test/c" },
		"agent shape":   func(r *RemoteRole) { r.Agent = "agent@ap.example" },
		"ap port":       func(r *RemoteRole) { r.AgentProvider = "https://ap.example:8443" },
		"ss path":       func(r *RemoteRole) { r.SupervisionServer = "https://ss.example/v1" },
	} {
		r := base
		change(&r)
		d := Deployment{Version: 1, ID: "i", Revision: "1", Roles: map[string]RemoteRole{FederatedRole: r}}
		if ValidateDeployment(d, suite) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := base
	r.Control, r.Agent, r.AgentProvider = "https://control.example/hooks", "aauth:agent@ap.example", "https://ap.example"
	if err := ValidateDeployment(Deployment{Version: 1, ID: "i", Revision: "1", Roles: map[string]RemoteRole{FederatedRole: r}}, suite); err != nil {
		t.Fatal(err)
	}
	if got := controlGap(RemoteRole{}, "/__fixture/fire"); !strings.Contains(got, "/__fixture/fire") {
		t.Fatalf("%q", got)
	}
	if controlGap(r, "/__fixture/fire") != "" || (&RemoteRun{Role: r}).ControlURL("/__fixture/fire") != "https://control.example/hooks/__fixture/fire" {
		t.Fatal("control not used")
	}
}

// Catches expected values that keep a replaced fixture identity, or a
// rewrite that touches values which only contain it.
func TestRebaseExpectedRewritesExactIdentities(t *testing.T) {
	s := Scenario{Assertions: []Assertion{
		{ID: "a", Equals: json.RawMessage(`"https://ss.conformance.test"`)},
		{ID: "b", Equals: json.RawMessage(`["https://ss.conformance.test","x"]`)},
		{ID: "c", Equals: json.RawMessage(`"https://ss.conformance.test/connect"`)},
	}}
	out := rebaseExpected(s, map[string]string{"https://ss.conformance.test": "https://ss.example"})
	if string(out.Assertions[0].Equals) != `"https://ss.example"` || string(out.Assertions[1].Equals) != `["https://ss.example","x"]` || string(out.Assertions[2].Equals) != `"https://ss.conformance.test/connect"` {
		t.Fatalf("%s %s %s", out.Assertions[0].Equals, out.Assertions[1].Equals, out.Assertions[2].Equals)
	}
	if string(s.Assertions[0].Equals) != `"https://ss.conformance.test"` {
		t.Fatal("rebasing changed the suite's scenario")
	}
}

func TestPublicHarnessUsesOneLabelUnderTheDomain(t *testing.T) {
	suite := loadSuite(t)
	out, err := PublicHarness(suite.Fixture, "harness.aauth.sidecat.dev")
	if err != nil {
		t.Fatal(err)
	}
	if out.Origin != "https://resource.harness.aauth.sidecat.dev" || out.Issuer != "https://ap.harness.aauth.sidecat.dev" {
		t.Fatalf("origin %s issuer %s", out.Origin, out.Issuer)
	}
	if out.Person == nil || out.Person.Issuer != "https://person.harness.aauth.sidecat.dev" {
		t.Fatal(out.Person)
	}
	joined := strings.Join(HarnessNames(out), " ")
	if !strings.Contains(joined, "resource.harness.aauth.sidecat.dev") || strings.Contains(joined, "resource.conformance.test") {
		t.Fatal(joined)
	}
	if _, err := PublicHarness(suite.Fixture, ""); err == nil {
		t.Fatal("empty domain accepted")
	}
}

func TestPublicScenariosRenameExpectedParties(t *testing.T) {
	suite := loadSuite(t)
	out := PublicScenarios(suite.Scenarios, "harness.aauth.sidecat.dev")
	if len(out) != len(suite.Scenarios) {
		t.Fatalf("%d scenarios, want %d", len(out), len(suite.Scenarios))
	}
	found := false
	for i, scenario := range out {
		for j, a := range scenario.Assertions {
			if strings.Contains(string(a.Equals), ".conformance.test") {
				t.Errorf("%s/%s still expects %s", scenario.ID, a.ID, a.Equals)
			}
			if string(a.Equals) == `"aauth:Agent@ap.harness.aauth.sidecat.dev"` {
				found = true
				if string(suite.Scenarios[i].Assertions[j].Equals) != `"aauth:Agent@ap.conformance.test"` {
					t.Errorf("the loaded suite was changed: %s", suite.Scenarios[i].Assertions[j].Equals)
				}
			}
			if len(suite.Scenarios[i].Assertions[j].Equals) == 0 && a.Equals != nil {
				t.Errorf("%s/%s gained an expected value", scenario.ID, a.ID)
			}
		}
	}
	if !found {
		t.Fatal("no expectation names the public fixture agent")
	}
}

func TestPublicHarnessIncludesEveryDerivedParty(t *testing.T) {
	f := loadSuite(t).Fixture
	public, err := PublicHarness(f, "harness.aauth.sidecat.dev")
	if err != nil {
		t.Fatal(err)
	}
	names := HarnessNames(public)
	for _, name := range HarnessNames(f) {
		want := strings.ReplaceAll(name, ".conformance.test", ".harness.aauth.sidecat.dev")
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("public harness is missing %s", want)
		}
	}
}
