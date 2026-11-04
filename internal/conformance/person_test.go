package conformance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A valid-looking token signed by another key must fail the independent oracle;
// correctly signed tokens must also fail on widened scope or parent expiry.
func TestPersonOracleRejectsSignatureLineageScopeAndLifetime(t *testing.T) {
	f := fixture()
	ps := defaultPersonFixture()
	claims := map[string]any{"iss": ps.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": ps.Subject, "jti": "p1", "iat": f.Now, "exp": f.Now + 120, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}}
	compact, _ := mintJWT(ps.Seed, ps.Kid, "aa-person+jwt", claims)
	o := observePersonJWT(f, ps, compact, "person", nil, f.Now+150)
	if !o.Valid {
		t.Fatal(o)
	}
	for name, value := range map[string]any{"aud": []any{f.Origin}, "sub": "another-person"} {
		cloned := map[string]any{}
		for k, v := range claims {
			cloned[k] = v
		}
		cloned[name] = value
		other, _ := mintJWT(ps.Seed, ps.Kid, "aa-person+jwt", cloned)
		// A one-member aud array is RFC 7519 aud; another subject is a host
		// binding, graded only by the configured-subject check.
		o := observePersonJWT(f, ps, other, "person", nil, f.Now+150)
		if !o.Valid || o.Subject != (name == "aud") {
			t.Fatal("protocol-valid Person token misgraded", cloned, o)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { c["aud"] = "https://foreign.test" },
		func(c map[string]any) { c["aud"] = []any{f.Origin, "https://foreign.test"} },
		func(c map[string]any) { c["cnf"] = map[string]any{"jwk": publicJWK(strings.Repeat("08", 32))} },
		func(c map[string]any) { c["exp"] = f.Now + 151 },
		func(c map[string]any) { c["scope"] = "read" },
	} {
		cloned := map[string]any{}
		for k, v := range claims {
			cloned[k] = v
		}
		mutate(cloned)
		bad, _ := mintJWT(ps.Seed, ps.Kid, "aa-person+jwt", cloned)
		if observePersonJWT(f, ps, bad, "person", nil, f.Now+150).Valid {
			t.Fatal("invalid Person token accepted", cloned)
		}
	}
	foreign, _ := mintJWT(strings.Repeat("09", 32), ps.Kid, "aa-person+jwt", claims)
	if observePersonJWT(f, ps, foreign, "person", nil, f.Now+150).Valid {
		t.Fatal("foreign signature accepted")
	}
	auth := map[string]any{}
	for k, v := range claims {
		auth[k] = v
	}
	auth["ps"] = ps.Issuer
	auth["scope"] = "read"
	auth["jti"] = "a1"
	good, _ := mintJWT(ps.Seed, ps.Kid, "aa-auth+jwt", auth)
	_, parent, _ := verifyJWT(compact, ps.Seed, ps.Kid, "aa-person+jwt")
	if !observePersonJWT(f, ps, good, "auth", parent, f.Now+150).Valid {
		t.Fatal("valid Auth token refused")
	}
	for _, mutate := range []func(map[string]any){func(c map[string]any) { c["sub"] = "another-person" }, func(c map[string]any) { c["scope"] = "read admin" }, func(c map[string]any) { c["exp"] = f.Now + 121 }, func(c map[string]any) { c["ps"] = "https://foreign.test" }} {
		cloned := map[string]any{}
		for k, v := range auth {
			cloned[k] = v
		}
		mutate(cloned)
		bad, _ := mintJWT(ps.Seed, ps.Kid, "aa-auth+jwt", cloned)
		if observePersonJWT(f, ps, bad, "auth", parent, f.Now+150).Valid {
			t.Fatal("invalid Auth token accepted", cloned)
		}
	}
}

// A wrong-person mutation must retain a mathematically valid Resource JWT and
// HTTP proof: otherwise a broken lineage check could be masked by bad inputs.
func TestPersonInputsBindActualIssuedToken(t *testing.T) {
	f := fixture()
	ps := defaultPersonFixture()
	s := Scenario{ID: "mutation", Person: &PersonSpec{Mutation: "wrong-sub"}, Token: TokenSpec{IATOffset: -10, EXPOffset: 600}}
	claims := map[string]any{"iss": ps.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": ps.Subject, "jti": "issued-by-sut", "iat": f.Now, "exp": f.Now + 300, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}}
	person, _ := mintJWT(ps.Seed, ps.Kid, "aa-person+jwt", claims)
	req, _, err := buildPersonExchange(f, ps, s, "token", person, claims)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	json.NewDecoder(req.Body).Decode(&body)
	if body["presented_token"] != person {
		t.Fatal("actual Person bytes lost")
	}
	_, resource, err := verifyJWT(body["resource_token"], ps.ResourceSeed, ps.ResourceKid, "aa-resource+jwt")
	if err != nil || resource["presented_jti"] != "issued-by-sut" || resource["sub"] == ps.Subject {
		t.Fatalf("%v %v", resource, err)
	}
}

// Missing adapters and unclaimed cases remain execution errors for the PS role.
func TestPersonRoleMissingAdapterIsNotARefusalPass(t *testing.T) {
	s, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := s.ForRole(PersonServerRole)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Scenarios) != 12 {
		t.Fatalf("PS cases=%d", len(ps.Scenarios))
	}
	r, err := RunSuite(context.Background(), s, Targets{Version: 1, Role: PersonServerRole, Implementations: []Target{{ID: "missing", Revision: "test", Command: []string{"/no-such-ps-adapter"}}}}, Options{Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if r.Success() || r.Runs[0].Error == "" || len(r.Runs[0].Cases) != 12 {
		t.Fatal(r)
	}
	for _, c := range r.Runs[0].Cases {
		if c.Error == "" {
			t.Fatal("execution error hidden", c)
		}
	}
}

// An unsigned refusal must not accidentally become successful JWT evidence.
func TestDependentAuthChecksAreUnexercisedWhenTheResourceTokenIsRefused(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := suite.ForRole(PersonServerRole)
	if err != nil {
		t.Fatal(err)
	}
	var scenario Scenario
	for _, s := range selected.Scenarios {
		if s.ID == "ps-valid" {
			scenario = s
		}
	}
	f := suite.Fixture
	f.Now, f.Skew = time.Now().Unix(), 5
	p := *f.Person
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/person") {
			claims := map[string]any{
				"iss": p.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": p.Subject,
				"jti": "person-1", "iat": f.Now, "exp": f.Now + 60,
				"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
			}
			token, err := mintJWT(p.Seed, p.Kid, "aa-person+jwt", claims)
			if err != nil {
				t.Error(err)
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"person_token": token, "expires_in": int64(60)})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_resource_token"}`))
	}))
	defer server.Close()
	got := runPersonCase(context.Background(), f, scenario, Target{Claims: Claims(suite, PersonServerRole)}, server.URL, Options{Timeout: time.Second}, nil)
	states := map[string]string{}
	for _, result := range got.Results {
		states[result.Assertion] = result.State
	}
	if states["auth-status"] != "fail" {
		t.Fatalf("endpoint %s error %s", states["auth-status"], got.Error)
	}
	for _, id := range []string{"auth-signature", "auth-identity", "auth-key", "auth-lifetime", "auth-authorization"} {
		if states[id] != "not_exercised" {
			t.Fatalf("%s is %s", id, states[id])
		}
	}
	if states["person-status"] != "pass" {
		t.Fatalf("person status %s %s", states["person-status"], got.Error)
	}
}

func TestScopeMutationsStayUnexercisedUntilTheResourceTokenVerifies(t *testing.T) {
	refused := Response{Status: 400, Body: []byte(`{"error":"invalid_resource_token"}`)}
	expired := unexercisedIssuance(Result{State: "fail"}, Assertion{ID: "token-error", Kind: "json-member", Stage: "token"}, Scenario{Person: &PersonSpec{Mutation: "expired-resource"}}, false, true, false)
	if expired.State != "not_exercised" || !strings.Contains(expired.Detail, "expiry") {
		t.Fatal(expired)
	}
	denied := unexercisedIssuance(Result{State: "fail"}, Assertion{ID: "token-refusal", Kind: "status", Stage: "token"}, Scenario{Person: &PersonSpec{Mutation: "denied-scope"}}, false, resourceUnverified(refused), false)
	if denied.State != "not_exercised" || !strings.Contains(denied.Detail, "scope policy") {
		t.Fatal(denied)
	}
	kept := unexercisedIssuance(Result{State: "pass"}, Assertion{ID: "token-error", Kind: "json-member", Stage: "token"}, Scenario{Person: &PersonSpec{Mutation: "wrong-aud"}}, false, true, false)
	if kept.State != "pass" {
		t.Fatal("wrong audience was dropped", kept)
	}
}

func TestDeclaredScopeIsTheGrantTheAuthTokenMustCarry(t *testing.T) {
	f := Fixture{Now: 1800000000, Origin: "https://resource.conformance.test", AgentSeed: strings.Repeat("02", 32), Skew: 5}
	p := defaultPersonFixture()
	p.PermittedScopes = []string{"records.read"}
	p.ScopeDeclared = true
	claims := map[string]any{"iss": p.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "ps": p.Issuer, "sub": p.Subject, "jti": "auth-1", "iat": f.Now, "exp": f.Now + 60, "scope": "records.read", "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}}
	token, err := mintJWT(p.Seed, p.Kid, "aa-auth+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	parent := map[string]any{"sub": p.Subject, "exp": float64(f.Now + 300)}
	if !observePersonJWT(f, p, token, "auth", parent, f.Now+3600).Scope {
		t.Fatal("declared scope was not the expected grant")
	}
	claims["scope"] = "read"
	other, _ := mintJWT(p.Seed, p.Kid, "aa-auth+jwt", claims)
	if observePersonJWT(f, p, other, "auth", parent, f.Now+3600).Scope {
		t.Fatal("read stood in for the declared scope")
	}
}

func TestPersonAssertionRequiresVerifiedToken(t *testing.T) {
	a := Assertion{ID: "jwt", Clause: "ps.person-structure", Kind: "ps-jwt", Equals: json.RawMessage(`true`)}
	if checkPerson(a, Response{Status: http.StatusOK, Body: []byte(`{"person_token":"a.b.c"}`)}, PersonObservation{Error: "bad signature"}).State != "fail" {
		t.Fatal("unverified token accepted")
	}
}

// A refusal that also releases a usable credential must never be a pass.
func TestPersonRefusalCannotReleaseToken(t *testing.T) {
	a := Assertion{ID: "no-token", Clause: "ps.resource-verification", Kind: "ps-no-token", Equals: json.RawMessage(`true`)}
	if checkPerson(a, Response{Status: 400, Body: []byte(`{"error":"invalid_resource_token"}`)}, PersonObservation{}).State != "pass" {
		t.Fatal("ordinary refusal not recognized")
	}
	for _, body := range []string{`{"error":"invalid_resource_token","auth_token":"a.b.c"}`, `{"person_token":"a.b.c"}`, `not-json`} {
		if checkPerson(a, Response{Status: 400, Body: []byte(body)}, PersonObservation{}).State != "fail" {
			t.Fatal("credential leak or unreadable refusal passed", body)
		}
	}
}

func TestPersonScenarioValidationRejectsIgnoredInputsAndNullBooleans(t *testing.T) {
	for _, mutate := range []func(*Suite){
		func(s *Suite) { s.Scenarios[0].Request.Method = "DELETE" },
		func(s *Suite) { s.Scenarios[0].Person.Mutation = "misspelled" },
		func(s *Suite) { s.Scenarios[0].Assertions[1].Equals = json.RawMessage(`null`) },
		func(s *Suite) { s.Scenarios[0].Assertions[1].Stage = "unknown" },
	} {
		suite, e := Load("../..")
		if e != nil {
			t.Fatal(e)
		}
		suite, e = suite.ForRole(PersonServerRole)
		if e != nil {
			t.Fatal(e)
		}
		mutate(&suite)
		if suite.validate() == nil {
			t.Fatal("unsupported PS input was silently accepted")
		}
	}
}

func defaultPersonFixture() PersonFixture {
	return PersonFixture{Issuer: "https://person.conformance.test", Seed: strings.Repeat("03", 32), Kid: "ps-1", Subject: "directed-person-1", Lifetime: 300, AuthLifetime: 180, PermittedScopes: []string{"read"}, ResourceSeed: strings.Repeat("04", 32), ResourceKid: "resource-1"}
}

func TestPersonConfirmationKeyAllowsPublicMetadataButNotDifferentMaterial(t *testing.T) {
	f := fixture()
	ps := defaultPersonFixture()
	for _, kind := range []string{"person", "auth"} {
		for _, tc := range []struct {
			name string
			key  map[string]any
			want bool
		}{
			{"kid", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": publicJWK(f.AgentSeed)["x"], "alg": "Ed25519", "kid": "agent-key-1", "use": "sig"}, true},
			{"different-key", publicJWK(strings.Repeat("08", 32)), false},
			{"private", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": publicJWK(f.AgentSeed)["x"], "alg": "Ed25519", "d": "secret"}, false},
			{"wrong-alg", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": publicJWK(f.AgentSeed)["x"], "alg": "EdDSA"}, false},
			{"bad-x", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "bad", "alg": "Ed25519"}, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				claims := map[string]any{"iss": ps.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": ps.Subject, "jti": "issued", "iat": f.Now, "exp": f.Now + 60, "cnf": map[string]any{"jwk": tc.key}}
				parent := map[string]any{"sub": ps.Subject, "exp": float64(f.Now + 120)}
				typ := "aa-person+jwt"
				if kind == "auth" {
					typ = "aa-auth+jwt"
					claims["ps"] = ps.Issuer
					claims["scope"] = "read"
				}
				compact, err := mintJWT(ps.Seed, ps.Kid, typ, claims)
				if err != nil {
					t.Fatal(err)
				}
				got := observePersonJWT(f, ps, compact, kind, parent, f.Now+600)
				if !got.Signature || got.Key != tc.want || got.Valid != tc.want {
					t.Fatalf("want key/valid=%v, got %+v", tc.want, got)
				}
			})
		}
	}
}

func TestPublishedPersonFixtureSeparatesThePresentedExpiryBound(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	ps := *suite.Fixture.Person
	var valid Scenario
	for _, s := range suite.Scenarios {
		if s.ID == "ps-valid" {
			valid = s
		}
	}
	if valid.ID == "" {
		t.Fatal("missing valid PS scenario")
	}
	if !(ps.Lifetime < ps.AuthLifetime && ps.Lifetime < valid.Token.EXPOffset && ps.AuthLifetime < 3600) {
		t.Fatalf("presented cap is masked: person=%d auth=%d agent=%d", ps.Lifetime, ps.AuthLifetime, valid.Token.EXPOffset)
	}
	// Simulate a correctly signed SUT grant that omits only the presented cap.
	f := suite.Fixture
	claims := map[string]any{"iss": ps.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "ps": ps.Issuer, "sub": ps.Subject, "jti": "bad-cap", "iat": f.Now, "exp": f.Now + ps.AuthLifetime, "scope": "read", "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}}
	token, err := mintJWT(ps.Seed, ps.Kid, "aa-auth+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	parent := map[string]any{"sub": ps.Subject, "exp": float64(f.Now + ps.Lifetime)}
	observed := observePersonJWT(f, ps, token, "auth", parent, f.Now+valid.Token.EXPOffset)
	assertion := Assertion{ID: "auth-lifetime", Clause: "ps.auth-lifetime", Kind: "ps-jwt-lifetime", Equals: json.RawMessage(`true`)}
	result := checkPerson(assertion, Response{Status: 200}, observed)
	if !observed.Signature || !observed.Identity || !observed.Key || !observed.Scope || result.State != "fail" {
		t.Fatalf("fault escaped targeted lifetime assertion: %+v %+v", observed, result)
	}
}

func TestSuccessfulResponseWithoutAuthTokenIsStillAProtocolFailure(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := suite.ForRole(PersonServerRole)
	if err != nil {
		t.Fatal(err)
	}
	var scenario Scenario
	for _, s := range selected.Scenarios {
		if s.ID == "ps-valid" {
			scenario = s
		}
	}
	f := suite.Fixture
	f.Now, f.Skew = time.Now().Unix(), 5
	p := *f.Person
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/person") {
			claims := map[string]any{
				"iss": p.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": p.Subject,
				"jti": "person-1", "iat": f.Now, "exp": f.Now + 60,
				"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
			}
			token, err := mintJWT(p.Seed, p.Kid, "aa-person+jwt", claims)
			if err != nil {
				t.Error(err)
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"person_token": token, "expires_in": int64(60)})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"expires_in":60}`))
	}))
	defer server.Close()
	got := runPersonCase(context.Background(), f, scenario, Target{Claims: Claims(suite, PersonServerRole)}, server.URL, Options{Timeout: time.Second}, nil)
	states := map[string]string{}
	for _, result := range got.Results {
		states[result.Assertion] = result.State
	}
	if states["auth-status"] != "pass" {
		t.Fatalf("endpoint %s error %s", states["auth-status"], got.Error)
	}
	for _, id := range []string{"auth-signature", "auth-identity", "auth-key", "auth-lifetime", "auth-authorization"} {
		if states[id] != "fail" {
			t.Fatalf("%s is %s", id, states[id])
		}
	}
	if states["person-status"] != "pass" {
		t.Fatalf("person status %s %s", states["person-status"], got.Error)
	}
}

func TestDeclaredScopesAreAnUnorderedSet(t *testing.T) {
 f := fixture(); p := defaultPersonFixture(); p.PermittedScopes=[]string{"read", "records.read"}
 claims:=map[string]any{"iss":p.Issuer,"dwk":"aauth-person.json","aud":f.Origin,"ps":p.Issuer,"sub":p.Subject,"jti":"auth-order","iat":f.Now,"exp":f.Now+60,"scope":"records.read read","cnf":map[string]any{"jwk":publicJWK(f.AgentSeed)}}
 token,_:=mintJWT(p.Seed,p.Kid,"aa-auth+jwt",claims)
 parent:=map[string]any{"sub":p.Subject,"exp":float64(f.Now+300)}
 if !observePersonJWT(f,p,token,"auth",parent,f.Now+600).Scope {t.Fatal("scope ordering changed the declared grant")}
}
