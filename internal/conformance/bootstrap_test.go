package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func bootstrapTestSuite(t *testing.T) (Suite, BootstrapFixture) {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	b, err := bootstrapFixture(suite.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	return suite, b
}

// gradeAll grades a case's observations as a target claiming every clause.
func gradeAll(s Scenario, stages map[string]*Response, own map[string]Result, err error) []Result {
	execution := ""
	if err != nil {
		execution = err.Error()
	}
	claims := []string{}
	for _, a := range s.Assertions {
		claims = append(claims, a.Clause)
	}
	results := []Result{}
	for _, a := range s.Assertions {
		results = append(results, Grade(a, claims, execution, stages[a.Stage], func(a Assertion) Result {
			if r := own[a.ID]; r.State != "" {
				return r
			}
			return Result{Assertion: a.ID, State: "error", Detail: "no observation"}
		}))
	}
	return results
}

func failing(results []Result) []string {
	out := []string{}
	for _, r := range results {
		if r.State != "pass" {
			out = append(out, fmt.Sprintf("%s=%s (%s)", r.Assertion, r.State, r.Detail))
		}
	}
	return out
}

func roleScenarios(s Suite, role string) []Scenario {
	out := []Scenario{}
	for _, scenario := range s.Scenarios {
		if scenario.Role == role {
			out = append(out, scenario)
		}
	}
	return out
}

// Catches a role whose clauses no scenario reaches, or a validator that
// accepts inputs the runner cannot observe.
func TestBootstrapScenariosLoadAndRefuseMalformedInput(t *testing.T) {
	suite, _ := bootstrapTestSuite(t)
	counts := map[string]int{}
	reached := map[string]bool{}
	for _, s := range suite.Scenarios {
		counts[s.Role]++
		for _, a := range s.Assertions {
			reached[a.Clause] = true
		}
	}
	if counts[BootstrapProviderRole] != 15 || counts[BootstrapAgentRole] != 4 || counts[BootstrapSelfHostedRole] != 5 {
		t.Fatalf("bootstrap scenario counts: %v", counts)
	}
	for _, c := range suite.Catalog.Clauses {
		if strings.HasPrefix(c.ID, "bootstrap.") && !reached[c.ID] {
			t.Errorf("clause %s has no scenario", c.ID)
		}
	}
	find := func(id string) Scenario {
		for _, s := range suite.Scenarios {
			if s.ID == id {
				return s
			}
		}
		t.Fatalf("scenario %s absent", id)
		return Scenario{}
	}
	for name, mutate := range map[string]func(*Scenario){
		"unknown mutation":    func(s *Scenario) { s.Input = json.RawMessage(`{"flow":"refresh","mutation":"other"}`) },
		"token at enrollment": func(s *Scenario) { s.Assertions[1].Stage = "enroll" },
		"unknown property":    func(s *Scenario) { s.Assertions[2].Member = "colour" },
		"same-subject early":  func(s *Scenario) { s.Assertions[2].Member = "same-subject" },
		"non-boolean":         func(s *Scenario) { s.Assertions[2].Equals = json.RawMessage(`"yes"`) },
	} {
		s := find("bootstrap-ap-refresh")
		s.Assertions = slices.Clone(s.Assertions)
		s.Assertions[1].Kind, s.Assertions[1].Member, s.Assertions[1].Equals = "bootstrap-token", "signature", json.RawMessage(`true`)
		mutate(&s)
		if err := validateBootstrapProvider(suite.Fixture, s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	agent := find("bootstrap-agent-refresh")
	for _, ops := range []string{`["refresh"]`, `["enroll","call"]`, `["enroll","refresh","refresh","refresh"]`, `["enroll","refresh","subagent","subagent"]`} {
		agent.Input = json.RawMessage(`{"operations":` + ops + `}`)
		if err := validateBootstrapAgent(suite.Fixture, agent); err == nil {
			t.Errorf("operations %s accepted", ops)
		}
	}
	self := find("bootstrap-self-subagent")
	for _, issues := range []string{`[{"parent":1,"key":"subagent","discriminator":"a"}]`, `[{"agent":"a+b","key":"durable"}]`, `[{"agent":"a","key":"nope"}]`, `[{"agent":"a","key":"durable"},{"parent":1,"key":"subagent"}]`} {
		self.Input = json.RawMessage(`{"issues":` + issues + `}`)
		if err := validateBootstrapSelf(suite.Fixture, self); err == nil {
			t.Errorf("issues %s accepted", issues)
		}
	}
}

// referenceAP is a test Agent Provider written to the adapter contract. Its
// faults let a test show that the scenarios catch the matching defect.
type referenceAP struct {
	f        Fixture
	b        BootstrapFixture
	fault    string
	mu       sync.Mutex
	enrolled map[string]string
	n        int
}

func (ap *referenceAP) mint(claims map[string]any) string {
	ap.n++
	claims["iss"], claims["dwk"], claims["jti"], claims["iat"] = ap.f.Issuer, "aauth-agent.json", fmt.Sprintf("ref-%d", ap.n), ap.f.Now
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = ap.f.Now + ap.b.AgentLifetime
	}
	return mintJOSE(ap.f.APSeed, map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": ap.f.Kid}, claims)
}

func (ap *referenceAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	c, _ := capturedRequest(r, 65536)
	signed := readSignedRequest(c)
	var body map[string]any
	json.Unmarshal(c.Body, &body)
	ps, _ := body["ps"].(string)
	refuse := func(status int) { writeJSON(w, status, map[string]any{"error": "refused"}) }
	switch r.URL.Path {
	case "/.well-known/aauth-agent.json":
		writeJSON(w, 200, map[string]any{"issuer": ap.f.Issuer, "jwks_uri": ap.f.Issuer + "/.well-known/jwks.json"})
	case "/.well-known/jwks.json":
		key := publicJWK(ap.f.APSeed)
		key["kid"] = ap.f.Kid
		writeJSON(w, 200, map[string]any{"keys": []any{key}})
	case ap.b.EnrollmentPath:
		key := signed.hwkKey()
		if !signed.verifiedBy(ap.f, key, "content-type", "content-digest") {
			refuse(401)
			return
		}
		if _, ok := ap.enrolled[jwkThumbprint(key)]; !ok {
			ap.enrolled[jwkThumbprint(key)] = fmt.Sprintf("aauth:install%d@%s", len(ap.enrolled)+1, hostOf(ap.f.Issuer))
		}
		writeJSON(w, 201, map[string]any{"agent": ap.enrolled[jwkThumbprint(key)]})
	case ap.b.RefreshPath:
		naming := readNamingJWT(ap.f, signed.Params["jwt"])
		accepted := naming.Valid || ap.fault == "accept-bad-iss" && strings.HasPrefix(naming.Error, "iss")
		if signed.Scheme != "jkt-jwt" || !accepted || !signed.verifiedBy(ap.f, naming.delegated, "content-type", "content-digest") {
			refuse(401)
			return
		}
		sub, ok := ap.enrolled[jwkThumbprint(naming.durable)]
		if !ok {
			refuse(404)
			return
		}
		if ap.fault == "unstable-sub" {
			sub = strings.Replace(sub, "install", fmt.Sprintf("install%d-", ap.n), 1)
		}
		cnf := naming.Claims["cnf"].(map[string]any)
		writeJSON(w, 200, map[string]any{"agent_token": ap.mint(map[string]any{"sub": sub, "ps": ps, "cnf": cnf})})
	case ap.b.SingleKeyRefreshPath:
		key := signed.hwkKey()
		sub, ok := ap.enrolled[jwkThumbprint(key)]
		if !signed.verifiedBy(ap.f, key, "content-type", "content-digest") || !ok {
			refuse(401)
			return
		}
		writeJSON(w, 200, map[string]any{"agent_token": ap.mint(map[string]any{"sub": sub, "ps": ps, "cnf": map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": signed.Params["x"], "alg": "Ed25519"}}})})
	case ap.b.SubagentPath:
		parent, err := ap.verifyParent(signed.Params["jwt"])
		if signed.Scheme != "jwt" || err != nil || !signed.verifiedBy(ap.f, confirmationPublicKey(parent["cnf"].(map[string]any)["jwk"]), "content-type", "content-digest") {
			refuse(401)
			return
		}
		writeJSON(w, 200, map[string]any{"agent_token": ap.child(parent, body)})
	default:
		refuse(404)
	}
}

// verifyParent accepts only an unexpired top-level token this AP signed.
func (ap *referenceAP) verifyParent(compact string) (map[string]any, error) {
	_, parent, err := verifyJWT(compact, ap.f.APSeed, ap.f.Kid, "aa-agent+jwt")
	if err != nil {
		return nil, err
	}
	if exp, _ := parent["exp"].(float64); exp <= float64(ap.f.Now) {
		return nil, fmt.Errorf("expired")
	}
	if _, nested := parent["parent_agent"]; nested && ap.fault != "nested" {
		return nil, fmt.Errorf("a sub-agent cannot have sub-agents")
	}
	return parent, nil
}

func (ap *referenceAP) child(parent, body map[string]any) string {
	discriminator, _ := body["discriminator"].(string)
	if discriminator == "" {
		discriminator = "auto1"
	}
	local, domain, _ := splitAgentIdentifier(parent["sub"].(string))
	claims := map[string]any{"sub": "aauth:" + local + "+" + discriminator + "@" + domain, "parent_agent": parent["sub"], "cnf": map[string]any{"jwk": body["jwk"]}, "exp": parent["exp"]}
	if ps, ok := parent["ps"]; ok {
		claims["ps"] = ps
	}
	return ap.mint(claims)
}

// The self-hosted control: a top-level agent or a sub-agent of a token it issued.
func (ap *referenceAP) issue(w http.ResponseWriter, r *http.Request) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	if compact, ok := body["parent_token"].(string); ok {
		parent, err := ap.verifyParent(compact)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"agent_token": ap.child(parent, body)})
		return
	}
	writeJSON(w, 200, map[string]any{"agent_token": ap.mint(map[string]any{"sub": body["agent"], "ps": body["ps"], "cnf": map[string]any{"jwk": body["jwk"]}})})
}

// Catches an AP oracle that fails a correct AP, or one that passes an AP
// accepting a bad naming JWT, nesting sub-agents or changing sub on refresh.
func TestBootstrapProviderScenariosAgainstReferenceAP(t *testing.T) {
	suite, b := bootstrapTestSuite(t)
	run := func(fault string, s Scenario) []Result {
		ap := &referenceAP{f: suite.Fixture, b: b, fault: fault, enrolled: map[string]string{}}
		server := httptest.NewServer(ap)
		defer server.Close()
		stages, _, own, err := bootstrapProviderCase(context.Background(), suite.Fixture, b, s, Ready{Version: 1, URL: server.URL + "/.well-known/aauth-agent.json"}, Options{Timeout: 2 * time.Second})
		return gradeAll(s, stages, own, err)
	}
	for _, s := range roleScenarios(suite, BootstrapProviderRole) {
		if bad := failing(run("", s)); len(bad) > 0 {
			t.Errorf("%s against the reference AP: %v", s.ID, bad)
		}
	}
	for fault, id := range map[string]string{"accept-bad-iss": "bootstrap-ap-refresh-jkt-iss", "nested": "bootstrap-ap-subagent-nested", "unstable-sub": "bootstrap-ap-rotate"} {
		for _, s := range roleScenarios(suite, BootstrapProviderRole) {
			if s.ID == id && len(failing(run(fault, s))) == 0 {
				t.Errorf("fault %s passed %s", fault, id)
			}
		}
	}
}

func TestBootstrapSelfHostedScenariosAgainstReference(t *testing.T) {
	suite, b := bootstrapTestSuite(t)
	run := func(fault string, s Scenario) []Result {
		ap := &referenceAP{f: suite.Fixture, b: b, fault: fault, enrolled: map[string]string{}}
		mux := http.NewServeMux()
		mux.Handle("/", ap)
		mux.HandleFunc(b.IssuePath, ap.issue)
		if fault == "publish-agent-keys" {
			mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
				key := publicJWK(suite.Fixture.APSeed)
				key["kid"] = suite.Fixture.Kid
				writeJSON(w, 200, map[string]any{"keys": []any{key, publicJWK(b.Seeds["durable"])}})
			})
		}
		server := httptest.NewServer(mux)
		defer server.Close()
		stages, _, own, err := bootstrapSelfCase(context.Background(), suite.Fixture, b, s, Ready{Version: 1, URL: server.URL + "/.well-known/aauth-agent.json"}, Options{Timeout: 2 * time.Second})
		return gradeAll(s, stages, own, err)
	}
	for _, s := range roleScenarios(suite, BootstrapSelfHostedRole) {
		if bad := failing(run("", s)); len(bad) > 0 {
			t.Errorf("%s against the reference: %v", s.ID, bad)
		}
	}
	for fault, id := range map[string]string{"nested": "bootstrap-self-subagent-nested", "publish-agent-keys": "bootstrap-self-many-agents"} {
		for _, s := range roleScenarios(suite, BootstrapSelfHostedRole) {
			if s.ID == id && len(failing(run(fault, s))) == 0 {
				t.Errorf("fault %s passed %s", fault, id)
			}
		}
	}
}

// referenceAgent is a test Agent written to the adapter contract: it enrolls
// a durable key, refreshes through jkt-jwt with a fresh ephemeral key, and
// signs a sub-agent request or a Resource call with the issued token.
type referenceAgent struct {
	f           Fixture
	b           BootstrapFixture
	apTransport string
	fault       string
	ephemerals  int
	key         string
	token       string
}

func (a *referenceAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var job map[string]any
	json.NewDecoder(r.Body).Decode(&job)
	durable := strings.Repeat("31", 32)
	send := func(transport string) func(*requestRecord, error) (Response, error) {
		return func(record *requestRecord, err error) (Response, error) {
			if err != nil {
				return Response{}, err
			}
			return Exchange(r.Context(), record.request, transport, 2*time.Second)
		}
	}
	covered := eventsCovered(true)
	if a.fault == "no-digest" {
		covered = eventsCovered(false)
	}
	var response Response
	var err error
	switch job["operation"] {
	case "enroll":
		response, err = send(a.apTransport)(signEventsRequest(a.f, "enroll", durable, http.MethodPost, a.f.Issuer+a.b.EnrollmentPath, sigkeyMember("sig", "hwk", sigkeyHWKParams(publicJWK(durable))...), []byte(`{}`), covered))
	case "refresh":
		if a.fault != "reuse-ephemeral" || a.key == "" {
			a.ephemerals++
			a.key = strings.Repeat(fmt.Sprintf("%02x", 0x40+a.ephemerals), 32)
		}
		naming := namingJWT(a.f, durable, a.key, "", fmt.Sprintf("naming-%d", a.ephemerals), "none")
		body, _ := json.Marshal(map[string]string{"ps": a.f.Person.Issuer})
		response, err = send(a.apTransport)(signEventsRequest(a.f, "refresh", a.key, http.MethodPost, a.f.Issuer+a.b.RefreshPath, `sig=jkt-jwt;jwt="`+naming+`"`, body, covered))
		if err == nil {
			a.token, _ = issuedToken(&response)
		}
	case "subagent":
		body, _ := json.Marshal(map[string]any{"jwk": job["jwk"], "discriminator": job["discriminator"]})
		response, err = send(a.apTransport)(signEventsRequest(a.f, "subagent", a.key, http.MethodPost, a.f.Issuer+a.b.SubagentPath, `sig=jwt;jwt="`+a.token+`"`, body, covered))
	case "call":
		response, err = send(job["transport"].(string))(signEventsRequest(a.f, "call", a.key, http.MethodGet, job["url"].(string), `sig=jwt;jwt="`+a.token+`"`, nil, eventsCovered(false)))
	}
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": response.Status})
}

// Catches an Agent oracle that fails a correct Agent, or one that passes an
// Agent reusing an ephemeral key or leaving its body uncovered.
func TestBootstrapAgentScenariosAgainstReferenceAgent(t *testing.T) {
	suite, b := bootstrapTestSuite(t)
	run := func(fault string, s Scenario) []Result {
		harness, err := prepareBootstrapAgent(suite.Fixture, b, s)
		if err != nil {
			t.Fatal(err)
		}
		defer harness.close()
		agent := &referenceAgent{f: suite.Fixture, b: b, apTransport: harness.config().APTransport, fault: fault}
		server := httptest.NewServer(agent)
		defer server.Close()
		stages, _, own, err := harness.run(context.Background(), Ready{Version: 1, URL: server.URL + "/control"}, Options{Timeout: 2 * time.Second})
		return gradeAll(s, stages, own, err)
	}
	for _, s := range roleScenarios(suite, BootstrapAgentRole) {
		if bad := failing(run("", s)); len(bad) > 0 {
			t.Errorf("%s against the reference Agent: %v", s.ID, bad)
		}
	}
	for fault, id := range map[string]string{"reuse-ephemeral": "bootstrap-agent-rotate", "no-digest": "bootstrap-agent-refresh"} {
		for _, s := range roleScenarios(suite, BootstrapAgentRole) {
			if s.ID == id && len(failing(run(fault, s))) == 0 {
				t.Errorf("fault %s passed %s", fault, id)
			}
		}
	}
}

// Catches a naming-JWT reader that accepts what the jkt-jwt scheme refuses.
func TestBootstrapNamingJWTOracle(t *testing.T) {
	suite, b := bootstrapTestSuite(t)
	f := suite.Fixture
	if o := readNamingJWT(f, namingJWT(f, b.Seeds["durable"], b.Seeds["ephemeral"], b.Seeds["other_durable"], "n", "none")); !o.Valid || !bytes.Equal(o.delegated, seedPublic(b.Seeds["ephemeral"])) {
		t.Fatalf("valid naming JWT refused: %s", o.Error)
	}
	for _, mutation := range []string{"jkt-iss", "jkt-typ", "jkt-signature", "jkt-expired"} {
		if o := readNamingJWT(f, namingJWT(f, b.Seeds["durable"], b.Seeds["ephemeral"], b.Seeds["other_durable"], "n", mutation)); o.Valid {
			t.Errorf("%s accepted", mutation)
		}
	}
}

// A full run with both libraries declared unavailable reports every
// Bootstrap assertion not claimed, with the reason, and no execution error.
func TestBootstrapRolesReportUnavailableTargets(t *testing.T) {
	suite, _ := bootstrapTestSuite(t)
	for _, role := range []string{BootstrapProviderRole, BootstrapAgentRole, BootstrapSelfHostedRole} {
		targets := Targets{Version: 1, Role: role, Implementations: []Target{{ID: "absent", Revision: "test", Unavailable: "no launcher"}}}
		report, err := RunSuite(context.Background(), suite, targets, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, run := range report.Runs {
			for _, c := range run.Cases {
				for _, r := range c.Results {
					if r.State != "not_claimed" || r.Detail != "no launcher" || c.Error != "" {
						t.Fatalf("%s %s: %+v", role, c.ID, r)
					}
				}
			}
		}
		if len(report.Runs) != 1 || len(report.Runs[0].Cases) != len(roleScenarios(suite, role)) {
			t.Fatalf("%s: %d runs", role, len(report.Runs))
		}
	}
}
