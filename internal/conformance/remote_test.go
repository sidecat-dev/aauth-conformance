package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServer serves handler over TLS with a certificate for names, and
// returns a Network that reaches each name's port 443 there.
func testServer(t *testing.T, handler http.Handler, names ...string) *Network {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	network := &Network{Roots: x509.NewCertPool(), Resolve: map[string]string{}}
	network.Roots.AddCert(certificate)
	for _, name := range names {
		network.Resolve[name+":443"] = server.Listener.Addr().String()
	}
	return network
}

func loadSuite(t *testing.T) Suite {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

// Catches a deployment the drafts' identifier rules or the role's needs reject.
func TestValidateDeploymentRefusesUnusableServers(t *testing.T) {
	suite := loadSuite(t)
	valid := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{
		ResourceRole:  {Resource: "https://api.example/whoami"},
		FederatedRole: {Resource: "https://records.example/records", AccessServer: "https://as.example"},
	}}
	if err := ValidateDeployment(valid, suite); err != nil {
		t.Fatal(err)
	}
	for name, role := range map[string]RemoteRole{
		"missing access server": {Resource: "https://records.example/records"},
		"port":                  {Resource: "https://records.example/records", AccessServer: "https://as.example:8443"},
		"path":                  {Resource: "https://records.example/records", AccessServer: "https://as.example/v1"},
		"uppercase":             {Resource: "https://records.example/records", AccessServer: "https://AS.example"},
		"suite name":            {Resource: "https://records.example/records", AccessServer: "https://ap.conformance.test"},
		"resource query":        {Resource: "https://records.example/records?x=1", AccessServer: "https://as.example"},
		"unknown claim":         {Resource: "https://records.example/records", AccessServer: "https://as.example", Claims: []string{"core.agent-identity"}},
	} {
		d := valid
		d.Roles = map[string]RemoteRole{FederatedRole: role}
		if ValidateDeployment(d, suite) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := valid
	d.Roles = map[string]RemoteRole{AgentRole: {Resource: "https://api.example/whoami"}}
	if err := ValidateDeployment(d, suite); err == nil || !strings.Contains(err.Error(), "cannot run") {
		t.Fatalf("Agent role accepted: %v", err)
	}
}

func TestValidateDeploymentRequiresProviderMapEntriesToBeOrigins(t *testing.T) {
	suite := loadSuite(t)
	d := Deployment{Version: 1, ID: "impl", Revision: "v1",
		BootstrapProviders: map[string]string{"https://ps.example": "https://ap.example"},
		Roles:              map[string]RemoteRole{PersonServerRole: {PersonServer: "https://ps.example"}},
	}
	if err := ValidateDeployment(d, suite); err != nil {
		t.Fatal(err)
	}
	d.BootstrapProviders = map[string]string{"ps.example": "https://ap.example"}
	if err := ValidateDeployment(d, suite); err == nil || !strings.Contains(err.Error(), "bootstrap_providers") {
		t.Fatalf("bad key: %v", err)
	}
	d.BootstrapProviders = map[string]string{"https://ps.example": "http://ap.example"}
	if err := ValidateDeployment(d, suite); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http provider: %v", err)
	}
}

// Catches a rebased fixture that keeps a deployed role's fixture identity, or
// that hands the harness Person Server's identity to the deployment.
func TestRemoteFixtureRebasesOnlyDeployedRoles(t *testing.T) {
	suite := loadSuite(t)
	r := RemoteRole{Resource: "https://records.example/v1/records", PersonServer: "https://ps.example", AccessServer: "https://as.example"}
	published := map[string]keySet{partyPerson: {"p": nil}, partyAccess: {"a": nil}, partyResource: {"r": nil}}
	native := Scenario{Federated: &FederatedSpec{Mutation: "none"}}
	endpoints := personEndpoints{person: "https://ps.example/v1/person", token: "https://ps.example/v1/token"}
	f := r.fixture(suite.Fixture, native, published, endpoints, 3)
	if f.Origin != "https://records.example" || f.Path != "/v1/records" || f.Person.Issuer != "https://ps.example" || f.Access.Issuer != "https://as.example" || f.Issuer != suite.Fixture.Issuer {
		t.Fatalf("identities %s %s %s %s %s", f.Origin, f.Path, f.Person.Issuer, f.Access.Issuer, f.Issuer)
	}
	_, person := f.Person.keys()["p"]
	_, resource := f.Person.resourceKeys()["r"]
	_, access := f.Access.keys()["a"]
	if !person || !resource || !access || f.Skew != 3 || time.Now().Unix()-f.Now > 1 {
		t.Fatalf("keys or clock not rebased: %+v", f)
	}
	if f.Person.personURL() != endpoints.person || f.Person.tokenURL() != endpoints.token {
		t.Fatalf("endpoints not rebased: %s %s", f.Person.personURL(), f.Person.tokenURL())
	}
	harness := r.fixture(suite.Fixture, Scenario{Federated: &FederatedSpec{Mutation: "none", HarnessPS: true}}, published, endpoints, 3)
	if harness.Person.Issuer != suite.Fixture.Person.Issuer || harness.Person.Published != nil || harness.Person.personURL() != suite.Fixture.Person.Issuer+"/person" {
		t.Fatalf("harness Person Server rebased: %+v", harness.Person)
	}
	if suite.Fixture.Person.Issuer == "https://ps.example" || suite.Fixture.Access.Published != nil {
		t.Fatal("rebasing changed the suite fixture")
	}
}

// Catches scenarios that need a private key or a relay being run, or graded
// as failures, instead of being reported as not exercised.
func TestRemoteGapsAreNotExercisedWithReasons(t *testing.T) {
	suite := loadSuite(t)
	run := map[string][]string{}
	for _, role := range []string{PersonServerRole, FederatedRole} {
		selected, _ := suite.ForRole(role)
		for _, s := range selected.Scenarios {
			if remoteDrivers[role].gap(s, RemoteRole{PersonServer: "https://ps.example"}) == "" {
				run[role] = append(run[role], s.ID)
			}
		}
	}
	if len(run[PersonServerRole]) != 11 || slices.ContainsFunc(run[PersonServerRole], func(id string) bool { return strings.Contains(id, "expired-presented") }) {
		t.Fatalf("Person Server scenarios run remotely: %v", run[PersonServerRole])
	}
	if len(run[FederatedRole]) != 7 {
		t.Fatalf("four-party scenarios run remotely: %v", run[FederatedRole])
	}
	scenario := Scenario{ID: "x", Assertions: []Assertion{{ID: "a", Clause: "c1", Stage: "access"}, {ID: "b", Clause: "c2", Stage: "token"}, {ID: "c", Clause: "c3", Stage: "handoff"}}}
	c := unexercisedCase(scenario, Target{Claims: []string{"c1", "c2"}}, "why")
	if c.Results[0].State != "not_exercised" || c.Results[0].Detail != "why" || c.Results[2].State != "not_claimed" {
		t.Fatalf("%+v", c.Results)
	}
	c.Results = []Result{{State: "error"}, {State: "pass"}, {State: "not_claimed"}}
	markUnobserved(&c, scenario, []string{"access", "handoff"}, "unseen")
	if c.Results[0].State != "not_exercised" || c.Results[1].State != "pass" || c.Results[2].State != "not_claimed" {
		t.Fatalf("%+v", c.Results)
	}
}

// Catches the suite's party documents being unreachable by name over TLS, or
// discovery accepting a server's metadata for another issuer.
func TestHarnessDocumentsAreDiscoverableOverTLS(t *testing.T) {
	suite := loadSuite(t)
	network := testServer(t, HarnessHandler(suite.Fixture), "ap.conformance.test", "person.conformance.test", "resource.conformance.test")
	ctx := WithNetwork(context.Background(), network)
	keys, _, err := publishedKeys(ctx, suite.Fixture.Person.Issuer, "aauth-person.json", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(keys["ps-1"], fixtureKeys(suite.Fixture.Person.Seed, "ps-1")["ps-1"]) || len(keys) != 1 {
		t.Fatalf("%v", keys)
	}
	if _, _, err := publishedKeys(ctx, suite.Fixture.Origin, "aauth-agent.json", time.Second); err == nil {
		t.Fatal("Resource name served Agent Provider metadata")
	}
}

// Catches remote mode posting to fixed paths instead of the endpoints a
// deployed Person Server advertises, or accepting metadata without them.
func TestRemotePersonServerEndpointsComeFromMetadata(t *testing.T) {
	suite := loadSuite(t)
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": publicJWK(suite.Fixture.Person.Seed)["x"]}}}
	metadata := map[string]any{"issuer": "https://ps.example", "jwks_uri": "https://ps.example/jwks",
		"person_token_endpoint": "https://ps.example/person-token", "auth_token_endpoint": "https://ps.example/v1/token"}
	serve := func(document map[string]any) *Network {
		return testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := document
			if r.URL.Path == "/jwks" {
				body = jwks
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(body)
		}), "ps.example")
	}
	r := RemoteRole{PersonServer: "https://ps.example"}
	documents := remoteDrivers[PersonServerRole].discover
	_, endpoints, err := discoverRemote(WithNetwork(context.Background(), serve(metadata)), r, documents, time.Second)
	if err != nil || endpoints.person != "https://ps.example/person-token" || endpoints.token != "https://ps.example/v1/token" {
		t.Fatalf("%+v %v", endpoints, err)
	}
	for _, missing := range []string{"person_token_endpoint", "auth_token_endpoint"} {
		partial := map[string]any{}
		for name, value := range metadata {
			partial[name] = value
		}
		delete(partial, missing)
		if _, _, err := discoverRemote(WithNetwork(context.Background(), serve(partial)), r, documents, time.Second); err == nil {
			t.Fatalf("accepted metadata without %s", missing)
		}
	}
}

// Catches remote exchanges that do not reach the deployed Resource by its
// logical HTTPS name, or that sign with the fixture's fixed clock.
func TestRunRemoteReachesDeployedResourceOverTLS(t *testing.T) {
	suite := loadSuite(t)
	var mu sync.Mutex
	hosts := map[string]bool{}
	created := []string{}
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts[r.Host+r.URL.Path] = true
		created = append(created, r.Header.Get("Signature-Input"))
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}), "api.example")
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{ResourceRole: {Resource: "https://api.example/v1/whoami"}}}
	reports, err := RunRemote(WithNetwork(context.Background(), network), suite, d, RemoteOptions{Timeout: time.Second, Skew: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Transport != "remote" || len(reports[0].Runs[0].Cases) != 9 || reports[0].Runs[0].Target.Remote["resource"] != d.Roles[ResourceRole].Resource {
		t.Fatalf("%+v", reports)
	}
	if len(hosts) != 1 || !hosts["api.example/v1/whoami"] {
		t.Fatalf("requests reached %v", hosts)
	}
	now := time.Now().Unix()
	for _, input := range created {
		_, value, signed := strings.Cut(input, ";created=")
		stamp, _ := strconv.ParseInt(value, 10, 64)
		if signed && (stamp < now-120 || stamp > now+120) {
			t.Fatalf("signed with created=%s, not the current clock", value)
		}
	}
	for _, c := range reports[0].Runs[0].Cases {
		if c.Error != "" {
			t.Fatalf("%s: %s", c.ID, c.Error)
		}
	}
}

// Catches a public grade dialing a host control it does not operate, and
// counting that unexercised role as a failed run.
func TestPublicGradeOmitsHostControlAndDoesNotFailWhenUnexercised(t *testing.T) {
	suite := loadSuite(t)
	hits := 0
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "control was dialed", http.StatusInternalServerError)
	}), "control.example")
	role := RemoteRole{Agent: "aauth:agent@ap.example", Control: "https://control.example/hooks"}
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{EventsAgentRole: role}}
	reports, err := RunRemote(WithNetwork(context.Background(), network), suite, d, RemoteOptions{Timeout: time.Second, Public: true})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("public grade dialed the host control %d times", hits)
	}
	if d.Roles[EventsAgentRole].Control != role.Control {
		t.Fatal("public grade cleared control on the caller's deployment")
	}
	report := reports[0]
	if report.Failed() {
		t.Fatal("unexercised host-control role failed the grade")
	}
	if report.Success() {
		t.Fatal("an unexercised role counted as a pass")
	}
	if report.Execution != "not_exercised" {
		t.Fatalf("execution %s", report.Execution)
	}
	for _, c := range report.Runs[0].Cases {
		if c.Error != "" {
			t.Fatal(c.Error)
		}
		for _, result := range c.Results {
			if result.State != "not_exercised" && result.State != "not_claimed" {
				t.Fatalf("%s graded %s", c.ID, result.State)
			}
		}
	}
}

// Catches treating an assertion error or a case error as a clean grade, and
// treating not_exercised as a failure.
func TestRemoteFailureIsAnAssertionErrorNotAnUnexercisedRole(t *testing.T) {
	report := Report{Runs: []Run{{Cases: []Case{{Results: []Result{{State: "not_exercised"}}}}}}}
	if report.Failed() || report.Success() {
		t.Fatal("not_exercised was a pass or a failure")
	}
	report.Runs[0].Cases[0].Results = []Result{{State: "pass"}, {State: "not_exercised"}}
	if report.Failed() || !report.Success() {
		t.Fatal("a pass beside not_exercised was not a clean pass")
	}
	report.Runs[0].Cases[0].Results = []Result{{State: "error"}}
	if !report.Failed() {
		t.Fatal("assertion error was not a failure")
	}
	report.Runs[0].Cases[0].Results = []Result{{State: "fail"}}
	if !report.Failed() {
		t.Fatal("assertion fail was not a failure")
	}
	report.Runs[0].Cases[0] = Case{Error: "dial tcp: lookup control.example", Results: []Result{{State: "not_exercised"}}}
	if !report.Failed() {
		t.Fatal("case error was not a failure")
	}
}

// Catches a public grade advertising a loopback callback the graded servers
// cannot reach, or refusing a listener on all interfaces.
func TestPublicCallbackRejectsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:18443", "localhost:443", "[::1]:443"} {
		if PublicListen(addr) == nil {
			t.Fatalf("loopback accepted: %s", addr)
		}
	}
	for _, addr := range []string{":443", "0.0.0.0:8443", "203.0.113.5:8443", "[::]:443"} {
		if err := PublicListen(addr); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if PublicListen("not-an-address") == nil {
		t.Fatal("malformed listen accepted")
	}
}

func TestSuitePlaysPersonOnlyInHarnessPersonScenarios(t *testing.T) {
	if !suitePlaysPerson(Scenario{Federated: &FederatedSpec{HarnessPS: true}}) {
		t.Fatal("a harness Person Server scenario presents an enrolled token")
	}
	if suitePlaysPerson(Scenario{Federated: &FederatedSpec{}}) || suitePlaysPerson(Scenario{}) {
		t.Fatal("a deployment Person Server scenario does not present the enrolled token")
	}
}
