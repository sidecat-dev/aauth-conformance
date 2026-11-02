package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

// Catches a rebased fixture that keeps a deployed role's fixture identity, or
// that hands the harness Person Server's identity to the deployment.
func TestRemoteFixtureRebasesOnlyDeployedRoles(t *testing.T) {
	suite := loadSuite(t)
	r := RemoteRole{Resource: "https://records.example/v1/records", PersonServer: "https://ps.example", AccessServer: "https://as.example"}
	published := map[string]keySet{partyPerson: {"p": nil}, partyAccess: {"a": nil}, partyResource: {"r": nil}}
	native := Scenario{Federated: &FederatedSpec{Mutation: "none"}}
	f := r.fixture(suite.Fixture, native, published, 3)
	if f.Origin != "https://records.example" || f.Path != "/v1/records" || f.Person.Issuer != "https://ps.example" || f.Access.Issuer != "https://as.example" || f.Issuer != suite.Fixture.Issuer {
		t.Fatalf("identities %s %s %s %s %s", f.Origin, f.Path, f.Person.Issuer, f.Access.Issuer, f.Issuer)
	}
	_, person := f.Person.keys()["p"]
	_, resource := f.Person.resourceKeys()["r"]
	_, access := f.Access.keys()["a"]
	if !person || !resource || !access || f.Skew != 3 || time.Now().Unix()-f.Now > 1 {
		t.Fatalf("keys or clock not rebased: %+v", f)
	}
	harness := r.fixture(suite.Fixture, Scenario{Federated: &FederatedSpec{Mutation: "none", HarnessPS: true}}, published, 3)
	if harness.Person.Issuer != suite.Fixture.Person.Issuer || harness.Person.Published != nil {
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
	keys, err := publishedKeys(ctx, suite.Fixture.Person.Issuer, "aauth-person.json", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !keys["ps-1"].Equal(fixtureKeys(suite.Fixture.Person.Seed, "ps-1")["ps-1"]) || len(keys) != 1 {
		t.Fatalf("%v", keys)
	}
	if _, err := publishedKeys(ctx, suite.Fixture.Origin, "aauth-agent.json", time.Second); err == nil {
		t.Fatal("Resource name served Agent Provider metadata")
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
	if len(reports) != 1 || reports[0].Transport != "remote" || len(reports[0].Runs[0].Cases) != 6 || reports[0].Runs[0].Target.Remote["resource"] != d.Roles[ResourceRole].Resource {
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
