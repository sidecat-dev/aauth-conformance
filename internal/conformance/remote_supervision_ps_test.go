package conformance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Catches supervised Person Server scenarios that need a host control being
// run without one, scenarios that need none being dropped, or a supervisor
// name the suite does not serve.
func TestRemoteSupervisionPSGapsNameTheControl(t *testing.T) {
	suite := loadSuite(t)
	selected, _ := suite.ForRole(SupervisionPersonServerRole)
	driver := remoteDrivers[SupervisionPersonServerRole]
	gapped := []string{}
	for _, s := range selected.Scenarios {
		if reason := driver.gap(s, RemoteRole{PersonServer: "https://ps.example"}); reason != "" {
			if !strings.Contains(reason, supervisionControlPath) {
				t.Fatalf("%s: %q", s.ID, reason)
			}
			gapped = append(gapped, s.ID)
		}
		if driver.gap(s, RemoteRole{PersonServer: "https://ps.example", Control: "https://control.example/ps"}) != "" {
			t.Fatalf("%s not run with a control", s.ID)
		}
	}
	slices.Sort(gapped)
	if strings.Join(gapped, " ") != "supervision.ps-ask supervision.ps-deferred supervision.ps-server-error" {
		t.Fatalf("gapped %v", gapped)
	}
	names := strings.Join(HarnessNames(suite.Fixture), " ")
	for _, want := range []string{"ss.conformance.test", "foreign-ss.conformance.test"} {
		if !strings.Contains(names, want) {
			t.Fatalf("%s is not served: %s", want, names)
		}
	}
	documents := HarnessDocuments(suite.Fixture)
	if _, served := documents["https://ss.conformance.test/.well-known/aauth-supervisor.json"]; served {
		t.Fatal("the supervisor's fixed document would hide the per-case harness")
	}
	if _, served := documents["https://foreign-ss.conformance.test/.well-known/aauth-supervisor.json"]; !served {
		t.Fatal("the foreign supervisor publishes no keys")
	}
}

// Catches a long-running Person Server's late report of another case's act
// being graded, or a case that made no connect failing its connect
// assertions when the run's first case connected.
func TestRemoteSupervisionPSGradesItsOwnEventsAndTheRunsConnect(t *testing.T) {
	request := func(kind, body string) SSRequest {
		return SSRequest{Kind: kind, Request: Captured{Body: []byte(body)}}
	}
	run := &remotePSSupervisor{}
	first := run.graded([]SSRequest{request("connect", `{"action":"connect"}`), request("decision", `{"sdi":"d-1"}`), request("event:person_token.issued", `{"sdi":"d-1"}`)})
	if len(first) != 3 || run.connect == nil {
		t.Fatalf("first case %v", first)
	}
	second := run.graded([]SSRequest{
		request("event:decision.resolved", `{"sdi":"d-1"}`), request("decision", `{"sdi":"d-2"}`),
		request("event:person_token.issued", `{"sdi":"d-2"}`), request("event:agent.bound", `{}`), request("report:approved", `{"sdi":"d-0"}`),
	})
	kinds := []string{}
	for _, r := range second {
		object, _ := jsonObject(r.Request.Body)
		sdi, _ := object["sdi"].(string)
		kinds = append(kinds, r.Kind+"/"+sdi)
	}
	if strings.Join(kinds, " ") != "connect/ decision/d-2 event:person_token.issued/d-2 event:agent.bound/" {
		t.Fatalf("second case graded on %v", kinds)
	}
}

// Catches a remote run that reaches the Person Server at fixed paths, posts
// host controls anywhere but the deployment's control, does not name the
// held act to the control, or grades without a control what needs one.
func TestRemoteSupervisionPSRunUsesMetadataAndNamesTheHeldAct(t *testing.T) {
	suite := loadSuite(t)
	var mu sync.Mutex
	seen, controls := []string{}, []map[string]any{}
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": publicJWK(suite.Fixture.Person.Seed)["x"]}}}
	metadata := map[string]any{"issuer": "https://ps.example", "jwks_uri": "https://ps.example/jwks", "person_token_endpoint": "https://ps.example/v1/person",
		"auth_token_endpoint": "https://ps.example/v1/token", "mission_endpoint": "https://ps.example/v1/mission"}
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.Host+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/.well-known/aauth-person.json":
			json.NewEncoder(w).Encode(metadata)
		case r.URL.Path == "/jwks":
			json.NewEncoder(w).Encode(jwks)
		case r.Host == "control.example":
			object, _ := jsonObject(body)
			controls = append(controls, object)
			w.Write([]byte(`{}`))
		case r.URL.Path == "/v1/person" && strings.Contains(agentJTI(r.Header), "ps-proposal"):
			// The proposal scenarios need a person token before they propose.
			token, _ := mintJWT(suite.Fixture.Person.Seed, "k1", "aa-person+jwt", map[string]any{"iss": "https://ps.example", "sub": "directed-person-1", "jti": "p-1"})
			json.NewEncoder(w).Encode(map[string]any{"person_token": token, "expires_in": 60})
		default:
			w.Header().Set("Location", "/pending/held-1")
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"status":"pending"}`))
		}
	}), "ps.example", "control.example")
	ctx := WithNetwork(context.Background(), network)
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{SupervisionPersonServerRole: {
		PersonServer: "https://ps.example", Control: "https://control.example/hooks"}}}
	reports, err := RunRemote(ctx, suite, d, RemoteOptions{Timeout: time.Second, Skew: 5})
	if err != nil || reports[0].Runs[0].Error != "" {
		t.Fatal(err, reports[0].Runs[0].Error)
	}
	mu.Lock()
	joined := strings.Join(seen, " ")
	for _, want := range []string{"ps.example/v1/person", "ps.example/v1/mission", "control.example/hooks/__fixture/supervision"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("no request to %s in %v", want, seen)
		}
	}
	if strings.Contains(joined, "ps.example/person ") || strings.Contains(joined, "ps.example/mission ") {
		t.Fatalf("fixed paths used: %v", seen)
	}
	named := 0
	for _, control := range controls {
		if control["resolve"] != nil || control["advance"] != nil {
			if control["pending"] != "https://ps.example/pending/held-1" {
				t.Fatalf("control without the held act: %v", control)
			}
			named++
		} else if control["deliver"] != true || control["pending"] != nil {
			t.Fatalf("unexpected control %v", control)
		}
	}
	mu.Unlock()
	if named != 3 {
		t.Fatalf("%d held acts named to the control: %v", named, controls)
	}

	d.Roles[SupervisionPersonServerRole] = RemoteRole{PersonServer: "https://ps.example"}
	reports, err = RunRemote(ctx, suite, d, RemoteOptions{Timeout: time.Second, Skew: 5})
	if err != nil {
		t.Fatal(err)
	}
	selected, _ := suite.ForRole(SupervisionPersonServerRole)
	for i, c := range reports[0].Runs[0].Cases {
		for j, r := range c.Results {
			member := selected.Scenarios[i].Assertions[j].Member
			needsDelivery := strings.HasPrefix(member, "event:") || strings.HasPrefix(member, "report:")
			if (needsDelivery || strings.HasPrefix(member, "connect")) && r.State != "not_exercised" && r.State != "not_claimed" {
				t.Fatalf("%s/%s graded %s without a control or a connect", c.ID, r.Assertion, r.State)
			}
		}
	}
}

// agentJTI reads the jti of the agent token a signed request carries.
func agentJTI(header http.Header) string {
	_, token, _ := strings.Cut(header.Get("Signature-Key"), `jwt="`)
	parts := strings.Split(strings.TrimSuffix(token, `"`), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		JTI string `json:"jti"`
	}
	json.Unmarshal(payload, &claims)
	return claims.JTI
}
