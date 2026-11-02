package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Catches supervision scenarios that need a host control being run without
// one, or scenarios that need none being dropped.
func TestRemoteSupervisionGapsNameTheControl(t *testing.T) {
	suite := loadSuite(t)
	selected, _ := suite.ForRole(SupervisionServerRole)
	driver := remoteDrivers[SupervisionServerRole]
	gapped := []string{}
	for _, s := range selected.Scenarios {
		if reason := driver.gap(s, RemoteRole{SupervisionServer: "https://ss.example"}); reason != "" {
			if !strings.Contains(reason, supervisionControlPath) {
				t.Fatalf("%s: %q", s.ID, reason)
			}
			gapped = append(gapped, s.ID)
		}
		if driver.gap(s, RemoteRole{SupervisionServer: "https://ss.example", Control: "https://control.example/ss"}) != "" {
			t.Fatalf("%s not run with a control", s.ID)
		}
	}
	if len(gapped) != 2 || gapped[0] != "supervision.ss-deferred" || gapped[1] != "supervision.ss-rate-limited" {
		t.Fatalf("gapped %v", gapped)
	}
	names := HarnessNames(suite.Fixture)
	if !strings.Contains(strings.Join(names, " "), "other-ps.conformance.test") {
		t.Fatalf("the refused Person Server is not served: %v", names)
	}
}

// Catches a rebased supervision fixture that keeps the fixture's issuer,
// fixed paths or seed, or a launcher fixture whose paths changed.
func TestRemoteSupervisionFixtureUsesMetadata(t *testing.T) {
	suite, ss := supervisionSuite(t)
	if ss.endpoint("decision") != ss.Issuer+"/decision" {
		t.Fatalf("launcher endpoint %s", ss.endpoint("decision"))
	}
	server := RemoteServer{Issuer: "https://ss.example", Keys: keySet{"k": publicJWK(ss.Foreign.Seed)}, Metadata: map[string]any{
		"issuer": "https://ss.example", "connect_endpoint": "https://ss.example/v1/connect", "mission_endpoint": "https://ss.example/v1/mission",
		"decision_endpoint": "https://ss.example/v1/decision", "event_endpoint": "http://ss.example/event"}}
	remote, err := remoteSupervisionFixture(suite.Fixture, server)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Issuer != "https://ss.example" || remote.endpoint("decision") != "https://ss.example/v1/decision" || remote.endpoint("event") != "" || remote.Seed != "" || remote.Published["k"] == nil {
		t.Fatalf("%+v", remote)
	}
	values := supervisionPlaceholders(suite.Fixture, remote, "x")
	request, _, err := buildSupervisionStep(suite.Fixture, remote, SupervisionStep{Stage: "m", Endpoint: "mission/$s256", Body: json.RawMessage(`{"sdi":"x"}`)}, values, nil, map[string][]byte{})
	if err != nil || request.URL.String() != "https://ss.example/v1/mission/"+values["$s256"].(string) {
		t.Fatalf("%v %v", request, err)
	}
	if _, _, err := buildSupervisionStep(suite.Fixture, remote, SupervisionStep{Stage: "e", Endpoint: "event", Body: json.RawMessage(`{}`)}, values, nil, map[string][]byte{}); err == nil {
		t.Fatal("sent to an endpoint the metadata does not name over HTTPS")
	}
}

// Catches remote signed-decision checks that fall back to the fixture seed,
// or accept a kid the deployed server does not publish.
func TestRemoteSupervisionSignedDecisionUsesPublishedKeys(t *testing.T) {
	suite, ss := supervisionSuite(t)
	deployed := ss
	deployed.Issuer, deployed.Kid, deployed.Seed = "https://ss.example", "", ""
	deployed.Published = keySet{"deployed-1": publicJWK(ss.Foreign.Seed)}
	body := []byte(`{"sdi":"d-1","act":"permission"}`)
	digest := sha256.Sum256(body)
	request := Captured{Method: "POST", URL: "https://ss.example/decision", Headers: http.Header{
		"Content-Digest":   {"sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"},
		"Accept-Signature": {supervisionAcceptSignature},
	}, Body: body}
	harness := &harnessSupervisor{fixture: suite.Fixture, ss: ss}
	sign := func(seed, kid string) Response {
		status, header, payload := harness.signedDecision(request, map[string]any{"sdi": "d-1", "decision": "allow"}, seed, "https://ss.example", kid, false)
		return Response{Status: status, Header: header, Body: payload}
	}
	if ok, observed := signedDecision(deployed, sign(ss.Foreign.Seed, "deployed-1"), request); !ok {
		t.Fatalf("decision under the published key refused: %+v", observed)
	}
	if ok, _ := signedDecision(deployed, sign(ss.Foreign.Seed, "other"), request); ok {
		t.Fatal("unpublished kid accepted")
	}
	if ok, _ := signedDecision(deployed, sign(ss.Seed, "deployed-1"), request); ok {
		t.Fatal("fixture seed accepted for a deployed server")
	}
	deployed.Published = keySet{}
	if ok, _ := signedDecision(deployed, sign(ss.Foreign.Seed, "deployed-1"), request); ok {
		t.Fatal("signature accepted from a server that publishes no keys")
	}
}

// Catches a remote run that posts host controls anywhere but the
// deployment's control, or reaches the server at fixed paths.
func TestRemoteSupervisionRunUsesControlAndMetadata(t *testing.T) {
	suite := loadSuite(t)
	var mu sync.Mutex
	seen := []string{}
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Host+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/.well-known/aauth-supervisor.json":
			json.NewEncoder(w).Encode(map[string]any{"issuer": "https://ss.example", "connect_endpoint": "https://ss.example/c",
				"mission_endpoint": "https://ss.example/m", "decision_endpoint": "https://ss.example/d", "event_endpoint": "https://ss.example/e"})
		case r.Host == "control.example":
			if !strings.Contains(string(body), "rate_limit") {
				w.WriteHeader(http.StatusBadRequest)
			}
			w.Write([]byte(`{"rate_limited":true}`))
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	}), "ss.example", "control.example")
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{SupervisionServerRole: {
		SupervisionServer: "https://ss.example", Control: "https://control.example/hooks"}}}
	reports, err := RunRemote(WithNetwork(context.Background(), network), suite, d, RemoteOptions{Timeout: time.Second, Skew: 5})
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].Runs[0].Error != "" {
		t.Fatal(reports[0].Runs[0].Error)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(seen, " ")
	for _, want := range []string{"ss.example/c", "ss.example/d", "ss.example/m/", "ss.example/e", "control.example/hooks/__fixture/supervision"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("no request to %s in %v", want, seen)
		}
	}
	if strings.Contains(joined, "ss.example/decision") || strings.Contains(joined, "ss.example/connect") {
		t.Fatalf("fixed paths used: %v", seen)
	}
	for _, c := range reports[0].Runs[0].Cases {
		for _, r := range c.Results {
			if r.State == "not_exercised" && !strings.Contains(r.Detail, "jwks_uri") {
				t.Fatalf("%s/%s not exercised: %s", c.ID, r.Assertion, r.Detail)
			}
		}
	}
}
