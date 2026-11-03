package conformance

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnrollAgentSignsWithTheDurableKeyAndPresentsTheRefreshedToken(t *testing.T) {
	seed := strings.Repeat("02", 32)
	now := time.Now().Unix()
	var refresh Captured
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured := Captured{Method: r.Method, URL: "http://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}
		signed := readSignedRequest(captured)
		clock := Fixture{Now: now}
		switch r.URL.Path {
		case "/bootstrap/enroll":
			key := signed.hwkKey()
			if !signed.verifiedBy(clock, key, "content-type", "content-digest") || !signed.coversBody(captured) {
				t.Errorf("enroll proof: %s covered %v", signed.Error, signed.Covered)
				http.Error(w, "signature", http.StatusUnauthorized)
				return
			}
			if !key.Equal(seedKey(seed).Public().(ed25519.PublicKey)) {
				t.Error("enrollment was not signed by the durable key")
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"agent": "aauth:local@ap.example"})
		case "/bootstrap/refresh":
			refresh = captured
			var payload map[string]any
			if json.Unmarshal(body, &payload) != nil || payload["ps"] != "https://ps.example" {
				t.Errorf("refresh body %s", body)
			}
			if signed.Scheme != "jkt-jwt" {
				t.Errorf("refresh scheme %s", signed.Scheme)
			}
			token, err := mintJWT(strings.Repeat("03", 32), "ap", "aa-agent+jwt", map[string]any{
				"iss": "https://ap.example", "sub": "aauth:local@ap.example", "ps": "https://ps.example",
			})
			if err != nil {
				t.Fatal(err)
			}
			json.NewEncoder(w).Encode(map[string]string{"agent_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enrolled, err := enrollAgent(context.Background(), server.URL, seed, "https://ps.example", now, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.Agent != "aauth:local@ap.example" || enrolled.Token == "" || enrolled.PS != "https://ps.example" {
		t.Fatalf("enrolled %+v", enrolled)
	}
	signed := readSignedRequest(refresh)
	if !signed.verifiedBy(Fixture{Now: now}, seedKey(enrolled.Seed).Public().(ed25519.PublicKey), "content-type", "content-digest") {
		t.Fatalf("refresh was not signed by the key the token binds: %s", signed.Error)
	}
}

func TestEnrollAgentRejectsATokenForADifferentPersonServer(t *testing.T) {
	seed := strings.Repeat("04", 32)
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap/enroll" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"agent": "aauth:local@ap.example"})
			return
		}
		token, _ := mintJWT(strings.Repeat("03", 32), "ap", "aa-agent+jwt", map[string]any{"ps": "https://ps.example"})
		json.NewEncoder(w).Encode(map[string]string{"agent_token": token})
	}))
	defer server.Close()
	_, err := enrollAgent(context.Background(), server.URL, seed, "https://other.example", now, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "https://other.example") || !strings.Contains(err.Error(), "https://ps.example") {
		t.Fatalf("error %v", err)
	}
}

func TestEnrollAgentRequiresHTTPSOffLoopback(t *testing.T) {
	_, err := enrollAgent(context.Background(), "http://ap.example", strings.Repeat("02", 32), "", time.Now().Unix(), time.Second)
	if err == nil {
		t.Fatal("http provider accepted")
	}
}

func TestPresentedAgentIsTheEnrolledToken(t *testing.T) {
	f := Fixture{Now: 1800000000, Issuer: "https://ap.conformance.test", Origin: "https://resource.example", Path: "/whoami", Subject: "aauth:Agent@ap.conformance.test", Kid: "ap-1", APSeed: strings.Repeat("01", 32), AgentSeed: strings.Repeat("02", 32)}
	enrolled := &EnrolledAgent{Provider: "https://ap.example", Agent: "aauth:local@ap.example", Token: "enrolled.token.value", Seed: strings.Repeat("05", 32), PS: "https://ps.example"}
	f = presentEnrolled(f, enrolled)
	token, err := MintToken(f, TokenSpec{IATOffset: -10, EXPOffset: 300}, "valid")
	if err != nil || token != enrolled.Token {
		t.Fatalf("token %q err %v", token, err)
	}
	request, _, err := BuildRequest(f, Scenario{ID: "valid", Token: TokenSpec{IATOffset: -10, EXPOffset: 300}, Request: RequestSpec{Method: "GET", Path: "/whoami", Proof: "jwt", Covered: []string{"@method", "@authority", "@path", "signature-key"}}})
	if err != nil {
		t.Fatal(err)
	}
	signed := readSignedRequest(Captured{Method: request.Method, URL: request.URL.String(), Headers: request.Header})
	if !signed.verifiedBy(f, seedKey(enrolled.Seed).Public().(ed25519.PublicKey)) {
		t.Fatalf("HTTP signature is not the enrolled key: %s", signed.Error)
	}
	if _, err := MintToken(f, TokenSpec{IATOffset: -300, EXPOffset: -1}, "expired"); err == nil {
		t.Fatal("expired scenario reused the enrolled token")
	}
}

func TestEnrolledGapSkipsATokenTheProviderCannotSign(t *testing.T) {
	if enrolledGap(Scenario{ID: "ps-valid", Token: TokenSpec{EXPOffset: 600}}) != "" {
		t.Fatal("ordinary scenario gapped")
	}
	if enrolledGap(Scenario{ID: "supervision-ps-allow"}) != "" {
		t.Fatal("a scenario with no token lifetime was gapped")
	}
	if enrolledGap(Scenario{ID: "expired", Token: TokenSpec{EXPOffset: -1}}) == "" {
		t.Fatal("expired scenario presented")
	}
	if enrolledGap(Scenario{ID: "ps-short-parent", Person: &PersonSpec{Mutation: "short-parent"}, Token: TokenSpec{EXPOffset: 600}}) == "" {
		t.Fatal("short parent presented")
	}
	if enrolledGap(Scenario{ID: "federated-short-agent", Federated: &FederatedSpec{Mutation: "short-agent"}, Token: TokenSpec{EXPOffset: 600}}) == "" {
		t.Fatal("short agent presented")
	}
}

func TestTrustTargetsAreThePersonServersTheSuiteAgentCalls(t *testing.T) {
	d := Deployment{Roles: map[string]RemoteRole{
		PersonServerRole:      {PersonServer: "https://ps.example"},
		FederatedRole:         {PersonServer: "https://fps.example"},
		ResourceRole:          {Resource: "https://api.example/whoami"},
		EventsAgentRole:       {Agent: "aauth:agent@eap.example"},
		SupervisionServerRole: {SupervisionServer: "https://ss.example"},
	}}
	got := trustTargets(d)
	want := map[string]bool{"": true, "https://ps.example": true, "https://fps.example": true}
	if len(got) != len(want) {
		t.Fatalf("targets %v", got)
	}
	for ps := range want {
		if _, ok := got[ps]; !ok {
			t.Fatalf("missing %q in %v", ps, got)
		}
	}
}

func TestPresentedSubjectFollowsTheEnrolledAgent(t *testing.T) {
	f := Fixture{Subject: "aauth:Agent@ap.conformance.test", Enrolled: &EnrolledAgent{Agent: "aauth:local@ap.example"}}
	raw, _ := json.Marshal(f.Subject)
	got := presentedSubject(f, Assertion{Kind: "json-member", Member: "sub", Equals: raw})
	var subject string
	if json.Unmarshal(got.Equals, &subject) != nil || subject != f.Enrolled.Agent {
		t.Fatalf("subject %s", got.Equals)
	}
	other, _ := json.Marshal("directed-person-1")
	kept := presentedSubject(f, Assertion{Kind: "json-member", Member: "sub", Equals: other})
	if string(kept.Equals) != string(other) {
		t.Fatal("person subject rewritten")
	}
}
