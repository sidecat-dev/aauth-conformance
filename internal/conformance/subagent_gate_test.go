package conformance

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
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

// A different 4xx or a different parameter error must fail the wire scenario,
// even when revocation withholds all credentials. These are HTTP runner fixtures,
// not native PS/AS conformance evidence.
func TestSubagentRevocationScenariosRequireExactStatusAndCode(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"subagent-revoked-binding", "subagent-revoked-pending"} {
		var scenario Scenario
		for _, s := range suite.Scenarios {
			if s.ID == id {
				scenario = s
			}
		}
		if scenario.ID == "" {
			t.Fatalf("missing scenario %s", id)
		}
		for _, reply := range []struct {
			name       string
			status     int
			code       string
			credential bool
			want       bool
		}{
			{"exact", 400, "revoked_presented_token", false, true},
			{"wrong-forbidden-status", 403, "revoked_presented_token", false, false},
			{"wrong-unauthorized-status", 401, "revoked_presented_token", false, false},
			{"wrong-denial-code", 400, "denied", false, false},
			{"wrong-expiry-code", 400, "expired_presented_token", false, false},
			{"missing-code", 400, "", false, false},
			{"unexpected-credential", 400, "revoked_presented_token", true, false},
		} {
			t.Run(id+"/"+reply.name, func(t *testing.T) {
				result := runRevokedSubagentHTTPFixture(t, suite, scenario, reply.status, reply.code, reply.credential)
				if result.Error != "" {
					t.Fatalf("fixture execution failed: %s", result.Error)
				}
				passed := len(result.Results) > 0
				for _, a := range result.Results {
					passed = passed && a.State == "pass"
				}
				if passed != reply.want {
					t.Fatalf("status %d error %q: all assertions pass=%v, want %v; results=%+v", reply.status, reply.code, passed, reply.want, result.Results)
				}
			})
		}
	}
}

func runRevokedSubagentHTTPFixture(t *testing.T, suite Suite, scenario Scenario, status int, code string, credential bool) Case {
	t.Helper()
	f := suite.Fixture
	person, err := mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": f.Person.Subject, "jti": "revocation-fixture-person", "cnf": map[string]any{"jwk": publicJWK(childSeed)}, "iat": f.Now, "exp": f.Now + 60})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := mintJWT(f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt", map[string]any{"iss": f.Origin, "dwk": "aauth-resource.json", "aud": f.Access.Issuer, "ps": f.Person.Issuer, "sub": f.Person.Subject, "presented_jti": "revocation-fixture-person", "agent_jkt": thumbprint(childSeed), "scope": "read", "jti": "revocation-fixture-resource", "iat": f.Now, "exp": f.Now + 120})
	if err != nil {
		t.Fatal(err)
	}
	relay := &deferredRelay{fixture: f, timeout: time.Second}
	relayServer := httptest.NewServer(relay)
	defer relayServer.Close()
	var revoked atomic.Bool
	var parent atomic.Value
	parent.Store("")
	pending := func(w http.ResponseWriter, issuer string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", issuer+"/token/pending/revocation-fixture")
		w.Header().Set("Retry-After", "0")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(202)
		io.WriteString(w, `{"status":"pending"}`)
	}
	refusal := func(w http.ResponseWriter) {
		body := map[string]any{}
		if code != "" {
			body["error"] = code
		}
		if credential {
			body["auth_token"] = "forbidden-credential"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "https://"+r.Host == f.Access.Issuer {
			pending(w, f.Access.Issuer)
			return
		}
		switch r.URL.Path {
		case "/__fixture/subagent":
			var command struct {
				Revoke bool `json:"revoke"`
			}
			if json.NewDecoder(r.Body).Decode(&command) != nil {
				http.Error(w, "bad fixture control", 400)
				return
			}
			if command.Revoke {
				revoked.Store(true)
			}
			w.WriteHeader(204)
		case "/person":
			parent.Store(r.Header.Get("Signature-Key"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"person_token": person, "expires_in": 60})
		case f.Path:
			w.Header().Set("AAuth-Requirement", `requirement=auth-token;resource-token="`+resource+`"`)
			w.WriteHeader(401)
		case "/token":
			if revoked.Load() {
				refusal(w)
				return
			}
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				http.Error(w, "bad fixture token body", 400)
				return
			}
			input["agent_token"] = strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Signature-Key"), `sig=jwt;jwt="`), `"`)
			body, _ := json.Marshal(input)
			request, _, err := signedFixtureRequest(f, f.Person.Seed, "POST", f.Access.Issuer+"/token", fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-person.json";kid=%q`, f.Person.Issuer, f.Person.Kid), body)
			if err != nil {
				t.Error(err)
				http.Error(w, "fixture sign failed", 500)
				return
			}
			response, err := Exchange(r.Context(), request, relayServer.URL, time.Second)
			if err != nil || response.Status != 202 {
				t.Errorf("fixture AS exchange: status %d error %v", response.Status, err)
				http.Error(w, "fixture AS failed", 500)
				return
			}
			pending(w, f.Person.Issuer)
		case "/token/pending/revocation-fixture":
			if r.Header.Get("Signature-Key") != parent.Load().(string) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				io.WriteString(w, `{"error":"wrong_poller"}`)
				return
			}
			if revoked.Load() {
				refusal(w)
				return
			}
			pending(w, f.Person.Issuer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result := runSubagentCase(context.Background(), f, scenario, Target{Claims: Claims(suite, SubagentRole)}, server.URL, Options{Timeout: time.Second}, relay, nil)
	if !revoked.Load() {
		t.Fatal("driver did not exercise parent binding revocation")
	}
	return result
}

// The depth scenario must reach the grandchild parameter guard with a valid
// top-level signing Agent; child-direct separately covers the signer role guard.
func TestSubagentDepthPresentsGrandchildFromTopLevelParent(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	f := suite.Fixture
	var scenario Scenario
	for _, s := range suite.Scenarios {
		if s.ID == "subagent-depth" {
			scenario = s
		}
	}
	var input map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("missing HTTP body")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"invalid_subagent_token"}`)
	}))
	defer server.Close()
	result := runSubagentCase(context.Background(), f, scenario, Target{Claims: Claims(suite, SubagentRole)}, server.URL, Options{Timeout: time.Second}, &deferredRelay{fixture: f, timeout: time.Second}, nil)
	if result.Error != "" || len(result.Exchanges) != 1 {
		t.Fatalf("depth fixture execution: %q exchanges %d", result.Error, len(result.Exchanges))
	}
	exchange := result.Exchanges[0]
	compact := strings.TrimSuffix(strings.TrimPrefix(exchange.Headers.Get("Signature-Key"), `sig=jwt;jwt="`), `"`)
	_, parent, err := verifyJWT(compact, f.APSeed, f.Kid, "aa-agent+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if parent["sub"] != f.Subject {
		t.Fatalf("depth used a different signing parent: %v", parent["sub"])
	}
	if _, childSigner := parent["parent_agent"]; childSigner {
		t.Fatal("depth still repeats child-signed endpoint refusal")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(exchange.Headers.Get("Signature"), "sig=:"), ":"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(f.AgentSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), []byte(exchange.SignatureBase), raw) {
		t.Fatal("request did not use the top-level parent's signing key")
	}
	_, grandchild, err := verifyJWT(input["subagent_token"], f.APSeed, f.Kid, "aa-agent+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if grandchild["sub"] != "aauth:Agent+child+grandchild@ap.conformance.test" || grandchild["parent_agent"] != "aauth:Agent+child@ap.conformance.test" {
		t.Fatalf("depth did not submit a grandchild: sub %v parent %v", grandchild["sub"], grandchild["parent_agent"])
	}
	for _, a := range result.Results {
		if a.State != "pass" {
			t.Fatalf("correct grandchild refusal failed: %+v", a)
		}
	}
}
