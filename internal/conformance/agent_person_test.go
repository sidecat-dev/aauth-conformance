package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Catches a person flow graded on the controller's word: one Agent-token
// request must fail both person assertions, and the full flow must pass,
// also when the Agent reads both metadata documents first. The scenario whose
// Resource publishes no metadata answers that read 404 and grades the same.
func TestPersonFlowGradesThePersonRequestAndTheRetry(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	claims := append(Claims(suite, AgentRole), "agent.person-flow", "agent.resource-metadata-unpublished")
	cases := map[string]bool{"agent-person-flow": false, "agent-person-flow-unpublished-metadata": true}
	for _, test := range []struct {
		mode      string
		pass      bool
		exchanges int
		// published and unpublished are the statuses the Resource metadata
		// read gets in each scenario; 0 when the Agent makes none.
		published, unpublished int
	}{
		{"agent-person", true, 3, 0, 0},
		{"agent-person-discovering", true, 5, http.StatusOK, http.StatusNotFound},
		{"agent-valid", false, 1, 0, 0},
	} {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("AAUTH_TEST_ADAPTER", test.mode)
			targets := Targets{Version: 1, Role: AgentRole, Implementations: []Target{{ID: "test-agent", Revision: "test", Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}, Claims: claims}}}
			report, err := RunSuite(context.Background(), suite, targets, Options{StartupTimeout: time.Second, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for i := range report.Runs[0].Cases {
				flow := &report.Runs[0].Cases[i]
				unpublished, ok := cases[flow.ID]
				if !ok {
					continue
				}
				seen++
				if flow.Error != "" || len(flow.Results) != 2 || len(flow.Exchanges) != test.exchanges {
					t.Fatalf("%s case: %+v", flow.ID, flow)
				}
				for _, result := range flow.Results {
					if (result.State == "pass") != test.pass {
						t.Fatalf("%s %s graded %s: %s", flow.ID, result.Assertion, result.State, result.Detail)
					}
				}
				want := test.published
				if unpublished {
					want = test.unpublished
				}
				for _, exchange := range flow.Exchanges {
					if strings.HasSuffix(exchange.URL, "/.well-known/aauth-resource.json") && exchange.Response.Status != want {
						t.Fatalf("%s: Resource metadata answered %d, want %d", flow.ID, exchange.Response.Status, want)
					}
				}
			}
			if seen != len(cases) {
				t.Fatalf("person flow cases = %d, want %d", seen, len(cases))
			}
		})
	}
}

// Catches a Resource case at the person endpoint that presents anything but
// a fixture Person token for the fixture Resource.
func TestPersonEndpointRequestPresentsAPersonToken(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range suite.Scenarios {
		if scenario.Role != ResourceRole || scenario.Request.Proof != "person" {
			continue
		}
		request, _, err := BuildRequest(suite.Fixture, scenario)
		if err != nil {
			t.Fatal(err)
		}
		_, compact, _ := strings.Cut(request.Header.Get("Signature-Key"), `jwt="`)
		_, claims, err := verifyJWT(strings.TrimSuffix(compact, `"`), suite.Fixture.Person.Seed, suite.Fixture.Person.Kid, "aa-person+jwt")
		if err != nil || claims["aud"] != suite.Fixture.Origin || request.URL.Path != suite.Fixture.PersonPath {
			t.Fatalf("%s: %v %v %s", scenario.ID, err, claims, request.URL)
		}
		return
	}
	t.Fatal("no Resource scenario presents a Person token")
}

// Test-process Agent that follows requirement=person-token through the
// harness Person Server; real launchers use their implementation's Agent.
// A discovering Agent reads the Person Server's and the Resource's metadata
// first and posts to the person_token_endpoint the metadata names.
func runPersonAgentTestProcess(config Bootstrap, discovering bool) {
	sign := func(request *http.Request, token string, body []byte) {
		request.Header.Set("Signature-Key", `sig=jwt;jwt="`+token+`"`)
		components := []string{"@method", "@authority", "@path"}
		if len(body) > 0 {
			sum := sha256.Sum256(body)
			request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
			components = append(components, "content-type", "content-digest")
		}
		components = append(components, "signature-key")
		names, lines := []string{}, []string{}
		for _, name := range components {
			value := request.Header.Get(name)
			switch name {
			case "@method":
				value = request.Method
			case "@authority":
				value = request.URL.Host
			case "@path":
				value = request.URL.EscapedPath()
			}
			names = append(names, fmt.Sprintf("%q", name))
			lines = append(lines, fmt.Sprintf("%q: %s", name, value))
		}
		params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), config.Now)
		lines = append(lines, `"@signature-params": `+params)
		request.Header.Set("Signature-Input", "sig="+params)
		request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(config.AgentSeed), []byte(strings.Join(lines, "\n"))))+":")
	}
	send := func(request *http.Request, transport string) (*http.Response, []byte, error) {
		physical, _ := url.Parse(transport)
		request.Host = request.URL.Host
		request.URL.Scheme, request.URL.Host = physical.Scheme, physical.Host
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return response, body, err
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job AgentJob
		if json.NewDecoder(r.Body).Decode(&job) != nil {
			http.Error(w, "job", 400)
			return
		}
		call := func(token string) (*http.Response, error) {
			request, err := http.NewRequest(job.Method, job.URL, nil)
			if err != nil {
				return nil, err
			}
			for name, value := range job.Headers {
				request.Header.Set(name, value)
			}
			sign(request, token, nil)
			response, _, err := send(request, job.Transport)
			return response, err
		}
		response, err := call(job.Token)
		if err == nil && response.Header.Get("AAuth-Requirement") == "requirement=person-token" && job.PersonTokenEndpoint != "" {
			target, _ := url.Parse(job.URL)
			if discovering {
				var metadata struct {
					PersonTokenEndpoint string `json:"person_token_endpoint"`
				}
				request, _ := http.NewRequest("GET", config.PersonServer+"/.well-known/aauth-person.json", nil)
				if _, answer, err := send(request, job.PersonTransport); err != nil || json.Unmarshal(answer, &metadata) != nil || metadata.PersonTokenEndpoint != job.PersonTokenEndpoint {
					http.Error(w, "Person Server metadata", 502)
					return
				}
				request, _ = http.NewRequest("GET", target.Scheme+"://"+target.Host+"/.well-known/aauth-resource.json", nil)
				if _, _, err := send(request, job.Transport); err != nil {
					http.Error(w, "Resource metadata", 502)
					return
				}
			}
			body, _ := json.Marshal(map[string]string{"resource": target.Scheme + "://" + target.Host})
			request, _ := http.NewRequest("POST", job.PersonTokenEndpoint, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			sign(request, job.Token, body)
			var issued struct {
				PersonToken string `json:"person_token"`
			}
			var answer []byte
			if _, answer, err = send(request, job.PersonTransport); err == nil && json.Unmarshal(answer, &issued) == nil {
				response, err = call(issued.PersonToken)
			}
		}
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]int{"status": response.StatusCode})
	}))
	json.NewEncoder(os.Stdout).Encode(Ready{Version: 1, URL: server.URL + "/control"})
	select {}
}
