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
// request must fail both person assertions, and the full flow must pass.
func TestPersonFlowGradesThePersonRequestAndTheRetry(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	claims := append(Claims(suite, AgentRole), "agent.person-flow")
	for _, test := range []struct {
		mode      string
		pass      bool
		exchanges int
	}{{"agent-person", true, 3}, {"agent-valid", false, 1}} {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("AAUTH_TEST_ADAPTER", test.mode)
			targets := Targets{Version: 1, Role: AgentRole, Implementations: []Target{{ID: "test-agent", Revision: "test", Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}, Claims: claims}}}
			report, err := RunSuite(context.Background(), suite, targets, Options{StartupTimeout: time.Second, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			var flow *Case
			for i := range report.Runs[0].Cases {
				if report.Runs[0].Cases[i].ID == "agent-person-flow" {
					flow = &report.Runs[0].Cases[i]
				}
			}
			if flow == nil || flow.Error != "" || len(flow.Results) != 2 || len(flow.Exchanges) != test.exchanges {
				t.Fatalf("person flow case: %+v", flow)
			}
			for _, result := range flow.Results {
				if (result.State == "pass") != test.pass {
					t.Fatalf("%s graded %s: %s", result.Assertion, result.State, result.Detail)
				}
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
func runPersonAgentTestProcess(config Bootstrap) {
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
