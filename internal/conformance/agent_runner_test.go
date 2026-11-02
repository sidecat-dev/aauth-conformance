package conformance

import (
	"context"
	"crypto/ed25519"
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

func TestAgentRunnerGradesReceivedProofsNotControllerPromises(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"agent-valid", "agent-unsigned", "agent-wrong-path"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AAUTH_TEST_ADAPTER", mode)
			targets := Targets{Version: 1, Role: AgentRole, Implementations: []Target{{ID: "test-agent", Revision: "test", Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}, Claims: Claims(suite, AgentRole)}}}
			report, err := RunSuite(context.Background(), suite, targets, Options{StartupTimeout: time.Second, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Runs[0].Cases) != 4 {
				t.Fatal("role cases mixed")
			}
			if mode == "agent-valid" {
				if !report.Success() {
					t.Fatalf("valid output refused: %+v", report.Runs)
				}
			} else {
				if report.Success() {
					t.Fatal("invalid signer output passed")
				}
				results := report.Runs[0].Cases[0].Results
				if mode == "agent-unsigned" && results[1].State != "fail" {
					t.Fatalf("missing proof not observed: %+v", results)
				}
				if mode == "agent-wrong-path" && (results[0].State != "fail" || results[1].State != "pass") {
					t.Fatalf("operation vs proof not distinguished: %+v", results)
				}
			}
		})
	}
}

// Test-process fixture only; real implementation launchers use their SUT signer.
func runAgentTestProcess(config Bootstrap, mode string) {
	if mode == "agent-person" {
		runPersonAgentTestProcess(config)
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job AgentJob
		if json.NewDecoder(r.Body).Decode(&job) != nil {
			http.Error(w, "job", 400)
			return
		}
		request, err := http.NewRequest(job.Method, job.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if mode == "agent-wrong-path" {
			request.URL.Path = "/different"
			request.URL.RawPath = ""
		}
		for name, value := range job.Headers {
			request.Header.Set(name, value)
		}
		if mode != "agent-unsigned" {
			request.Header.Set("Signature-Key", `test=jwt;jwt="`+job.Token+`"`)
			components := []string{"@method", "@authority", "@path"}
			if request.URL.RawQuery != "" {
				components = append(components, "@query")
			}
			if request.Header.Get("Authorization") != "" {
				components = append(components, "authorization")
			}
			components = append(components, "signature-key")
			names, lines := []string{}, []string{}
			for _, name := range components {
				var value string
				switch name {
				case "@method":
					value = request.Method
				case "@authority":
					value = request.URL.Host
				case "@path":
					value = request.URL.EscapedPath()
				case "@query":
					value = "?" + request.URL.RawQuery
				default:
					value = request.Header.Get(name)
				}
				names = append(names, fmt.Sprintf("%q", name))
				lines = append(lines, fmt.Sprintf("%q: %s", name, value))
			}
			params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), config.Now)
			lines = append(lines, `"@signature-params": `+params)
			request.Header.Set("Signature-Input", "test="+params)
			request.Header.Set("Signature", "test=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(config.AgentSeed), []byte(strings.Join(lines, "\n"))))+":")
		}
		physical, _ := url.Parse(job.Transport)
		request.Host = request.URL.Host
		request.URL.Scheme = physical.Scheme
		request.URL.Host = physical.Host
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		json.NewEncoder(w).Encode(map[string]int{"status": response.StatusCode})
	}))
	json.NewEncoder(os.Stdout).Encode(Ready{Version: 1, URL: server.URL + "/control"})
	select {}
}
