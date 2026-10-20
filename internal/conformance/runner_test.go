package conformance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Catches following a redirect to a different role or accepting truncated evidence.
func TestExchangeRejectsRedirectOversizeAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", 302)
		case "/large":
			w.Write(make([]byte, 65537))
		case "/slow":
			<-r.Context().Done()
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer server.Close()
	for _, path := range []string{"/redirect", "/large", "/slow"} {
		req, _ := http.NewRequest("GET", "https://resource.conformance.test"+path, nil)
		if _, err := Exchange(context.Background(), req, server.URL+path, 50*time.Millisecond); err == nil {
			t.Fatal("accepted", path)
		}
	}
	req, _ := http.NewRequest("GET", "https://resource.conformance.test/ok", nil)
	response, err := Exchange(context.Background(), req, server.URL+"/ok", time.Second)
	if err != nil || string(response.Body) != "ok" {
		t.Fatalf("%+v %v", response, err)
	}
}

// Catches startup failures being counted as passing refusals and tests process cleanup.
func TestRunnerPreservesRealHTTPFailureAndStartupErrors(t *testing.T) {
	s, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims(s, ResourceRole)
	for _, mode := range []string{"respond", "silent", "missing", "wrong-path", "empty-query"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AAUTH_TEST_ADAPTER", mode)
			command := []string{os.Args[0], "-test.run=^TestAdapterProcess$"}
			if mode == "missing" {
				command = []string{"/no-such-aauth-adapter"}
			}
			report, err := RunSuite(context.Background(), s, Targets{Version: 1, Implementations: []Target{{ID: "test", Revision: "test-process", Command: command, Claims: claims}}}, Options{Timeout: time.Second, StartupTimeout: 200 * time.Millisecond, Stderr: io.Discard})
			if err != nil {
				t.Fatal(err)
			}
			if report.Success() || len(report.Runs) != 1 || len(report.Runs[0].Cases) != 6 {
				t.Fatalf("false green: %+v", report)
			}
			if mode == "respond" {
				if report.Runs[0].Cases[0].Response.Status != 200 {
					t.Fatal("did not observe test server")
				}
			} else if report.Runs[0].Error == "" {
				t.Fatal("startup error missing")
			}
		})
	}
}

func TestAdapterProcess(t *testing.T) {
	mode := os.Getenv("AAUTH_TEST_ADAPTER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	if mode == "silent" {
		select {}
	}
	var config Bootstrap
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		os.Exit(11)
	}
	for _, path := range []string{"/.well-known/aauth-agent.json", "/.well-known/jwks.json"} {
		r, e := http.Get(config.APTransport + path)
		if e != nil || r.StatusCode != 200 {
			os.Exit(12)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	if strings.HasPrefix(mode, "agent-") {
		runAgentTestProcess(config, mode)
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "drop-signed" {
			if r.Header.Get("Signature-Key") != "" {
				connection, _, _ := w.(http.Hijacker).Hijack()
				connection.Close()
				return
			}
			w.Header().Set("AAuth-Requirement", "requirement=agent-token")
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub":"wrong"}`))
	}))
	path := "/whoami"
	if mode == "wrong-path" {
		path = "/different"
	}
	if mode == "empty-query" {
		path += "?"
	}
	json.NewEncoder(os.Stdout).Encode(Ready{Version: 1, URL: server.URL + path})
	select {}
}

// An unclaimed assertion must not hide an actual failed exchange.
func TestUnclaimedCasesCannotHideTransportFailures(t *testing.T) {
	t.Setenv("AAUTH_TEST_ADAPTER", "drop-signed")
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	targets := Targets{Version: 1, Implementations: []Target{{ID: "partial", Revision: "test", Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}, Claims: []string{"core.agent-token-required"}}}}
	report, err := RunSuite(context.Background(), suite, targets, Options{StartupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Success() {
		t.Fatal("transport failures hidden behind not_claimed")
	}
	b, _ := json.Marshal(report.Runs[0].Cases[1])
	var record map[string]any
	json.Unmarshal(b, &record)
	if record["error"] == nil || record["error"] == "" {
		t.Fatal("transport failure missing from case evidence")
	}
}

func TestPhysicalAddressDoesNotReplaceSignedPathOrQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Host+" "+r.RequestURI) }))
	defer server.Close()
	request, _ := http.NewRequest("GET", "https://resource.conformance.test/whoami%2Fpart?q=1", nil)
	response, err := Exchange(context.Background(), request, server.URL+"/different?wrong=1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != "resource.conformance.test /whoami%2Fpart?q=1" {
		t.Fatalf("sent %s", response.Body)
	}
}

// Adding an implementation name must never change the token, proof or request.
func TestTargetsReceiveIdenticalScenarioInputs(t *testing.T) {
	t.Setenv("AAUTH_TEST_ADAPTER", "respond")
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims(suite, ResourceRole)
	targets := Targets{Version: 1}
	for _, id := range []string{"first", "second"} {
		targets.Implementations = append(targets.Implementations, Target{ID: id, Revision: "test", Claims: claims, Command: []string{os.Args[0], "-test.run=^TestAdapterProcess$"}})
	}
	report, err := RunSuite(context.Background(), suite, targets, Options{StartupTimeout: time.Second, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i, first := range report.Runs[0].Cases {
		second := report.Runs[1].Cases[i]
		if first.URL != second.URL || first.Method != second.Method || first.SignatureBase != second.SignatureBase || !reflect.DeepEqual(first.Headers, second.Headers) {
			t.Fatalf("scenario %s changed between targets", first.ID)
		}
	}
}
