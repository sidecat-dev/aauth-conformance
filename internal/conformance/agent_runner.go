package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"
)

func startCapture(f Fixture) (string, <-chan Captured, func(), error) {
	received := make(chan Captured, 32)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			http.Error(w, "body read", 400)
			return
		}
		captured := Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}
		select {
		case received <- captured:
		default:
			http.Error(w, "capture overflow", 503)
			return
		}
		observed := ObserveAgent(f, captured)
		valid := observed.ValidProof && observed.ValidToken && len(body) == 0 && observed.Created >= f.Now-60 && observed.Created <= f.Now+60
		for _, required := range []string{"@method", "@authority", "@path", "signature-key"} {
			valid = valid && slices.Contains(observed.Covered, required)
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			valid = valid && slices.Contains(observed.Covered, "@query")
		}
		if r.Header.Get("Authorization") != "" {
			valid = valid && slices.Contains(observed.Covered, "authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		if !valid {
			w.Header().Set("Signature-Error", "error=invalid_signature")
			w.WriteHeader(401)
		}
		io.WriteString(w, `{"received":true}`)
	})
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	return "http://" + listener.Addr().String(), received, func() { server.Close(); <-done }, nil
}

func runAgents(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		transport, received, closeCapture, err := startCapture(s.Fixture)
		if err != nil {
			run.Error = err.Error()
			report.Runs = append(report.Runs, run)
			continue
		}
		config := Bootstrap{Version: 1, Role: AgentRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: s.Fixture.Origin + s.Fixture.Path, APTransport: ap, AgentSeed: s.Fixture.AgentSeed, Subject: s.Fixture.Subject}
		config.withPersonTrust(s.Fixture)
		ready, stop, startError := startAdapter(ctx, target, config, options)
		if startError != nil {
			run.Error = startError.Error()
		}
		for _, scenario := range s.Scenarios {
			if scenario.Request.Endpoint == personEndpoint {
				run.Cases = append(run.Cases, runPersonFlowCase(ctx, s.Fixture, scenario, target, ready.URL, options, startError))
				continue
			}
			c := Case{ID: scenario.ID}
			token, issueError := MintToken(s.Fixture, scenario.Token, scenario.ID)
			job := AgentJob{Method: scenario.Request.Method, URL: s.Fixture.Origin + scenario.Request.Path, Headers: scenario.Request.Headers, Token: token, Transport: transport}
			c.SigningInput = &job
			var capture *Captured
			executionError := startError
			if issueError != nil {
				executionError = issueError
			}
			if executionError == nil {
				encoded, _ := json.Marshal(job)
				request, _ := http.NewRequest("POST", ready.URL, bytes.NewReader(encoded))
				request.Header.Set("Content-Type", "application/json")
				response, err := Exchange(ctx, request, ready.URL, options.Timeout)
				if err != nil {
					executionError = err
				} else {
					c.ControlResponse = &response
					if response.Status != 200 {
						executionError = fmt.Errorf("signer operation returned HTTP %d: %s", response.Status, response.Body)
					}
				}
				select {
				case value := <-received:
					capture = &value
				default:
				}
				if capture == nil && executionError == nil {
					timer := time.NewTimer(options.Timeout)
					select {
					case value := <-received:
						capture = &value
					case <-timer.C:
						executionError = fmt.Errorf("signer produced no outbound request")
					case <-ctx.Done():
						executionError = ctx.Err()
					}
					timer.Stop()
				}
				select {
				case <-received:
					executionError = fmt.Errorf("signer sent multiple requests for one command")
				default:
				}
			}
			observed := Observation{}
			if capture != nil {
				observed = ObserveAgent(s.Fixture, *capture)
				c.Method = capture.Method
				c.URL = capture.URL
				c.Headers = capture.Headers
				c.SignatureBase = observed.Base
				c.RequestBody = capture.Body
			}
			if executionError != nil {
				c.Error = executionError.Error()
			}
			for _, assertion := range scenario.Assertions {
				result := Result{Assertion: assertion.ID, Clause: assertion.Clause, Expected: assertion.Equals}
				switch {
				case !slices.Contains(target.Claims, assertion.Clause):
					result.State = "not_claimed"
				case capture != nil:
					result = CheckAgent(assertion, observed, *capture, job)
				default:
					result.State = "error"
					result.Detail = c.Error
				}
				c.Results = append(c.Results, result)
			}
			run.Cases = append(run.Cases, c)
		}
		if stop != nil {
			stop()
		}
		closeCapture()
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}
