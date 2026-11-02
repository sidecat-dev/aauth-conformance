package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"time"
)

type Options struct {
	Timeout, StartupTimeout time.Duration
	Stderr                  io.Writer
}

// Exchange sends a logical request and returns the bounded response. A
// launcher's loopback transport replaces only the physical origin. An empty
// transport sends to the logical HTTPS URL itself, over the context's Network.
func Exchange(ctx context.Context, logical *http.Request, transport string, timeout time.Duration) (Response, error) {
	req := logical.Clone(ctx)
	req.Host = logical.URL.Host
	connections := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if transport == "" {
		connections = networkFrom(ctx).transport()
	} else {
		physical, err := url.Parse(transport)
		if err != nil {
			return Response{}, err
		}
		physical.Path = logical.URL.Path
		physical.RawPath = logical.URL.RawPath
		physical.RawQuery = logical.URL.RawQuery
		physical.ForceQuery = logical.URL.ForceQuery
		req.URL = physical
	}
	client := &http.Client{Timeout: timeout, Transport: connections, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirects are not conformance responses")
	}}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return Response{}, err
	}
	if len(body) > 65536 {
		return Response{}, fmt.Errorf("response exceeds 64 KiB")
	}
	return Response{Status: response.StatusCode, Header: response.Header.Clone(), Trailer: response.Trailer.Clone(), Body: body}, nil
}
func startAP(f Fixture) (string, func(), error) {
	key := publicJWK(f.APSeed)
	key["kid"] = f.Kid
	metadata, _ := json.Marshal(map[string]any{"issuer": f.Issuer, "jwks_uri": f.Issuer + "/.well-known/jwks.json"})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{key}})
	mux := http.NewServeMux()
	for path, body := range map[string][]byte{"/.well-known/aauth-agent.json": metadata, "/.well-known/jwks.json": jwks} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Write(body)
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() { server.Close(); <-done }, nil
}
func startAdapter(ctx context.Context, t Target, config Bootstrap, options Options) (Ready, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	b, _ := json.Marshal(config)
	command := exec.CommandContext(ctx, t.Command[0], t.Command[1:]...)
	command.Stdin = bytes.NewReader(b)
	command.Stderr = options.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		return Ready{}, nil, err
	}
	if err = command.Start(); err != nil {
		cancel()
		return Ready{}, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stop := func() { cancel(); <-done }
	type startup struct {
		ready Ready
		err   error
	}
	ready := make(chan startup, 1)
	go func() {
		var value Ready
		err := json.NewDecoder(io.LimitReader(stdout, 65536)).Decode(&value)
		ready <- startup{value, err}
	}()
	timer := time.NewTimer(options.StartupTimeout)
	defer timer.Stop()
	var value Ready
	select {
	case item := <-ready:
		err = item.err
		value = item.ready
	case <-timer.C:
		err = fmt.Errorf("adapter readiness timeout")
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err == nil {
		u, e := url.Parse(value.URL)
		target, targetError := url.Parse(config.Resource)
		if config.Role == PersonServerRole && targetError == nil {
			target.Path = "/person"
			target.RawPath = ""
		}
		if config.Role == AgentRole && targetError == nil {
			target.Path = "/control"
			target.RawPath = ""
		}
		if e != nil || targetError != nil || value.Version != 1 || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !net.ParseIP(u.Hostname()).IsLoopback() || u.EscapedPath() != target.EscapedPath() {
			err = fmt.Errorf("adapter must advertise version 1 and a loopback HTTP URL matching the configured path, without query or fragment")
		}
	}
	if err != nil {
		stop()
		return Ready{}, nil, err
	}
	return value, stop, nil
}

func RunSuite(ctx context.Context, s Suite, targets Targets, options Options) (Report, error) {
	role := targetRole(targets.Role)
	selected, selectError := s.ForRole(role)
	if selectError != nil {
		return Report{}, selectError
	}
	s = selected
	report := Report{Version: 1, Role: role, SuiteSHA256: s.Digest, Clock: s.Fixture.Now, Catalog: s.Catalog}
	if err := s.validate(); err != nil {
		return report, err
	}
	if err := ValidateTargets(targets, s); err != nil {
		return report, err
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.StartupTimeout <= 0 {
		options.StartupTimeout = 10 * time.Second
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	ap, closeAP, err := startAP(s.Fixture)
	if err != nil {
		return report, err
	}
	defer closeAP()
	if extension, ok := extensionRoles[role]; ok {
		available, unavailable := splitUnavailable(s, targets)
		if len(available.Implementations) > 0 {
			report = extension.Run(ctx, s, available, options, ap, report)
		}
		report.Runs = append(report.Runs, unavailable...)
		report.Execution = "failed_or_incomplete"
		if report.Success() {
			report.Execution = "passed"
		}
		return report, nil
	}
	if role == SubagentRole {
		return runSubagents(ctx, s, targets, options, ap, report), nil
	}
	if role == DeferredRole {
		available, unavailable := splitUnavailable(s, targets)
		if len(available.Implementations) > 0 {
			report = runDeferred(ctx, s, available, options, ap, report)
		}
		report.Runs = append(report.Runs, unavailable...)
		report.Execution = "failed_or_incomplete"
		if report.Success() {
			report.Execution = "passed"
		}
		return report, nil
	}
	if role == FederatedRole {
		return runFederated(ctx, s, targets, options, ap, report), nil
	}
	if role == PersonServerRole {
		return runPersonServers(ctx, s, targets, options, ap, report), nil
	}
	if role == AgentRole {
		return runAgents(ctx, s, targets, options, ap, report), nil
	}
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		config := Bootstrap{Version: 1, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: s.Fixture.Origin + s.Fixture.Path, APTransport: ap}
		ready, stop, startError := startAdapter(ctx, target, config, options)
		if startError != nil {
			run.Error = startError.Error()
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runResourceCase(ctx, s.Fixture, scenario, target, ready.URL, options, startError))
		}
		if stop != nil {
			stop()
		}
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report, nil
}

// runResourceCase sends one agent-identity request and grades the response.
func runResourceCase(ctx context.Context, f Fixture, scenario Scenario, target Target, physical string, options Options, startError error) Case {
	c := Case{ID: scenario.ID}
	request, base, requestError := BuildRequest(f, scenario)
	var response Response
	var exchangeError error
	if requestError != nil {
		exchangeError = requestError
	} else {
		c.Method = request.Method
		c.URL = request.URL.String()
		c.Headers = request.Header.Clone()
		c.SignatureBase = string(base)
		switch {
		case startError != nil:
			exchangeError = startError
		default:
			response, exchangeError = Exchange(ctx, request, physical, options.Timeout)
			if exchangeError == nil {
				c.Response = &response
			}
		}
	}
	if exchangeError != nil {
		c.Error = exchangeError.Error()
	}
	for _, assertion := range scenario.Assertions {
		result := Result{Assertion: assertion.ID, Clause: assertion.Clause, Expected: assertion.Equals}
		switch {
		case !slices.Contains(target.Claims, assertion.Clause):
			result.State = "not_claimed"
		case exchangeError != nil:
			result.State = "error"
			result.Detail = exchangeError.Error()
		default:
			result = Check(assertion, response)
		}
		c.Results = append(c.Results, result)
	}
	return c
}
