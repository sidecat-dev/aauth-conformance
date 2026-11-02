package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
)

// SupervisionPSInput is one Person Server scenario. Act is the act graded:
// person_token, or auth_token or mission_proposal after a person token the
// harness SS allows. Decision is how the harness SS answers that act.
type SupervisionPSInput struct {
	Act       string `json:"act"`
	Decision  string `json:"decision"`
	AllowExp  int64  `json:"allow_exp_offset,omitempty"`
	SecondAct bool   `json:"second_act,omitempty"`
}

var supervisionPSDecisions = []string{"allow", "deny", "ask", "defer", "server-error", "wrong-sdi", "bad-signature", "foreign-signer", "unsigned", "allow-no-description"}

// supervisionPSProposal is the mission the Agent proposes; the harness SS
// allows it as proposed.
const supervisionPSProposal = "# Fixture mission\n\nRead the fixture resource."

func validateSupervisionPSScenario(f Fixture, s Scenario) error {
	if _, err := supervisionFixture(f); err != nil {
		return err
	}
	var input SupervisionPSInput
	if err := DecodeInput(s, &input); err != nil {
		return err
	}
	if !slices.Contains([]string{"person_token", "auth_token", "mission_proposal"}, input.Act) || !slices.Contains(supervisionPSDecisions, input.Decision) || input.AllowExp < 0 || input.AllowExp > 3600 || input.AllowExp != 0 && (input.Decision != "allow" || input.Act == "mission_proposal") || (input.Decision == "allow-no-description") != (input.Act == "mission_proposal" && input.Decision != "allow") {
		return fmt.Errorf("%s: unsupported act, decision or allow_exp_offset", s.ID)
	}
	stages := []string{"person", "deliver"}
	switch input.Act {
	case "auth_token":
		stages = append(stages, "token")
	case "mission_proposal":
		stages = append(stages, "mission")
	}
	if slices.Contains([]string{"ask", "server-error", "defer"}, input.Decision) {
		stages = append(stages, "poll")
	}
	if input.SecondAct {
		stages = append(stages, "person-again")
	}
	for _, a := range s.Assertions {
		switch a.Kind {
		case "ss-request-proof", "ss-request-has", "ss-request-equals", "ss-request-token", "ss-sdi-distinct", "ss-mission-match":
			if a.Stage != "deliver" {
				return fmt.Errorf("%s/%s: supervisor-side observations are graded at stage deliver", s.ID, a.ID)
			}
			selector, path, _ := strings.Cut(a.Member, "/")
			if !validSSSelector(selector) || (a.Kind != "ss-request-proof" && a.Kind != "ss-sdi-distinct" && a.Kind != "ss-mission-match") == (path == "") {
				return fmt.Errorf("%s/%s: member is selector or selector/member", s.ID, a.ID)
			}
			if a.Kind == "ss-request-token" && !slices.Contains([]string{"agent_token", "resource_token", "presented_token"}, path) {
				return fmt.Errorf("%s/%s: ss-request-token compares agent_token, resource_token or presented_token", s.ID, a.ID)
			}
		default:
			if !slices.Contains(stages, a.Stage) || a.Stage == "deliver" {
				return fmt.Errorf("%s/%s: stage %q is not observed in this scenario", s.ID, a.ID, a.Stage)
			}
		}
		if a.Kind != "ss-request-equals" && !slices.Contains(GenericKinds, a.Kind) {
			if err := boolEquals(a); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
			}
		}
		if a.Kind == "ps-credential-exp" && input.AllowExp == 0 {
			return fmt.Errorf("%s/%s: ps-credential-exp needs allow_exp_offset", s.ID, a.ID)
		}
	}
	return nil
}

func validSSSelector(selector string) bool {
	name, _, _ := strings.Cut(selector, "#")
	return slices.Contains([]string{"connect", "decision", "proposal", "poll"}, name) || strings.HasPrefix(name, "event:") && len(name) > 6 || strings.HasPrefix(name, "report:") && len(name) > 7 || strings.HasPrefix(name, "mission:") && len(name) > 8
}

// SSRequest is one request the native PS made of the harness SS.
type SSRequest struct {
	Kind     string      `json:"kind"`
	Request  Captured    `json:"request"`
	Proof    Observation `json:"ps_proof"`
	Response *Response   `json:"response,omitempty"`
}

// harnessSupervisor is the SS the native PS consults. It answers connects,
// events and reports, answers the first supervision request of the graded act
// as the scenario says and every other one allow, and signs its decisions
// with the supervisor fixture key under the components the PS asked for.
type harnessSupervisor struct {
	mu       sync.Mutex
	fixture  Fixture
	ss       SupervisionFixture
	input    SupervisionPSInput
	requests []SSRequest
	acts     int
	pending  map[string]string
}

func (h *harnessSupervisor) reset(input SupervisionPSInput) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.input, h.requests, h.acts, h.pending = input, nil, 0, map[string]string{}
}

// rebase points the harness at one case's fixture: its clock, which dates
// signed decisions, and the Person Server whose proofs it checks.
func (h *harnessSupervisor) rebase(f Fixture) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fixture = f
}
func (h *harnessSupervisor) snapshot() []SSRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.requests)
}

func (h *harnessSupervisor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(body) > 65536 {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	captured := Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.ss
	path := r.URL.Path
	answer := func(kind string, status int, header http.Header, payload []byte) {
		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
		w.Write(payload)
		response := Response{Status: status, Header: header.Clone(), Body: payload}
		entry := SSRequest{Kind: kind, Request: captured, Response: &response}
		switch kind {
		case "metadata", "jwks":
		case "poll":
			entry.Proof = observePSPollProof(h.fixture, captured, captured.URL)
		default:
			entry.Proof = observePSRequestProof(h.fixture, captured, captured.URL, captured.Method)
		}
		h.requests = append(h.requests, entry)
	}
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	switch {
	case r.Method == "GET" && path == "/.well-known/aauth-supervisor.json":
		metadata, _ := json.Marshal(map[string]any{"issuer": s.Issuer, "name": "Conformance supervisor", "connect_endpoint": s.Issuer + "/connect", "mission_endpoint": s.Issuer + "/mission", "decision_endpoint": s.Issuer + "/decision", "event_endpoint": s.Issuer + "/event", "jwks_uri": s.Issuer + "/.well-known/jwks.json"})
		answer("metadata", 200, jsonHeader, metadata)
	case r.Method == "GET" && path == "/.well-known/jwks.json":
		key := publicJWK(s.Seed)
		key["kid"] = s.Kid
		jwks, _ := json.Marshal(map[string]any{"keys": []any{key}})
		answer("jwks", 200, jsonHeader, jwks)
	case r.Method == "POST" && path == "/connect":
		answer("connect", 200, jsonHeader, []byte(`{"status":"connected"}`))
	case r.Method == "POST" && path == "/event":
		object, _ := jsonObject(body)
		name, _ := object["event"].(string)
		answer("event:"+name, 201, http.Header{}, nil)
	case r.Method == "POST" && strings.HasPrefix(path, "/mission/"):
		object, _ := jsonObject(body)
		action, _ := object["action"].(string)
		if action == "approved" || action == "terminated" {
			answer("report:"+action, 201, http.Header{}, nil)
			return
		}
		h.decide("mission:"+action, captured, body, answer)
	case r.Method == "POST" && path == "/mission":
		h.decide("proposal", captured, body, answer)
	case r.Method == "POST" && path == "/decision":
		h.decide("decision", captured, body, answer)
	case r.Method == "GET" && strings.HasPrefix(path, "/pending/"):
		sdi, held := h.pending[path]
		if !held {
			problem, _ := json.Marshal(map[string]any{"error": "unknown_pending"})
			answer("poll", 404, jsonHeader, problem)
			return
		}
		delete(h.pending, path)
		status, header, payload := h.signedDecision(captured, map[string]any{"sdi": sdi, "decision": "allow"}, s.Seed, s.Issuer, s.Kid, true)
		answer("poll", status, header, payload)
	default:
		answer("unknown", 404, jsonHeader, []byte(`{"error":"not_found"}`))
	}
}

// decide answers one supervision request. The graded act is the first
// supervision request for a person_token act, and the second (after the
// allowed person token) for an auth_token or mission_proposal act.
func (h *harnessSupervisor) decide(kind string, captured Captured, body []byte, answer func(string, int, http.Header, []byte)) {
	object, _ := jsonObject(body)
	sdi, _ := object["sdi"].(string)
	h.acts++
	graded := h.acts == 1 && h.input.Act == "person_token" || h.acts == 2 && h.input.Act != "person_token"
	mode := "allow"
	if graded {
		mode = h.input.Decision
	}
	s := h.ss
	decision := map[string]any{"sdi": sdi, "decision": "allow"}
	if graded && h.input.AllowExp > 0 {
		decision["exp"] = h.fixture.Now + h.input.AllowExp
	}
	if kind == "proposal" && mode != "allow-no-description" {
		decision["description"] = object["description"]
	}
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	switch mode {
	case "deny":
		decision = map[string]any{"sdi": sdi, "decision": "deny", "reason": "Fixture denial."}
	case "ask":
		decision = map[string]any{"sdi": sdi, "decision": "ask", "summary": "Fixture question for the person."}
	case "defer":
		path := fmt.Sprintf("/pending/%s-%d", "fixture", h.acts)
		h.pending[path] = sdi
		payload, _ := json.Marshal(map[string]any{"sdi": sdi, "status": "pending"})
		answer(kind, 202, http.Header{"Content-Type": {"application/json"}, "Location": {s.Issuer + path}, "Retry-After": {"0"}, "Cache-Control": {"no-store"}}, payload)
		return
	case "server-error":
		answer(kind, 500, jsonHeader, []byte(`{"error":"server_error"}`))
		return
	case "wrong-sdi":
		decision["sdi"] = "d-not-the-request"
	case "unsigned":
		payload, _ := json.Marshal(decision)
		answer(kind, 200, jsonHeader, payload)
		return
	}
	seed, issuer, kid := s.Seed, s.Issuer, s.Kid
	switch mode {
	case "bad-signature":
		seed = s.Foreign.Seed
	case "foreign-signer":
		seed, issuer, kid = s.Foreign.Seed, s.Foreign.Issuer, s.Foreign.Kid
	}
	status, header, payload := h.signedDecision(captured, decision, seed, issuer, kid, false)
	answer(kind, status, header, payload)
}

// signedDecision serializes and signs a decision as RFC 9421 response
// signature under the label and components the request's Accept-Signature
// asked for, after the three every decision covers.
func (h *harnessSupervisor) signedDecision(request Captured, decision map[string]any, seed, issuer, kid string, poll bool) (int, http.Header, []byte) {
	payload, _ := json.Marshal(decision)
	header := http.Header{"Content-Type": {"application/json"}}
	digest := sha256.Sum256(payload)
	header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	header.Set("Signature-Key", fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-supervisor.json";kid=%q`, issuer, kid))
	label := "sig"
	items := []httpsfv.Item{httpsfv.NewItem("@status"), httpsfv.NewItem("content-type"), httpsfv.NewItem("content-digest")}
	if asked, err := httpsfv.UnmarshalDictionary(request.Headers.Values("Accept-Signature")); err == nil && len(asked.Names()) > 0 {
		label = asked.Names()[0]
		member, _ := asked.Get(label)
		if list, ok := member.(httpsfv.InnerList); ok {
			for _, item := range list.Items {
				identifier, err := httpsfv.Marshal(item)
				if err != nil {
					continue
				}
				known := false
				for _, existing := range items {
					if marshaled, _ := httpsfv.Marshal(existing); marshaled == identifier {
						known = true
					}
				}
				if _, present := responseComponent(item, 200, header, request); present && !known {
					items = append(items, item)
				}
			}
		}
	}
	params := httpsfv.NewParams()
	params.Add("created", h.fixture.Now)
	input := httpsfv.InnerList{Items: items, Params: params}
	var lines []string
	for _, item := range items {
		identifier, _ := httpsfv.Marshal(item)
		value, _ := responseComponent(item, 200, header, request)
		lines = append(lines, identifier+": "+value)
	}
	serialized, _ := httpsfv.Marshal(input)
	lines = append(lines, `"@signature-params": `+serialized)
	signature := ed25519.Sign(seedKey(seed), []byte(strings.Join(lines, "\n")))
	header.Set("Signature-Input", label+"="+serialized)
	header.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return 200, header, payload
}

// SupervisionPSExchange is one Agent request to, or host control of, the native PS.
type SupervisionPSExchange struct {
	Stage    string    `json:"stage"`
	Request  *Captured `json:"request,omitempty"`
	Response *Response `json:"response,omitempty"`
	Error    string    `json:"error,omitempty"`
}

func runSupervisionPersonServers(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	ss, _ := supervisionFixture(s.Fixture)
	p := *s.Fixture.Person
	harness := &harnessSupervisor{fixture: s.Fixture, ss: ss, pending: map[string]string{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		for _, target := range targets.Implementations {
			report.Runs = append(report.Runs, Run{Target: target, Error: err.Error()})
		}
		return report
	}
	server := &http.Server{Handler: harness, ReadHeaderTimeout: 3 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	defer func() { server.Close(); <-done }()
	transport := "http://" + listener.Addr().String()
	keys := []map[string]any{}
	for _, peer := range []SupervisionPeer{{ss.Issuer, ss.Seed, ss.Kid}, ss.Foreign} {
		jwk := publicJWK(peer.Seed)
		jwk["kid"] = peer.Kid
		keys = append(keys, map[string]any{"issuer": peer.Issuer, "kid": peer.Kid, "jwk": jwk})
	}
	extension, _ := json.Marshal(map[string]any{"supervisor": ss.Issuer, "supervisor_transport": transport, "supervisor_subject": ss.Subject, "supervisor_keys": keys, "resource": s.Fixture.Origin})
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			var input SupervisionPSInput
			DecodeInput(scenario, &input)
			harness.reset(input)
			config := Bootstrap{Version: 1, Role: SupervisionPersonServerRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: p.Issuer + "/person", APTransport: ap, PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid, PersonSubject: p.Subject, PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime, PermittedScopes: p.PermittedScopes, ResourceKid: p.ResourceKid, ResourceJWK: publicJWK(p.ResourceSeed), Extension: extension}
			ready, stop, startError := startAdapter(ctx, target, config, options)
			physical := strings.TrimSuffix(ready.URL, "/person")
			reach := supervisionPSReach{
				physical: physical,
				mission:  p.Issuer + "/mission",
				control: func(ctx context.Context, body string, _ string) (Response, error) {
					return supervisionControl(ctx, physical, json.RawMessage(body), options.Timeout)
				},
			}
			c := runSupervisionPSCase(ctx, s.Fixture, ss, scenario, input, target, reach, options, startError, harness)
			if stop != nil {
				stop()
			}
			run.Cases = append(run.Cases, c)
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

// supervisionPSReach is how a case reaches the Person Server under test:
// the physical address its requests are sent to ("" for a deployed server
// reached by name), its mission endpoint, and its host control, which is
// given the control body and the held act's pending URL. graded, when set,
// chooses the supervisor requests the case is graded on.
type supervisionPSReach struct {
	physical string
	mission  string
	control  func(ctx context.Context, body, pending string) (Response, error)
	graded   func([]SSRequest) []SSRequest
}

func runSupervisionPSCase(ctx context.Context, f Fixture, ss SupervisionFixture, scenario Scenario, input SupervisionPSInput, target Target, reach supervisionPSReach, options Options, startError error, harness *harnessSupervisor) Case {
	c := Case{ID: scenario.ID}
	p := *f.Person
	physical := reach.physical
	agent, _ := mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": scenario.ID + "-agent", "iat": f.Now - 10, "exp": f.Now + 600, "ps": p.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}})
	credential := `sig=jwt;jwt="` + agent + `"`
	exchanges := []*SupervisionPSExchange{}
	stages := map[string]*SupervisionPSExchange{}
	executionError := ""
	if startError != nil {
		executionError = startError.Error()
	}
	send := func(stage, method, target string, body []byte) *SupervisionPSExchange {
		exchange := &SupervisionPSExchange{Stage: stage}
		exchanges = append(exchanges, exchange)
		if executionError != "" {
			return exchange
		}
		request, _, err := signedFixtureRequest(f, f.AgentSeed, method, target, credential, body)
		if err != nil {
			executionError = stage + ": " + err.Error()
			return exchange
		}
		exchange.Request = &Captured{Method: method, URL: target, Headers: request.Header.Clone(), Body: body}
		response, err := Exchange(ctx, request, physical, options.Timeout)
		if err != nil {
			executionError = stage + ": " + err.Error()
			exchange.Error = err.Error()
			return exchange
		}
		exchange.Response = &response
		stages[stage] = exchange
		return exchange
	}
	control := func(stage string, body, pending string) {
		exchange := &SupervisionPSExchange{Stage: stage}
		exchanges = append(exchanges, exchange)
		if executionError != "" {
			return
		}
		if reach.control == nil {
			executionError = stage + ": the deployment names no control"
			exchange.Error = executionError
			return
		}
		response, err := reach.control(ctx, body, pending)
		if err == nil && response.Status != http.StatusOK {
			err = fmt.Errorf("host control answered %d: %s", response.Status, strings.TrimSpace(string(response.Body)))
		}
		if err != nil {
			executionError = stage + ": " + err.Error()
			exchange.Error = err.Error()
			return
		}
		exchange.Response = &response
		stages[stage] = exchange
	}
	personBody, _ := json.Marshal(map[string]any{"resource": f.Origin})
	actStage := "person"
	person := send("person", "POST", p.personURL(), personBody)
	if input.Act == "mission_proposal" && executionError == "" {
		if person.Response.Status != http.StatusOK {
			executionError = fmt.Sprintf("person: prerequisite person token answered %d", person.Response.Status)
		} else {
			body, _ := json.Marshal(map[string]any{"description": supervisionPSProposal})
			send("mission", "POST", reach.mission, body)
			actStage = "mission"
		}
	}
	if input.Act == "auth_token" && executionError == "" {
		token, err := responseToken(*person.Response, "person_token")
		var claims map[string]any
		if err == nil {
			_, claims, err = verifyJWTWith(token, p.keys(), "aa-person+jwt")
		}
		if err != nil {
			executionError = "person: prerequisite person token: " + err.Error()
		} else {
			resource, _ := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", map[string]any{"iss": f.Origin, "dwk": "aauth-resource.json", "aud": p.Issuer, "ps": p.Issuer, "sub": claims["sub"], "presented_jti": claims["jti"], "agent_jkt": thumbprint(f.AgentSeed), "jti": scenario.ID + "-resource", "iat": f.Now - 1, "exp": f.Now + 120, "scope": "read"})
			body, _ := json.Marshal(map[string]any{"resource_token": resource, "presented_token": token})
			send("token", "POST", p.tokenURL(), body)
			actStage = "token"
		}
	}
	// The held act's pending URL, which a deployed server's control is told.
	held := ""
	if pending := stages[actStage]; pending != nil && pending.Response != nil {
		held, _ = pendingLocation(*pending.Response, p.Issuer)
	}
	switch input.Decision {
	case "ask", "server-error":
		control("resolve", `{"resolve":"allow"}`, held)
	case "defer":
		control("advance", `{"advance":true}`, held)
	}
	if slices.Contains([]string{"ask", "server-error", "defer"}, input.Decision) && executionError == "" {
		if pending := stages[actStage]; pending != nil && pending.Response != nil {
			location, ok := pendingLocation(*pending.Response, p.Issuer)
			if !ok {
				executionError = actStage + ": the PS returned no same-origin pending URL"
			} else {
				send("poll", "GET", location, nil)
			}
		}
	}
	if input.SecondAct {
		send("person-again", "POST", p.personURL(), personBody)
	}
	if reach.control != nil {
		control("deliver", `{"deliver":true}`, "")
	}
	observed := harness.snapshot()
	if reach.graded != nil {
		observed = reach.graded(observed)
	}
	tokenName := "person_token"
	tokenType := "aa-person+jwt"
	if input.Act == "auth_token" {
		tokenName, tokenType = "auth_token", "aa-auth+jwt"
	}
	c.Evidence = map[string]any{"agent_exchanges": exchanges, "supervisor_requests": observed}
	c.Error = executionError
	// The exact credentials the Agent presented, as the PS must forward them.
	presented := map[string]string{"agent_token": agent}
	if token := stages["token"]; token != nil && token.Request != nil {
		object, _ := jsonObject(token.Request.Body)
		for _, name := range []string{"resource_token", "presented_token"} {
			presented[name], _ = object[name].(string)
		}
	}
	for _, a := range scenario.Assertions {
		exchange := stages[a.Stage]
		var response *Response
		if exchange != nil {
			response = exchange.Response
		}
		result := Grade(a, target.Claims, executionError, response, func(a Assertion) Result {
			return checkSupervisionPS(a, f, input, exchange, stages["mission"], tokenName, tokenType, observed, presented)
		})
		c.Results = append(c.Results, result)
	}
	return c
}

// selectSSRequest returns the nth (from 1) observed request of a kind.
func selectSSRequest(observed []SSRequest, selector string) (SSRequest, bool) {
	kind, ordinal, _ := strings.Cut(selector, "#")
	want := 1
	if ordinal != "" {
		want, _ = strconv.Atoi(ordinal)
	}
	seen := 0
	for _, request := range observed {
		if request.Kind == kind {
			seen++
			if seen == want {
				return request, true
			}
		}
	}
	return SSRequest{}, false
}

func checkSupervisionPS(a Assertion, f Fixture, input SupervisionPSInput, exchange, mission *SupervisionPSExchange, tokenName, tokenType string, observed []SSRequest, presented map[string]string) Result {
	p := *f.Person
	switch a.Kind {
	case "ps-credential", "ps-credential-exp":
		if exchange == nil || exchange.Response == nil {
			return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "stage was not reached"}
		}
		name, typ := tokenName, tokenType
		if a.Stage == "person" || a.Stage == "person-again" {
			name, typ = "person_token", "aa-person+jwt"
		}
		token, err := responseToken(*exchange.Response, name)
		var claims map[string]any
		if err == nil {
			_, claims, err = verifyJWTWith(token, p.keys(), typ)
		}
		if a.Kind == "ps-credential" {
			detail := ""
			if err != nil {
				detail = err.Error()
			}
			return CompareResult(a, err == nil, detail)
		}
		if err != nil {
			return CompareResult(a, false, "no verified credential: "+err.Error())
		}
		exp, _ := claims["exp"].(float64)
		return CompareResult(a, exp > float64(f.Now) && exp <= float64(f.Now+input.AllowExp), fmt.Sprintf("credential exp %v, allow exp %d", claims["exp"], f.Now+input.AllowExp))
	case "ps-mission":
		if exchange == nil || exchange.Response == nil {
			return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "stage was not reached"}
		}
		object, _ := jsonObject(exchange.Response.Body)
		_, description, ok := approvedMission(object)
		return CompareResult(a, ok && description == supervisionPSProposal, "no mission whose s256 is the digest of its blob and whose description is the allowed one")
	case "ss-mission-match":
		report, found := selectSSRequest(observed, a.Member)
		agentView := map[string]any{}
		if mission != nil && mission.Response != nil {
			agentView, _ = jsonObject(mission.Response.Body)
		}
		reported, _ := jsonObject(report.Request.Body)
		_, _, ok := approvedMission(reported)
		same := found && ok && reported["s256"] == agentView["s256"] && reported["mission"] == agentView["mission"]
		return CompareResult(a, same, "the report's s256 and mission are not those returned to the Agent")
	case "ss-sdi-distinct":
		first, ok := selectSSRequest(observed, "decision#1")
		second, okSecond := selectSSRequest(observed, "decision#2")
		a1, _ := jsonObject(first.Request.Body)
		a2, _ := jsonObject(second.Request.Body)
		s1, _ := a1["sdi"].(string)
		s2, _ := a2["sdi"].(string)
		return CompareResult(a, ok && okSecond && s1 != "" && s2 != "" && s1 != s2, fmt.Sprintf("sdi %q and %q", s1, s2))
	}
	selector, path, _ := strings.Cut(a.Member, "/")
	request, found := selectSSRequest(observed, selector)
	if !found {
		return CompareResult(a, nil, "the PS made no "+selector+" request of the supervisor")
	}
	switch a.Kind {
	case "ss-request-proof":
		return CompareResult(a, request.Proof.ValidProof, request.Proof.Error)
	}
	var body any
	if len(request.Request.Body) > 0 && json.Unmarshal(request.Request.Body, &body) != nil {
		return CompareResult(a, nil, "request body is not JSON")
	}
	cursor, present := body, true
	for _, part := range strings.Split(path, ".") {
		object, ok := cursor.(map[string]any)
		if !ok {
			present = false
			break
		}
		cursor, present = object[part]
		if !present {
			break
		}
	}
	switch a.Kind {
	case "ss-request-has":
		nonEmpty := present && cursor != nil && cursor != ""
		return CompareResult(a, nonEmpty, "member absent or empty")
	case "ss-request-equals":
		if !present {
			return CompareResult(a, nil, "member absent")
		}
		return CompareResult(a, cursor, "")
	case "ss-request-token":
		want := presented[path]
		return CompareResult(a, present && want != "" && cursor == want, "forwarded token differs from what the Agent presented")
	}
	return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail", Detail: "unknown supervision assertion"}
}

// approvedMission checks an s256 and base64url mission pair: the s256 is the
// digest of the decoded bytes, which are a JSON blob with a description.
func approvedMission(object map[string]any) (string, string, bool) {
	s256, _ := object["s256"].(string)
	encoded, _ := object["mission"].(string)
	blob, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || s256 == "" {
		return "", "", false
	}
	digest := sha256.Sum256(blob)
	var decoded struct {
		Description string `json:"description"`
	}
	if base64.RawURLEncoding.EncodeToString(digest[:]) != s256 || json.Unmarshal(blob, &decoded) != nil {
		return "", "", false
	}
	return s256, decoded.Description, true
}
