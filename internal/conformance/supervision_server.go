package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// SupervisionServerInput is one SS scenario: an ordered script of signed
// requests from the harness Person Server and host controls. A step names
// the stage its assertions grade.
type SupervisionServerInput struct {
	Steps []SupervisionStep `json:"steps"`
}
type SupervisionStep struct {
	Stage string `json:"stage"`
	// Endpoint is metadata, connect, mission, mission/$s256, decision, event,
	// or location:<stage> for the pending URL an earlier stage returned.
	Endpoint string `json:"endpoint,omitempty"`
	Method   string `json:"method,omitempty"`
	// Body is a JSON template; placeholders are listed in FORMAT.md.
	Body json.RawMessage `json:"body,omitempty"`
	// Signer is ps (default), other-ps or unsigned.
	Signer string `json:"signer,omitempty"`
	// OmitBodyComponents leaves content-type and content-digest uncovered.
	OmitBodyComponents bool `json:"omit_body_components,omitempty"`
	AcceptSignature    bool `json:"accept_signature,omitempty"`
	// Repeat resends the exact request bytes of an earlier stage.
	Repeat string `json:"repeat,omitempty"`
	// Control is a host-control body for the launcher instead of a request.
	Control json.RawMessage `json:"control,omitempty"`
	// Expect is a prerequisite status; any other ends the case as an error.
	Expect int `json:"expect,omitempty"`
}

// The components every signed decision covers, and those a PS asks for.
const supervisionAcceptSignature = `sig=("@status" "content-type" "content-digest" "content-digest";req "@authority";req "@path";req)`
const supervisionPollAcceptSignature = `sig=("@status" "content-type" "content-digest" "@authority";req "@path";req)`

func validateSupervisionServerScenario(f Fixture, s Scenario) error {
	if _, err := supervisionFixture(f); err != nil {
		return err
	}
	var input SupervisionServerInput
	if err := DecodeInput(s, &input); err != nil {
		return err
	}
	stages := map[string]bool{}
	controls := map[string]bool{}
	for _, step := range input.Steps {
		if step.Stage == "" || stages[step.Stage] || controls[step.Stage] {
			return fmt.Errorf("%s: each step needs a unique stage", s.ID)
		}
		if len(step.Control) > 0 {
			if step.Endpoint != "" || step.Body != nil || step.Repeat != "" || step.Signer != "" || !json.Valid(step.Control) {
				return fmt.Errorf("%s/%s: a control step carries only control", s.ID, step.Stage)
			}
			controls[step.Stage] = true
			continue
		}
		switch {
		case step.Repeat != "":
			if !stages[step.Repeat] || step.Endpoint != "" || step.Body != nil {
				return fmt.Errorf("%s/%s: repeat names an earlier request stage only", s.ID, step.Stage)
			}
		case strings.HasPrefix(step.Endpoint, "location:"):
			if !stages[strings.TrimPrefix(step.Endpoint, "location:")] || step.Body != nil {
				return fmt.Errorf("%s/%s: location names an earlier stage and carries no body", s.ID, step.Stage)
			}
		case slices.Contains([]string{"metadata", "connect", "mission", "mission/$s256", "decision", "event"}, step.Endpoint):
			if (step.Endpoint == "metadata") != (step.Body == nil) {
				return fmt.Errorf("%s/%s: metadata is a bodyless GET; other endpoints take a body", s.ID, step.Stage)
			}
		default:
			return fmt.Errorf("%s/%s: unknown endpoint %q", s.ID, step.Stage, step.Endpoint)
		}
		if !slices.Contains([]string{"", "ps", "other-ps", "unsigned"}, step.Signer) || !slices.Contains([]string{"", "GET", "POST", "DELETE"}, step.Method) || step.Expect != 0 && (step.Expect < 100 || step.Expect > 599) {
			return fmt.Errorf("%s/%s: unsupported signer, method or expect", s.ID, step.Stage)
		}
		if step.Body != nil {
			var template any
			if err := json.Unmarshal(step.Body, &template); err != nil {
				return err
			}
			if _, err := substitute(template, supervisionPlaceholders(f, SupervisionFixture{}, s.ID)); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, step.Stage, err)
			}
		}
		stages[step.Stage] = true
	}
	if len(stages) == 0 {
		return fmt.Errorf("%s: at least one request step", s.ID)
	}
	for _, a := range s.Assertions {
		if !stages[a.Stage] {
			return fmt.Errorf("%s/%s: assertion stage must name a request step", s.ID, a.ID)
		}
		switch a.Kind {
		case "ss-same-response", "ss-same-location":
			if !stages[a.Member] || a.Member == a.Stage {
				return fmt.Errorf("%s/%s: %s compares with another request stage in member", s.ID, a.ID, a.Kind)
			}
			fallthrough
		case "ss-signed", "ss-pending", "ss-metadata-endpoints", "ss-retry-after", "ss-no-decision":
			if err := boolEquals(a); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
			}
		}
	}
	return nil
}

// supervisionPlaceholders are the values a body template may name. The
// fixture is decoded again so validation sees the same names as the run.
func supervisionPlaceholders(f Fixture, s SupervisionFixture, id string) map[string]any {
	if s.Issuer == "" {
		s, _ = supervisionFixture(f)
	}
	_, mission, s256 := supervisionMission(f, s)
	values := map[string]any{"$now": f.Now, "$exp": f.Now + 60, "$sub": s.Subject, "$agent": f.Subject, "$mission": mission, "$s256": s256, "$resource": f.Origin}
	for name, token := range supervisionTokens(f, id) {
		values[name] = token
	}
	return values
}

type ssStepRecord struct {
	Stage    string             `json:"stage"`
	Request  *Captured          `json:"request,omitempty"`
	Response *Response          `json:"response,omitempty"`
	Signed   *ResponseSignature `json:"response_signature,omitempty"`
	Control  json.RawMessage    `json:"control,omitempty"`
	Error    string             `json:"error,omitempty"`
}

func runSupervisionServers(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	ss, _ := supervisionFixture(s.Fixture)
	p := *s.Fixture.Person
	extension, _ := json.Marshal(map[string]any{
		"supervisor": map[string]any{"issuer": ss.Issuer, "seed_hex": ss.Seed, "kid": ss.Kid},
		"person_servers": []map[string]any{
			{"issuer": p.Issuer, "kid": p.Kid, "jwk": publicJWK(p.Seed), "accept": true},
			{"issuer": ss.OtherPS.Issuer, "kid": ss.OtherPS.Kid, "jwk": publicJWK(ss.OtherPS.Seed), "accept": false},
		},
	})
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			// A fresh native SS per scenario keeps connections, decisions and
			// deliveries from one case out of another.
			config := Bootstrap{Version: 1, Role: SupervisionServerRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: ss.Issuer + "/.well-known/aauth-supervisor.json", APTransport: ap, Extension: extension}
			ready, stop, startError := Ready{}, func() {}, error(nil)
			if target.Unavailable == "" {
				ready, stop, startError = startAdapter(ctx, target, config, options)
			}
			c := runSupervisionServerCase(ctx, s.Fixture, ss, scenario, target, ready.URL, options, startError)
			if stop != nil {
				stop()
			}
			run.Cases = append(run.Cases, c)
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func runSupervisionServerCase(ctx context.Context, f Fixture, ss SupervisionFixture, scenario Scenario, target Target, ready string, options Options, startError error) Case {
	c := Case{ID: scenario.ID}
	var input SupervisionServerInput
	DecodeInput(scenario, &input)
	values := supervisionPlaceholders(f, ss, scenario.ID)
	physical := ""
	if ready != "" {
		physical = strings.TrimSuffix(ready, "/.well-known/aauth-supervisor.json")
	}
	records := map[string]*ssStepRecord{}
	sent := map[string][]byte{}
	var trail []*ssStepRecord
	notOffered := ""
	executionError := ""
	if target.Unavailable != "" {
		notOffered = target.Unavailable
	}
	if startError != nil {
		executionError = startError.Error()
	}
	for _, step := range input.Steps {
		if executionError != "" || notOffered != "" {
			break
		}
		record := &ssStepRecord{Stage: step.Stage}
		trail = append(trail, record)
		if len(step.Control) > 0 {
			record.Control = step.Control
			response, err := supervisionControl(ctx, physical, step.Control, options.Timeout)
			switch {
			case err != nil:
				executionError = step.Stage + ": " + err.Error()
			case response.Status == http.StatusNotImplemented:
				var declared struct {
					NotOffered string `json:"not_offered"`
				}
				json.Unmarshal(response.Body, &declared)
				notOffered = declared.NotOffered
				if notOffered == "" {
					notOffered = "the launcher declares this host control unavailable"
				}
			case response.Status != http.StatusOK:
				executionError = fmt.Sprintf("%s: host control answered %d", step.Stage, response.Status)
			}
			record.Response = &response
			continue
		}
		request, raw, err := buildSupervisionStep(f, ss, step, values, records, sent)
		if err != nil {
			executionError = step.Stage + ": " + err.Error()
			record.Error = err.Error()
			break
		}
		sent[step.Stage] = raw
		captured := Captured{Method: request.Method, URL: request.URL.String(), Headers: request.Header.Clone(), Body: requestBody(raw)}
		record.Request = &captured
		response, err := Exchange(ctx, request, physical, options.Timeout)
		if err != nil {
			executionError = step.Stage + ": " + err.Error()
			record.Error = err.Error()
			break
		}
		record.Response = &response
		if len(response.Header.Values("Signature-Key")) > 0 {
			_, observed := signedDecision(ss, response, captured)
			record.Signed = &observed
		}
		records[step.Stage] = record
		if step.Expect != 0 && response.Status != step.Expect {
			executionError = fmt.Sprintf("%s: prerequisite expected HTTP %d, observed %d", step.Stage, step.Expect, response.Status)
		}
	}
	c.Evidence = map[string]any{"steps": trail, "not_offered": notOffered}
	c.Error = executionError
	for _, a := range scenario.Assertions {
		record := records[a.Stage]
		var response *Response
		if record != nil {
			response = record.Response
		}
		result := Grade(a, target.Claims, executionError, response, func(a Assertion) Result {
			return checkSupervisionServer(a, ss, record, records)
		})
		if notOffered != "" && result.State != "not_claimed" {
			result = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: "not offered: " + notOffered}
		} else if record == nil && result.State != "not_claimed" && result.State != "error" {
			result = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "stage was not reached"}
		}
		c.Results = append(c.Results, result)
	}
	return c
}

func requestBody(raw []byte) []byte {
	if raw == nil {
		return nil
	}
	_, body, _ := splitStoredRequest(raw)
	return body
}

// A stored request is its method line, headers and body, so a repeat sends
// exactly the bytes of the original.
func storeRequest(request *http.Request, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s\n", request.Method, request.URL.String())
	for name, values := range request.Header {
		for _, value := range values {
			fmt.Fprintf(&b, "%s: %s\n", name, value)
		}
	}
	b.WriteString("\n")
	b.Write(body)
	return b.Bytes()
}
func splitStoredRequest(raw []byte) (*http.Request, []byte, error) {
	head, body, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		return nil, nil, fmt.Errorf("stored request is malformed")
	}
	lines := strings.Split(string(head), "\n")
	method, target, _ := strings.Cut(lines[0], " ")
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for _, line := range lines[1:] {
		name, value, _ := strings.Cut(line, ": ")
		request.Header.Add(name, value)
	}
	return request, body, nil
}

func buildSupervisionStep(f Fixture, ss SupervisionFixture, step SupervisionStep, values map[string]any, records map[string]*ssStepRecord, sent map[string][]byte) (*http.Request, []byte, error) {
	if step.Repeat != "" {
		request, _, err := splitStoredRequest(sent[step.Repeat])
		return request, sent[step.Repeat], err
	}
	method := step.Method
	var target string
	switch {
	case step.Endpoint == "metadata":
		request, err := http.NewRequest("GET", ss.Issuer+"/.well-known/aauth-supervisor.json", nil)
		if err != nil {
			return nil, nil, err
		}
		return request, storeRequest(request, nil), nil
	case strings.HasPrefix(step.Endpoint, "location:"):
		earlier := records[strings.TrimPrefix(step.Endpoint, "location:")]
		if earlier == nil || earlier.Response == nil {
			return nil, nil, fmt.Errorf("no pending URL from %s", step.Endpoint)
		}
		location, ok := pendingLocation(*earlier.Response, ss.Issuer)
		if !ok {
			return nil, nil, fmt.Errorf("%s returned no same-origin pending URL", step.Endpoint)
		}
		target = location
		if method == "" {
			method = "GET"
		}
	case step.Endpoint == "mission/$s256":
		target = ss.Issuer + "/mission/" + values["$s256"].(string)
	default:
		target = ss.Issuer + "/" + step.Endpoint
	}
	if method == "" {
		method = "POST"
	}
	var body []byte
	if step.Body != nil {
		var template any
		json.Unmarshal(step.Body, &template)
		filled, err := substitute(template, values)
		if err != nil {
			return nil, nil, err
		}
		if body, err = json.Marshal(filled); err != nil {
			return nil, nil, err
		}
	}
	accept := ""
	if step.AcceptSignature {
		accept = supervisionAcceptSignature
		if method == "GET" {
			accept = supervisionPollAcceptSignature
		}
	}
	p := *f.Person
	seed, issuer, kid := p.Seed, p.Issuer, p.Kid
	switch step.Signer {
	case "other-ps":
		seed, issuer, kid = ss.OtherPS.Seed, ss.OtherPS.Issuer, ss.OtherPS.Kid
	case "unsigned":
		request, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		return request, storeRequest(request, body), nil
	}
	request, _, err := signServerRequest(f, seed, issuer, "aauth-person.json", kid, method, target, body, accept, step.OmitBodyComponents)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Prefer", "wait=30")
	return request, storeRequest(request, body), nil
}

// supervisionControl posts a host-control body to the launcher's loopback
// control path. Its answer is evidence of host input, never protocol output.
func supervisionControl(ctx context.Context, physical string, body json.RawMessage, timeout time.Duration) (Response, error) {
	if physical == "" {
		return Response{}, fmt.Errorf("launcher is not running")
	}
	request, err := http.NewRequestWithContext(ctx, "POST", physical+"/__fixture/supervision", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: response.StatusCode, Header: response.Header.Clone(), Body: b}, nil
}

func checkSupervisionServer(a Assertion, ss SupervisionFixture, record *ssStepRecord, records map[string]*ssStepRecord) Result {
	if record == nil || record.Response == nil {
		return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "stage was not reached"}
	}
	r := *record.Response
	switch a.Kind {
	case "ss-signed":
		ok, observed := signedDecision(ss, r, *record.Request)
		return CompareResult(a, ok, observed.Error)
	case "ss-same-response":
		earlier := records[a.Member]
		if earlier == nil || earlier.Response == nil {
			return CompareResult(a, false, "earlier stage has no response")
		}
		same := earlier.Response.Status == r.Status && bytes.Equal(earlier.Response.Body, r.Body)
		for _, name := range []string{"Signature", "Signature-Input", "Signature-Key", "Content-Digest"} {
			same = same && canonicalField(earlier.Response.Header, name) == canonicalField(r.Header, name)
		}
		return CompareResult(a, same, "status, body or signature fields differ")
	case "ss-pending":
		_, located := pendingLocation(r, ss.Issuer)
		return CompareResult(a, r.Status == http.StatusAccepted && located && validRetryAfter(r), "not a 202 with same-origin Location and integer Retry-After")
	case "ss-same-location":
		earlier := records[a.Member]
		if earlier == nil || earlier.Response == nil {
			return CompareResult(a, false, "earlier stage has no response")
		}
		first, ok := pendingLocation(*earlier.Response, ss.Issuer)
		again, okAgain := pendingLocation(r, ss.Issuer)
		return CompareResult(a, ok && okAgain && first == again, "pending URLs differ or are absent")
	case "ss-metadata-endpoints":
		object, ok := jsonObject(r.Body)
		valid := ok && r.Status == http.StatusOK
		for _, member := range []string{"connect_endpoint", "mission_endpoint", "decision_endpoint", "event_endpoint"} {
			endpoint, isString := object[member].(string)
			valid = valid && isString && (endpoint == ss.Issuer || strings.HasPrefix(endpoint, ss.Issuer+"/"))
		}
		return CompareResult(a, valid, "an endpoint is absent, not HTTPS or not on the issuer's origin")
	case "ss-retry-after":
		return CompareResult(a, validRetryAfter(r), "Retry-After is absent or not an integer")
	case "ss-no-decision":
		object, ok := jsonObject(r.Body)
		_, decided := object["decision"]
		return CompareResult(a, !ok || !decided, "the refusal carries a decision")
	}
	return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail", Detail: "unknown supervision assertion"}
}
