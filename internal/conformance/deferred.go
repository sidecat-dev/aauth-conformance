package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DeferredSpec struct {
	Outcome string `json:"outcome"`
}

func validateDeferredScenario(f Fixture, s Scenario) error {
	if s.Deferred == nil || s.Person != nil || s.Federated != nil || !reflect.DeepEqual(s.Request, RequestSpec{}) || !slices.Contains([]string{"payment", "approval", "denied", "invalid-grant", "foreign-location"}, s.Deferred.Outcome) {
		return fmt.Errorf("invalid deferred profile")
	}
	copy := s
	copy.Federated = &FederatedSpec{Mutation: "none"}
	return validateFederatedScenario(f, copy)
}
func validDeferredAssertion(a Assertion) bool {
	if !slices.Contains([]string{"access", "pending", "waiting", "approval", "result", "token", "protected", "gone", "as-gone"}, a.Stage) {
		return false
	}
	if strings.HasPrefix(a.Kind, "deferred-") {
		var b any
		json.Unmarshal(a.Equals, &b)
		if _, ok := b.(bool); !ok {
			return false
		}
		switch a.Kind {
		case "deferred-pending":
			return slices.Contains([]string{"access", "pending", "approval"}, a.Stage)
		case "deferred-proof":
			return slices.Contains([]string{"access", "approval", "result"}, a.Stage)
		case "deferred-forwarded":
			return a.Stage == "access"
		case "deferred-stable":
			return a.Stage == "waiting" || a.Stage == "approval"
		}
		return false
	}
	if strings.HasPrefix(a.Kind, "ps-") {
		var b any
		json.Unmarshal(a.Equals, &b)
		_, ok := b.(bool)
		return ok && (a.Stage == "token" || a.Kind == "ps-no-token")
	}
	return slices.Contains([]string{"status", "json-member", "sfv-token"}, a.Kind)
}
func deferredLocation(r Response, base string) string {
	origin, err := url.Parse(base)
	if err != nil {
		return ""
	}
	location, err := url.Parse(r.Header.Get("Location"))
	if err != nil || len(r.Header.Values("Location")) != 1 || location.String() == "" {
		return ""
	}
	resolved := origin.ResolveReference(location)
	if resolved.Scheme != "https" || resolved.Host != origin.Host || resolved.User != nil || resolved.Fragment != "" {
		return ""
	}
	return resolved.String()
}
func validDeferredPending(r Response, base, prior string) bool {
	location := deferredLocation(r, base)
	if location == "" || prior != "" && location != prior {
		return false
	}
	if r.Status == 402 {
		return r.Header.Get("WWW-Authenticate") != ""
	}
	if r.Status != 202 || len(r.Header.Values("Retry-After")) != 1 {
		return false
	}
	if _, err := strconv.ParseUint(r.Header.Get("Retry-After"), 10, 32); err != nil {
		return false
	}
	noStore := false
	for _, part := range strings.Split(r.Header.Get("Cache-Control"), ",") {
		noStore = noStore || strings.EqualFold(strings.TrimSpace(part), "no-store")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var body struct {
		Status string `json:"status"`
	}
	return noStore && err == nil && media == "application/json" && json.Unmarshal(r.Body, &body) == nil && body.Status != ""
}

type deferredRelay struct {
	mu                           sync.Mutex
	fixture                      Fixture
	physical, mutation, location string
	expected                     map[string]string
	timeout                      time.Duration
	handoffs                     []FederatedHandoff
}

func (d *deferredRelay) reset(physical, mutation string, expected map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.physical = physical
	d.mutation = mutation
	d.expected = expected
	d.location = ""
	d.handoffs = nil
}
func (d *deferredRelay) snapshot() []FederatedHandoff {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]FederatedHandoff(nil), d.handoffs...)
}
func (d *deferredRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h := FederatedHandoff{}
	defer func() { d.handoffs = append(d.handoffs, h) }()
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(body) > 65536 {
		h.Error = "invalid bounded AS request"
		http.Error(w, h.Error, 502)
		return
	}
	h.Sent = Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}
	h.Delivered = h.Sent
	if r.Method == "POST" {
		h.Proof = observePSProof(d.fixture, h.Sent)
		var values map[string]string
		h.Forwarded = json.Unmarshal(body, &values) == nil
		for _, name := range []string{"resource_token", "agent_token", "presented_token"} {
			h.Forwarded = h.Forwarded && values[name] != "" && values[name] == d.expected[name]
		}
		if child, required := d.expected["subagent_token"]; required {
			h.Forwarded = h.Forwarded && values["subagent_token"] != "" && values["subagent_token"] == child
		}
	} else {
		h.Proof = observePSPollProof(d.fixture, h.Sent, d.location)
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, h.Sent.URL, bytes.NewReader(body))
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	request.Header = r.Header.Clone()
	response, err := Exchange(r.Context(), request, d.physical, d.timeout)
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	h.NativeResponse = &response
	if d.location == "" {
		d.location = deferredLocation(response, d.fixture.Access.Issuer+"/token")
	}
	final := response
	final.Header = response.Header.Clone()
	if d.mutation == "foreign-location" && (final.Status == 202 || final.Status == 402) {
		final.Header.Set("Location", "https://foreign.example/pending")
	}
	if d.mutation == "invalid-grant" && final.Status == 200 {
		final, err = mutateASResponse(d.fixture, "grant-signature", final)
		if err != nil {
			h.Error = err.Error()
			http.Error(w, h.Error, 502)
			return
		}
	}
	h.DeliveredResponse = &final
	for k, v := range final.Header {
		if !strings.EqualFold(k, "Content-Length") {
			w.Header()[k] = append([]string(nil), v...)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(final.Body)))
	w.WriteHeader(final.Status)
	_, _ = w.Write(final.Body)
}

func runDeferred(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	f, p, a := s.Fixture, *s.Fixture.Person, *s.Fixture.Access
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		relay := &deferredRelay{fixture: f, timeout: options.Timeout}
		listener := httptest.NewServer(relay)
		config := Bootstrap{Version: 1, Role: DeferredRole, Now: f.Now, Issuer: f.Issuer, Resource: f.Origin + f.Path, APTransport: ap, PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid, PersonSubject: p.Subject, PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime, PermittedScopes: p.PermittedScopes, ResourceKid: p.ResourceKid, ResourceJWK: publicJWK(p.ResourceSeed), ResourceSeed: p.ResourceSeed, AccessServer: a.Issuer, AccessSeed: a.Seed, AccessKid: a.Kid, FederationTransport: listener.URL}
		ready, stop, startError := startAdapter(ctx, target, config, options)
		if startError != nil {
			run.Error = startError.Error()
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runDeferredCase(ctx, f, scenario, target, ready.URL, options, relay, startError))
		}
		if stop != nil {
			stop()
		}
		listener.Close()
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}
func runDeferredCase(ctx context.Context, f Fixture, s Scenario, target Target, physical string, options Options, relay *deferredRelay, startError error) Case {
	c := Case{ID: s.ID}
	responses := map[string]Response{}
	observations := map[string]PersonObservation{}
	proofs := map[string]bool{}
	forwarded := false
	locations := map[string]string{}
	exchange := func(stage string, request *http.Request, base string) (Response, error) {
		body := []byte(nil)
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
		e := PersonExchange{Stage: stage, Method: request.Method, URL: request.URL.String(), Headers: request.Header.Clone(), Body: body, SignatureBase: base}
		response, err := Exchange(ctx, request, physical, options.Timeout)
		if err != nil {
			e.Error = err.Error()
		} else {
			e.Response = &response
			responses[stage] = response
		}
		c.Exchanges = append(c.Exchanges, e)
		return response, err
	}
	send := func(stage, method, location, token string, body []byte) (Response, error) {
		r, base, err := signedFixtureRequest(f, f.AgentSeed, method, location, `sig=jwt;jwt="`+token+`"`, body)
		if err != nil {
			return Response{}, err
		}
		return exchange(stage, r, base)
	}
	control := func(stage int, id string) error {
		body, _ := json.Marshal(map[string]any{"stage": stage, "reference": id})
		r, _ := http.NewRequest("POST", f.Person.Issuer+"/__fixture/deferred", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		response, err := exchange("host-control", r, "")
		if err == nil && response.Status != 204 {
			err = fmt.Errorf("host control HTTP %d", response.Status)
		}
		return err
	}
	capture := func(stage string) error {
		c.DeferredHandoffs = relay.snapshot()
		if len(c.DeferredHandoffs) == 0 {
			return fmt.Errorf("no AS exchange")
		}
		h := c.DeferredHandoffs[len(c.DeferredHandoffs)-1]
		if h.Error != "" {
			return fmt.Errorf("AS handoff: %s", h.Error)
		}
		if h.NativeResponse == nil {
			return fmt.Errorf("no native AS response")
		}
		responses[stage] = *h.NativeResponse
		proofs[stage] = h.Proof.ValidProof
		if stage == "access" {
			forwarded = h.Forwarded
			locations["access"] = deferredLocation(*h.NativeResponse, f.Access.Issuer+"/token")
		}
		return nil
	}
	execute := func() error {
		if startError != nil {
			return startError
		}
		stage := 0
		if s.Deferred.Outcome == "approval" {
			stage = 1
		}
		if err := control(stage, ""); err != nil {
			return err
		}
		agentExp := f.Now + s.Token.EXPOffset
		token, err := federationAgentToken(f, s.ID, f.Now+s.Token.IATOffset, agentExp)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]string{"resource": f.Origin})
		personResponse, err := send("person", "POST", f.Person.Issuer+"/person", token, body)
		if err != nil {
			return err
		}
		person, err := responseToken(personResponse, "person_token")
		if err != nil {
			return err
		}
		po := observePersonJWT(f, *f.Person, person, "person", nil, agentExp)
		if !po.Valid {
			return fmt.Errorf("invalid Person token: %s", po.Error)
		}
		challenge, err := send("challenge", "GET", f.Origin+f.Path, person, nil)
		if err != nil {
			return err
		}
		resource, err := challengedResourceToken(challenge)
		if err != nil {
			return err
		}
		if ro := observeFederatedResource(f, resource, po.Claims); !ro.Valid {
			return fmt.Errorf("invalid Resource token: %s", ro.Error)
		}
		relay.reset(physical, s.Deferred.Outcome, map[string]string{"resource_token": resource, "presented_token": person, "agent_token": token})
		body, _ = json.Marshal(map[string]string{"resource_token": resource, "presented_token": person})
		pending, err := send("pending", "POST", f.Person.Issuer+"/token", token, body)
		if err != nil {
			return err
		}
		if err = capture("access"); err != nil {
			return err
		}
		if s.Deferred.Outcome == "foreign-location" {
			return nil
		}
		location := deferredLocation(pending, f.Person.Issuer+"/token")
		if location == "" {
			return fmt.Errorf("invalid PS pending Location")
		}
		locations["pending"] = location
		id := location[strings.LastIndex(location, "/")+1:]
		if _, err = send("waiting", "GET", location, token, nil); err != nil {
			return err
		}
		if len(relay.snapshot()) != 1 {
			return fmt.Errorf("Agent poll caused an implicit AS request")
		}
		if s.Deferred.Outcome == "payment" {
			if err = control(1, id); err != nil {
				return err
			}
			if err = capture("approval"); err != nil {
				return err
			}
		}
		stage = 2
		if s.Deferred.Outcome == "denied" {
			stage = -1
		}
		if err = control(stage, id); err != nil {
			return err
		}
		if err = capture("result"); err != nil {
			return err
		}
		result, err := send("token", "GET", location, token, nil)
		if err != nil {
			return err
		}
		if result.Status == 200 {
			compact, err := responseToken(result, "auth_token")
			if err != nil {
				return err
			}
			o := checkResponseExpiry(result, observeFederatedAuth(f, compact, po.Claims, agentExp))
			observations["token"] = o
			if s.Deferred.Outcome == "payment" || s.Deferred.Outcome == "approval" {
				if !o.Valid {
					return fmt.Errorf("invalid delivered grant: %s", o.Error)
				}
				if _, err = send("protected", "GET", f.Origin+f.Path, compact, nil); err != nil {
					return err
				}
			}
		}
		if _, err = send("gone", "GET", location, token, nil); err != nil {
			return err
		}
		r, base, err := signedFixtureRequest(f, f.Person.Seed, "GET", locations["access"], fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-person.json";kid=%q`, f.Person.Issuer, f.Person.Kid), nil)
		if err != nil {
			return err
		}
		_, err = exchange("as-gone", r, base)
		return err
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	for i := range c.Exchanges {
		if o, ok := observations[c.Exchanges[i].Stage]; ok {
			c.Exchanges[i].JWT = &o
		}
	}
	for _, a := range s.Assertions {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals}
		response, ok := responses[a.Stage]
		switch {
		case !slices.Contains(target.Claims, a.Clause):
			result.State = "not_claimed"
		case !ok:
			result.State = "error"
			result.Detail = "required stage not exercised: " + c.Error
		case strings.HasPrefix(a.Kind, "deferred-"):
			actual := false
			switch a.Kind {
			case "deferred-pending":
				base := f.Access.Issuer + "/token"
				if a.Stage == "pending" {
					base = f.Person.Issuer + "/token"
				}
				actual = validDeferredPending(response, base, "")
			case "deferred-proof":
				var observed bool
				actual, observed = proofs[a.Stage]
				if !observed {
					result.State = "error"
					result.Detail = "required proof observation is missing"
					c.Results = append(c.Results, result)
					continue
				}
			case "deferred-forwarded":
				actual = forwarded
			case "deferred-stable":
				base, prior := f.Access.Issuer+"/token", locations["access"]
				if a.Stage == "waiting" {
					base, prior = f.Person.Issuer+"/token", locations["pending"]
				}
				actual = validDeferredPending(response, base, prior)
			}
			result.Actual = actual
			var want bool
			json.Unmarshal(a.Equals, &want)
			result.State = "fail"
			if actual == want {
				result.State = "pass"
			}
		default:
			result = checkPerson(a, response, observations[a.Stage])
		}
		c.Results = append(c.Results, result)
	}
	return c
}
