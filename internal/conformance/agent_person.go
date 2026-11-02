package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// personFlow plays, for one agent.signing scenario at the person endpoint,
// a Resource that requires a Person token and the Agent's Person Server
// (protocol, Person Token Required and Person Token Endpoint). The Resource
// answers a valid Agent-token request with requirement=person-token; the
// Person Server issues a fixture Person token for a valid Person token
// request; the Resource accepts a retry presenting exactly that token. Both
// publish their metadata, which an Agent may read first: the Person Server
// the four members Person Server Metadata requires, the Resource its issuer,
// unless the fixture's resource_metadata_unpublished has it publish none.
type personFlow struct {
	f        Fixture
	job      AgentJob
	agentExp int64
	mu       sync.Mutex
	arrived  []personArrival
	issued   string
	close    func()
}

type personArrival struct {
	stage    string
	captured Captured
	status   int
}

// personEndpoint is the request endpoint value that selects the fixture's
// person_path.
const personEndpoint = "person"

// metadataStage marks a metadata fetch: kept as evidence, never graded.
const metadataStage = "metadata"

// withPersonTrust names the fixture Person Server and its public key, for a
// launcher that verifies Person tokens it does not issue.
func (b *Bootstrap) withPersonTrust(f Fixture) {
	if f.Person == nil {
		return
	}
	b.PersonServer, b.PersonKid, b.PersonJWK = f.Person.Issuer, f.Person.Kid, publicJWK(f.Person.Seed)
}

func startPersonFlow(f Fixture, job AgentJob, agentExp int64) (*personFlow, AgentJob, error) {
	resource, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, job, err
	}
	person, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		resource.Close()
		return nil, job, err
	}
	job.Transport = "http://" + resource.Addr().String()
	job.PersonTokenEndpoint = f.Person.personURL()
	job.PersonTransport = "http://" + person.Addr().String()
	p := &personFlow{f: f, job: job, agentExp: agentExp}
	servers := []*http.Server{
		{Handler: http.HandlerFunc(p.serveResource), ReadHeaderTimeout: 3 * time.Second},
		{Handler: http.HandlerFunc(p.servePerson), ReadHeaderTimeout: 3 * time.Second},
	}
	done := make(chan struct{}, 2)
	for i, listener := range []net.Listener{resource, person} {
		go func() { servers[i].Serve(listener); done <- struct{}{} }()
	}
	p.close = func() {
		for _, server := range servers {
			server.Close()
		}
		<-done
		<-done
	}
	return p, job, nil
}

func capturedRequest(r *http.Request, limit int64) (Captured, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err == nil && int64(len(body)) > limit {
		err = fmt.Errorf("body over %d bytes", limit)
	}
	return Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}, err
}

func (p *personFlow) record(stage string, c Captured, status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.arrived = append(p.arrived, personArrival{stage: stage, captured: c, status: status})
}

func (p *personFlow) issuedToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.issued
}

// serveMetadata answers a GET for a metadata document: the document, or
// 404 when it is nil because the party publishes none.
func (p *personFlow) serveMetadata(w http.ResponseWriter, r *http.Request, path string, document map[string]string) bool {
	if r.Method != http.MethodGet || r.URL.Path != path {
		return false
	}
	c, _ := capturedRequest(r, 1024)
	if document == nil {
		p.record(metadataStage, c, http.StatusNotFound)
		http.NotFound(w, r)
		return true
	}
	p.record(metadataStage, c, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(document)
	return true
}

// resourceMetadata is the Resource's document, nil when it publishes none.
func (p *personFlow) resourceMetadata() map[string]string {
	if p.f.ResourceMetadataUnpublished {
		return nil
	}
	return map[string]string{"issuer": p.f.Origin}
}

func (p *personFlow) serveResource(w http.ResponseWriter, r *http.Request) {
	if p.serveMetadata(w, r, "/.well-known/aauth-resource.json", p.resourceMetadata()) {
		return
	}
	c, err := capturedRequest(r, 1024)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusUnauthorized
	switch {
	case err != nil:
		status = http.StatusBadRequest
	case p.validRetry(c):
		status = http.StatusOK
	case ObserveAgent(p.f, c).ValidProof && len(c.Body) == 0:
		w.Header().Set("AAuth-Requirement", "requirement=person-token")
	default:
		w.Header().Set("Signature-Error", "error=invalid_signature")
	}
	p.record("resource", c, status)
	w.WriteHeader(status)
	io.WriteString(w, `{"received":true}`)
}

func (p *personFlow) servePerson(w http.ResponseWriter, r *http.Request) {
	person := p.f.Person
	if p.serveMetadata(w, r, "/.well-known/aauth-person.json", map[string]string{
		"issuer": person.Issuer, "jwks_uri": person.Issuer + "/.well-known/jwks.json",
		"auth_token_endpoint": person.tokenURL(), "person_token_endpoint": person.personURL(),
	}) {
		return
	}
	c, err := capturedRequest(r, 16384)
	w.Header().Set("Content-Type", "application/json")
	if err != nil || !p.validRequest(c) {
		p.record("person", c, http.StatusUnauthorized)
		w.Header().Set("Signature-Error", "error=invalid_signature")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_signature"}`)
		return
	}
	exp := min(p.f.Now+person.Lifetime, p.agentExp)
	token, err := mintJWT(person.Seed, person.Kid, "aa-person+jwt", map[string]any{
		"iss": person.Issuer, "dwk": "aauth-person.json", "aud": p.f.Origin, "sub": person.Subject,
		"jti": "person-flow-1", "iat": p.f.Now, "exp": exp, "cnf": map[string]any{"jwk": publicJWK(p.f.AgentSeed)},
	})
	if err != nil {
		p.record("person", c, http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.issued = token
	p.mu.Unlock()
	p.record("person", c, http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"person_token": token, "expires_in": exp - p.f.Now})
}

// signedAtNow requires a proof created within the 60-second window that
// covers the profile components and every one of extra.
func signedAtNow(f Fixture, o Observation, extra ...string) bool {
	if !o.ValidProof || o.Created < f.Now-60 || o.Created > f.Now+60 {
		return false
	}
	for _, component := range append([]string{"@method", "@authority", "@path", "signature-key"}, extra...) {
		if !slices.Contains(o.Covered, component) {
			return false
		}
	}
	return true
}

// validRequest checks the Person token request: a POST to the
// person_token_endpoint signed with the job's Agent token, covering the
// JSON body by its actual digest, and naming this Resource.
func (p *personFlow) validRequest(c Captured) bool {
	o := ObserveAgent(p.f, c)
	mediaType, _, err := mime.ParseMediaType(canonicalField(c.Headers, "Content-Type"))
	sum := sha256.Sum256(c.Body)
	var body struct {
		Resource string `json:"resource"`
	}
	decoder := json.NewDecoder(bytes.NewReader(c.Body))
	return c.Method == http.MethodPost && c.URL == p.job.PersonTokenEndpoint && o.Token == p.job.Token &&
		signedAtNow(p.f, o, "content-type", "content-digest") &&
		err == nil && strings.EqualFold(mediaType, "application/json") &&
		contentDigestMatches(c.Headers.Values("Content-Digest"), sum[:]) &&
		decoder.Decode(&body) == nil && body.Resource == p.f.Origin
}

// validRetry checks a Resource request presenting exactly the issued
// Person token, signed by the Agent key it confirms.
func (p *personFlow) validRetry(c Captured) bool {
	issued := p.issuedToken()
	if issued == "" {
		return false
	}
	o := observeAgentKey(p.f, c, func(token string) bool { return token == issued })
	return c.Method == p.job.Method && c.URL == p.job.URL && len(c.Body) == 0 && signedAtNow(p.f, o)
}

// check grades one person-flow assertion from what arrived.
func (p *personFlow) check(a Assertion) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	var expected any
	json.Unmarshal(a.Equals, &expected)
	var requests, retries []personArrival
	for _, arrival := range p.arrivals() {
		switch {
		case arrival.stage == "person":
			requests = append(requests, arrival)
		case arrival.stage == "resource" && arrival.status == http.StatusOK:
			retries = append(retries, arrival)
		}
	}
	var actual bool
	switch a.Kind {
	case "wire-person-request":
		actual = len(requests) == 1 && requests[0].status == http.StatusOK
		if !actual {
			result.Detail = fmt.Sprintf("%d Person token requests reached the Person Server; one valid one is required", len(requests))
		}
	case "wire-person-token":
		actual = len(retries) == 1
		if !actual {
			result.Detail = "no retry presented the issued Person token under a valid Agent-key signature"
		}
	default:
		result.Detail = "unknown person-flow assertion"
		return result
	}
	result.Actual = actual
	if expected == actual {
		result.State = "pass"
		result.Detail = ""
	}
	return result
}

func (p *personFlow) arrivals() []personArrival {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.arrived)
}

// exchanges is the case evidence: every request in arrival order.
func (p *personFlow) exchanges() []PersonExchange {
	var out []PersonExchange
	for _, arrival := range p.arrivals() {
		c := arrival.captured
		out = append(out, PersonExchange{Stage: arrival.stage, Method: c.Method, URL: c.URL, Headers: c.Headers, Body: c.Body,
			Response: &Response{Status: arrival.status}})
	}
	return out
}

// runPersonFlowCase sends one Agent job whose Resource requires a Person
// token and grades the exchanges that follow.
func runPersonFlowCase(ctx context.Context, f Fixture, scenario Scenario, target Target, control string, options Options, startError error) Case {
	c := Case{ID: scenario.ID}
	token, executionError := MintToken(f, scenario.Token, scenario.ID)
	job := AgentJob{Method: scenario.Request.Method, URL: f.Origin + scenario.Request.Path, Headers: scenario.Request.Headers, Token: token}
	var flow *personFlow
	if executionError == nil {
		flow, job, executionError = startPersonFlow(f, job, f.Now+scenario.Token.EXPOffset)
	}
	c.SigningInput = &job
	if startError != nil {
		executionError = startError
	}
	if executionError == nil {
		encoded, _ := json.Marshal(job)
		request, _ := http.NewRequest("POST", control, bytes.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		// What reached the harness is graded; a launcher whose Agent stops
		// short reports that in its control response, which stays evidence.
		response, err := Exchange(ctx, request, control, options.Timeout)
		if err != nil {
			executionError = err
		} else {
			c.ControlResponse = &response
		}
	}
	if flow != nil {
		flow.close()
		c.Exchanges = flow.exchanges()
	}
	if executionError != nil {
		c.Error = executionError.Error()
	}
	for _, assertion := range scenario.Assertions {
		result := Result{Assertion: assertion.ID, Clause: assertion.Clause, Expected: assertion.Equals}
		switch {
		case !slices.Contains(target.Claims, assertion.Clause):
			result.State = "not_claimed"
		case executionError != nil:
			result.State = "error"
			result.Detail = c.Error
		default:
			result = flow.check(assertion)
		}
		c.Results = append(c.Results, result)
	}
	return c
}
