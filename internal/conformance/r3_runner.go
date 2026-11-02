package conformance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
)

// r3Extension is the launcher configuration of both R3 roles. Seeds are the
// public fixture test vectors of the role the launcher hosts; trust is given
// as public JWKs.
type r3Extension struct {
	Topology        string         `json:"topology,omitempty"`
	ResourceSeed    string         `json:"resource_seed_hex,omitempty"`
	ResourceKid     string         `json:"resource_kid"`
	ResourceJWK     map[string]any `json:"resource_jwk"`
	PersonServer    string         `json:"person_server"`
	PersonSeed      string         `json:"person_seed_hex,omitempty"`
	PersonKid       string         `json:"person_kid"`
	PersonJWK       map[string]any `json:"person_jwk"`
	PersonSubject   string         `json:"person_subject"`
	PersonLifetime  int64          `json:"person_lifetime"`
	AuthLifetime    int64          `json:"auth_lifetime"`
	PermittedScopes []string       `json:"permitted_scopes"`
	AccessServer    string         `json:"access_server"`
	AccessSeed      string         `json:"access_seed_hex,omitempty"`
	AccessKid       string         `json:"access_kid"`
	AccessJWK       map[string]any `json:"access_jwk"`
	OtherServer     string         `json:"other_server"`
	OtherKid        string         `json:"other_kid"`
	OtherJWK        map[string]any `json:"other_jwk"`
	Vocabulary      string         `json:"vocabulary"`
	Tools           []string       `json:"tools"`
	Grantable       []string       `json:"grantable"`
	R3Transport     string         `json:"r3_transport,omitempty"`
}

func r3Bootstrap(f Fixture, r R3Fixture, role string, ap string, extension r3Extension) Bootstrap {
	p, a := *f.Person, *f.Access
	extension.ResourceKid, extension.ResourceJWK = p.ResourceKid, publicJWK(p.ResourceSeed)
	extension.PersonServer, extension.PersonKid, extension.PersonJWK = p.Issuer, p.Kid, publicJWK(p.Seed)
	extension.PersonSubject, extension.PersonLifetime, extension.AuthLifetime, extension.PermittedScopes = p.Subject, p.Lifetime, p.AuthLifetime, p.PermittedScopes
	extension.AccessServer, extension.AccessKid, extension.AccessJWK = a.Issuer, a.Kid, publicJWK(a.Seed)
	extension.OtherServer, extension.OtherKid, extension.OtherJWK = r.Other.Issuer, r.Other.Kid, publicJWK(r.Other.Seed)
	extension.Vocabulary, extension.Tools, extension.Grantable = r.Vocabulary, r.Tools, r.Grantable
	raw, _ := json.Marshal(extension)
	return Bootstrap{Version: 1, Role: role, Now: f.Now, Issuer: f.Issuer, Resource: f.Origin + f.Path, APTransport: ap, Extension: raw}
}

// r3Run starts one fresh launcher per scenario, so a document store, issuance
// log or consumed grant cannot change another scenario's result.
func r3Run(ctx context.Context, s Suite, targets Targets, o Options, report Report, runCase func(Target, Scenario) Case) Report {
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			if target.Unavailable != "" {
				c := Case{ID: scenario.ID}
				for _, a := range scenario.Assertions {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: target.Unavailable})
				}
				run.Cases = append(run.Cases, c)
				continue
			}
			run.Cases = append(run.Cases, runCase(target, scenario))
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

type r3Exchanger struct {
	ctx       context.Context
	physical  string
	timeout   time.Duration
	c         *Case
	responses map[string]Response
}

func (x *r3Exchanger) send(stage string, request *http.Request, base string) (Response, error) {
	var body []byte
	if request.Body != nil {
		var err error
		if body, err = io.ReadAll(request.Body); err != nil {
			return Response{}, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	entry := PersonExchange{Stage: stage, Method: request.Method, URL: request.URL.String(), Headers: request.Header.Clone(), Body: body, SignatureBase: base}
	response, err := r3Exchange(x.ctx, request, x.physical, x.timeout)
	if err != nil {
		entry.Error = err.Error()
	} else {
		entry.Response = &response
		x.responses[stage] = response
	}
	x.c.Exchanges = append(x.c.Exchanges, entry)
	return response, err
}

// r3Exchange sends one logical request to the physical launcher as Exchange
// does, but as an ordinary persistent HTTP/1.1 request: it sends no
// Connection: close, and closes the idle connection afterwards.
func r3Exchange(ctx context.Context, logical *http.Request, transport string, timeout time.Duration) (Response, error) {
	if transport == "" {
		// Remote mode: the logical HTTPS URL itself, over the context's Network.
		return Exchange(ctx, logical, "", timeout)
	}
	request := logical.Clone(ctx)
	physical, err := url.Parse(transport)
	if err != nil {
		return Response{}, err
	}
	request.Host = logical.URL.Host
	physical.Path, physical.RawPath = logical.URL.Path, logical.URL.RawPath
	physical.RawQuery, physical.ForceQuery = logical.URL.RawQuery, logical.URL.ForceQuery
	request.URL = physical
	connections := &http.Transport{Proxy: nil}
	defer connections.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: connections, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirects are not conformance responses")
	}}
	response, err := client.Do(request)
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

// r3ResourceEvidence is retained in the report next to the exchanges.
type r3ResourceEvidence struct {
	ResourceToken R3TokenObservation               `json:"resource_token"`
	AuthToken     string                           `json:"harness_auth_token,omitempty"`
	Documents     map[string]R3DocumentObservation `json:"documents,omitempty"`
	PerCall       *R3TokenObservation              `json:"per_call_challenge,omitempty"`
	PerCallToken  string                           `json:"harness_per_call_auth_token,omitempty"`
	Proposal      bool                             `json:"proposal_shape"`
	Executions    *float64                         `json:"executions,omitempty"`
}

func runR3Resources(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	f := s.Fixture
	r, _ := r3Fixture(f)
	return r3Run(ctx, s, targets, o, report, func(target Target, scenario Scenario) Case {
		var in R3ResourceInput
		DecodeInput(scenario, &in)
		config := r3Bootstrap(f, r, R3ResourceRole, ap, r3Extension{Topology: in.Topology, ResourceSeed: f.Person.ResourceSeed})
		ready, stop, err := startAdapter(ctx, target, config, o)
		c := runR3ResourceCase(ctx, f, r, scenario, in, target, ready.URL, o, err)
		if stop != nil {
			stop()
		}
		return c
	})
}

func runR3ResourceCase(ctx context.Context, f Fixture, r R3Fixture, s Scenario, in R3ResourceInput, target Target, physical string, o Options, startError error) Case {
	c := Case{ID: s.ID}
	x := &r3Exchanger{ctx: ctx, physical: physical, timeout: o.Timeout, c: &c, responses: map[string]Response{}}
	p, a := *f.Person, *f.Access
	evidence := r3ResourceEvidence{Documents: map[string]R3DocumentObservation{}}
	vocabulary := r.Vocabulary
	if in.Vocabulary != "" {
		vocabulary = in.Vocabulary
	}
	requested := r3Operations(vocabulary, in.Operations)
	issuer, issuerDocument, issuerSeed, issuerKid := a.Issuer, "aauth-access.json", a.Seed, a.Kid
	if in.Topology == "three-party" {
		issuer, issuerDocument, issuerSeed, issuerKid = p.Issuer, "aauth-person.json", p.Seed, p.Kid
	}
	var advertised map[string]any
	vocabulariesValid := false
	remote := remoteFrom(ctx)
	execute := func() error {
		if startError != nil {
			return startError
		}
		metadataRequest, _ := http.NewRequest("GET", f.Origin+"/.well-known/aauth-resource.json", nil)
		metadata, err := x.send("metadata", metadataRequest, "")
		if err != nil {
			return err
		}
		advertised, vocabulariesValid = r3Vocabularies(metadata, r.Vocabulary)
		authorize := f.Origin + "/authorize"
		if remote != nil {
			// A deployed Resource names its authorization endpoint.
			if endpoint := r3AuthorizationEndpoint(metadata, f.Origin); endpoint != "" {
				authorize = endpoint
			}
		}
		person, err := mintJWT(p.Seed, p.Kid, "aa-person+jwt", map[string]any{
			"iss": p.Issuer, "dwk": "aauth-person.json", "aud": f.Origin,
			"sub": p.Subject, "jti": "r3-person-" + s.ID,
			"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
			"iat": f.Now, "exp": f.Now + p.Lifetime,
		})
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"r3_operations": map[string]any{"vocabulary": vocabulary, "operations": requested}})
		request, base, err := signedFixtureRequest(f, f.AgentSeed, "POST", authorize, `sig=jwt;jwt="`+person+`"`, body)
		if err != nil {
			return err
		}
		authorized, err := x.send("authorize", request, base)
		if err != nil {
			return err
		}
		evidence.ResourceToken = observeR3ResourceToken(f, authorized, issuer)
		if len(in.Fetches) == 0 && len(in.Calls) == 0 {
			return nil
		}
		if !evidence.ResourceToken.Valid {
			return fmt.Errorf("cannot advance without a valid R3 Resource token: %s", evidence.ResourceToken.Error)
		}
		claims := evidence.ResourceToken.Claims
		uri, digest := claims["r3_uri"].(string), claims["r3_s256"].(string)
		seen := map[string]int{}
		for _, mode := range in.Fetches {
			seen[mode]++
			stage := "fetch-" + mode
			if seen[mode] > 1 {
				stage = fmt.Sprintf("%s-%d", stage, seen[mode])
			}
			request, base, err := r3FetchRequest(f, r, mode, uri, person)
			if err != nil {
				return err
			}
			response, err := x.send(stage, request, base)
			if err != nil {
				return err
			}
			evidence.Documents[stage] = observeR3Document(response, digest, advertised, vocabulary, requested)
		}
		if len(in.Calls) == 0 {
			return nil
		}
		authClaims := map[string]any{
			"iss": issuer, "dwk": issuerDocument, "aud": f.Origin, "jti": "r3-auth-" + s.ID,
			"ps": p.Issuer, "sub": claims["sub"], "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
			"iat": f.Now, "exp": f.Now + p.AuthLifetime, "r3_uri": uri, "r3_s256": digest,
			"r3_granted": map[string]any{"vocabulary": vocabulary, "operations": r3Operations(vocabulary, in.Grant)},
		}
		if len(in.PerCall) > 0 {
			authClaims["r3_per_call"] = map[string]any{"vocabulary": vocabulary, "operations": r3Operations(vocabulary, in.PerCall)}
		}
		auth, err := mintJWT(issuerSeed, issuerKid, "aa-auth+jwt", authClaims)
		if err != nil {
			return err
		}
		evidence.AuthToken = auth
		// A deployed Resource counts executions over its whole life, so a
		// remote case grades the count its own calls added.
		var before map[string]float64
		if remote != nil && in.PerCallFlow != "" && remote.ControlURL("") != "" {
			if before, err = r3ReadExecutions(x, "executions-before", remote.ControlURL("/__fixture/r3/executions")); err != nil {
				return err
			}
		}
		for _, tool := range in.Calls {
			callBody := []byte(`{"record":"r-1"}`)
			request, base, err := signedFixtureRequest(f, f.AgentSeed, "POST", f.Origin+"/op/"+tool, `sig=jwt;jwt="`+auth+`"`, callBody)
			if err != nil {
				return err
			}
			if _, err := x.send("call-"+tool, request, base); err != nil {
				return err
			}
		}
		if in.PerCallFlow == "" {
			return nil
		}
		// The harness AS approves the proposal the native Resource published
		// and issues the one-operation per-call token (Flow, steps 2-4).
		tool := in.Calls[0]
		challenge := observeR3PerCallChallenge(f, x.responses["call-"+tool], uri, "r3-auth-"+s.ID)
		evidence.PerCall = &challenge
		if !challenge.Valid {
			return fmt.Errorf("cannot complete without a per-call challenge: %s", challenge.Error)
		}
		proposalURI, proposalDigest := challenge.Claims["r3_uri"].(string), challenge.Claims["r3_s256"].(string)
		request, base, err = r3FetchRequest(f, r, "access", proposalURI, person)
		if err != nil {
			return err
		}
		proposal, err := x.send("fetch-proposal", request, base)
		if err != nil {
			return err
		}
		evidence.Documents["fetch-proposal"] = observeR3Document(proposal, proposalDigest, advertised, vocabulary, r3Operations(vocabulary, []string{tool}))
		evidence.Proposal = r3ProposalShape(proposal, vocabulary, tool, "r-1")
		perCall, err := mintJWT(a.Seed, a.Kid, "aa-auth+jwt", map[string]any{
			"iss": a.Issuer, "dwk": "aauth-access.json", "aud": f.Origin, "jti": "r3-per-call-" + s.ID,
			"ps": p.Issuer, "sub": claims["sub"], "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
			"iat": f.Now, "exp": f.Now + p.AuthLifetime, "r3_uri": proposalURI, "r3_s256": proposalDigest,
			"r3_granted": map[string]any{"vocabulary": vocabulary, "operations": r3Operations(vocabulary, []string{tool})},
		})
		if err != nil {
			return err
		}
		evidence.PerCallToken = perCall
		retryBody := []byte(`{"record":"r-1"}`)
		if in.PerCallFlow == "mismatch" {
			retryBody = []byte(`{"record":"r-2"}`)
		}
		stages := []string{"retry-" + tool}
		if in.PerCallFlow == "complete" {
			stages = append(stages, "repeat-"+tool)
		}
		for _, stage := range stages {
			request, base, err := signedFixtureRequest(f, f.AgentSeed, "POST", f.Origin+"/op/"+tool, `sig=jwt;jwt="`+perCall+`"`, retryBody)
			if err != nil {
				return err
			}
			if _, err := x.send(stage, request, base); err != nil {
				return err
			}
		}
		// The launcher's own count of application executions, read after the
		// calls; it is host evidence, not a protocol response. A deployment
		// serves it under its control, if it names one.
		executions := f.Origin + "/__fixture/r3/executions"
		if remote != nil {
			if executions = remote.ControlURL("/__fixture/r3/executions"); executions == "" {
				return nil
			}
		}
		counts, err := r3ReadExecutions(x, "executions", executions)
		if err != nil {
			return err
		}
		count := counts[tool] - before[tool]
		evidence.Executions = &count
		return nil
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	c.Evidence = evidence
	for _, assertion := range s.Assertions {
		response, observed := x.responses[assertion.Stage]
		var pointer *Response
		if observed {
			pointer = &response
		}
		executionError := c.Error
		if executionError == "" && !observed {
			executionError = "stage " + assertion.Stage + " was not reached"
		}
		c.Results = append(c.Results, Grade(assertion, target.Claims, executionError, pointer, func(a Assertion) Result {
			document := evidence.Documents[a.Stage]
			switch a.Kind {
			case "r3-resource-token":
				return CompareResult(a, evidence.ResourceToken.Valid, evidence.ResourceToken.Error)
			case "r3-no-resource-token":
				return CompareResult(a, noR3Token(response, "resource_token"), "")
			case "r3-document-digest":
				return CompareResult(a, document.Matches, document.Error)
			case "r3-no-document":
				return CompareResult(a, !document.Matches, "")
			case "r3-document-fields":
				return CompareResult(a, document.Fields, document.Error)
			case "r3-document-covers":
				return CompareResult(a, document.Covers, document.Error)
			case "r3-vocabularies":
				return CompareResult(a, vocabulariesValid, "")
			case "r3-per-call-challenge":
				if evidence.PerCall == nil {
					return CompareResult(a, false, "no per-call challenge was observed")
				}
				return CompareResult(a, evidence.PerCall.Valid, evidence.PerCall.Error)
			case "r3-proposal":
				return CompareResult(a, evidence.Proposal, "")
			case "r3-executions":
				if evidence.Executions == nil {
					return CompareResult(a, nil, "no execution count")
				}
				return CompareResult(a, *evidence.Executions, "")
			case "r3-single-use":
				// Single use is exercised only once the approved call has run.
				if evidence.Executions == nil || *evidence.Executions == 0 {
					return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: "the approved call never ran, so a second execution was not possible"}
				}
				return CompareResult(a, *evidence.Executions == 1, fmt.Sprintf("%v executions", *evidence.Executions))
			}
			return CompareResult(a, nil, "unknown R3 assertion kind")
		}))
	}
	return c
}

// r3ReadExecutions reads the host's count of application executions per
// operation through its host control.
func r3ReadExecutions(x *r3Exchanger, stage, target string) (map[string]float64, error) {
	request, _ := http.NewRequest("GET", target, nil)
	counted, err := x.send(stage, request, "")
	if err != nil {
		return nil, err
	}
	var counts map[string]float64
	if counted.Status != 200 || json.Unmarshal(counted.Body, &counts) != nil {
		return nil, fmt.Errorf("launcher did not report its execution counts")
	}
	return counts, nil
}

// r3FetchRequest signs GET r3_uri as each kind of caller. Server callers sign
// under jwks_uri with id set to their issuer (R3 Document Access Restriction).
func r3FetchRequest(f Fixture, r R3Fixture, mode, uri, person string) (*http.Request, string, error) {
	server := func(issuer, document, kid string) string {
		return fmt.Sprintf("sig=jwks_uri;id=%q;dwk=%q;kid=%q", issuer, document, kid)
	}
	p, a := *f.Person, *f.Access
	switch mode {
	case "unsigned":
		request, err := http.NewRequest("GET", uri, nil)
		return request, "", err
	case "agent":
		return signedFixtureRequest(f, f.AgentSeed, "GET", uri, `sig=jwt;jwt="`+person+`"`, nil)
	case "person":
		return signedFixtureRequest(f, p.Seed, "GET", uri, server(p.Issuer, "aauth-person.json", p.Kid), nil)
	case "other":
		return signedFixtureRequest(f, r.Other.Seed, "GET", uri, server(r.Other.Issuer, "aauth-access.json", r.Other.Kid), nil)
	}
	request, base, err := signedFixtureRequest(f, a.Seed, "GET", uri, server(a.Issuer, "aauth-access.json", a.Kid), nil)
	if err == nil && mode == "tampered" {
		err = tamperSignature(request)
	}
	return request, base, err
}

// tamperSignature flips one bit of the encoded signature after signing.
func tamperSignature(request *http.Request) error {
	signatures, err := httpsfv.UnmarshalDictionary(request.Header.Values("Signature"))
	if err != nil {
		return err
	}
	member, _ := signatures.Get("sig")
	item, ok := member.(httpsfv.Item)
	raw, isBytes := item.Value.([]byte)
	if !ok || !isBytes || len(raw) == 0 {
		return fmt.Errorf("no signature to tamper")
	}
	changed := append([]byte(nil), raw...)
	changed[0] ^= 1
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(changed)+":")
	return nil
}

// r3DocumentServer is the harness Resource's R3 endpoint. It retains every
// request so the PS's own fetch proof can be graded, and serves the bytes the
// scenario selects.
type r3DocumentServer struct {
	mu       sync.Mutex
	path     string
	body     []byte
	status   int
	captured []Captured
}

func (d *r3DocumentServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	d.mu.Lock()
	d.captured = append(d.captured, Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body})
	status, served, path := d.status, d.body, d.path
	d.mu.Unlock()
	if r.URL.Path != path || status != 200 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(served)
}

type r3IssuerEvidence struct {
	Document  string             `json:"served_document,omitempty"`
	Resource  string             `json:"harness_resource_token,omitempty"`
	Fetches   []Captured         `json:"native_ps_fetches,omitempty"`
	Proof     Observation        `json:"native_ps_fetch_proof"`
	AuthToken R3TokenObservation `json:"auth_token"`
}

func runR3Issuers(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	f := s.Fixture
	r, _ := r3Fixture(f)
	return r3Run(ctx, s, targets, o, report, func(target Target, scenario Scenario) Case {
		var in R3IssuerInput
		DecodeInput(scenario, &in)
		documents := &r3DocumentServer{}
		listener := httptest.NewServer(documents)
		defer listener.Close()
		config := r3Bootstrap(f, r, R3IssuerRole, ap, r3Extension{PersonSeed: f.Person.Seed, R3Transport: listener.URL})
		ready, stop, err := startAdapter(ctx, target, config, o)
		c := runR3IssuerCase(ctx, f, r, scenario, in, target, ready.URL, o, documents, err)
		if stop != nil {
			stop()
		}
		return c
	})
}

func runR3IssuerCase(ctx context.Context, f Fixture, r R3Fixture, s Scenario, in R3IssuerInput, target Target, physical string, o Options, documents *r3DocumentServer, startError error) Case {
	c := Case{ID: s.ID}
	x := &r3Exchanger{ctx: ctx, physical: physical, timeout: o.Timeout, c: &c, responses: map[string]Response{}}
	p := *f.Person
	evidence := r3IssuerEvidence{}
	operations := r3Operations(r.Vocabulary, in.Operations)
	exact, _ := json.Marshal(map[string]any{
		"vocabulary": r.Vocabulary, "operations": operations,
		"display": map[string]any{"summary": "Read and export fixture records"},
	})
	digest := r3Digest(exact)
	path := "/r3/c." + digest
	uri := f.Origin + path
	served := exact
	if in.Document == "altered" {
		// Equal-length, valid JSON with different bytes: only the hash differs.
		served = bytes.Replace(exact, []byte("fixture records"), []byte("fixture Records"), 1)
	}
	status := 200
	if in.Document == "missing" {
		status = 404
	}
	documents.mu.Lock()
	documents.path, documents.body, documents.status = path, served, status
	documents.mu.Unlock()
	evidence.Document = string(served)
	execute := func() error {
		if startError != nil {
			return startError
		}
		agent, err := mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", map[string]any{
			"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": s.ID + "-agent",
			"iat": f.Now - 10, "exp": f.Now + 600, "ps": p.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
		})
		if err != nil {
			return err
		}
		credential := `sig=jwt;jwt="` + agent + `"`
		personBody, _ := json.Marshal(map[string]string{"resource": f.Origin})
		request, base, err := signedFixtureRequest(f, f.AgentSeed, "POST", p.personURL(), credential, personBody)
		if err != nil {
			return err
		}
		personResponse, err := x.send("person", request, base)
		if err != nil {
			return err
		}
		person, err := responseToken(personResponse, "person_token")
		if err != nil {
			return err
		}
		_, personClaims, err := verifyJWTWith(person, p.keys(), "aa-person+jwt")
		if err != nil {
			return fmt.Errorf("cannot advance from an unverifiable Person token: %w", err)
		}
		resourceClaims := map[string]any{
			"iss": f.Origin, "dwk": "aauth-resource.json", "aud": p.Issuer, "ps": p.Issuer,
			"sub": personClaims["sub"], "presented_jti": personClaims["jti"], "agent_jkt": thumbprint(f.AgentSeed),
			"jti": s.ID + "-resource", "iat": f.Now - 1, "exp": f.Now + 120, "r3_uri": uri, "r3_s256": digest,
		}
		if in.Scope != "" {
			resourceClaims["scope"] = in.Scope
		}
		resource, err := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", resourceClaims)
		if err != nil {
			return err
		}
		evidence.Resource = resource
		tokenBody, _ := json.Marshal(map[string]string{"resource_token": resource, "presented_token": person})
		request, base, err = signedFixtureRequest(f, f.AgentSeed, "POST", p.tokenURL(), credential, tokenBody)
		if err != nil {
			return err
		}
		tokenResponse, err := x.send("token", request, base)
		if err != nil {
			return err
		}
		evidence.AuthToken = observeR3AuthToken(f, tokenResponse, uri, digest, operations, r.Vocabulary)
		return nil
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	documents.mu.Lock()
	evidence.Fetches = append([]Captured(nil), documents.captured...)
	documents.mu.Unlock()
	// Every request that reached the R3 endpoint must be a GET of r3_uri, and
	// every one must carry the PS's own server proof.
	fetched := len(evidence.Fetches) > 0
	evidence.Proof = Observation{Error: "the PS did not fetch r3_uri"}
	for _, fetch := range evidence.Fetches {
		fetched = fetched && fetch.Method == "GET" && fetch.URL == uri
		evidence.Proof = observePSRequestProof(f, fetch, uri, "GET")
		if !evidence.Proof.ValidProof {
			break
		}
	}
	c.Evidence = evidence
	for _, assertion := range s.Assertions {
		response, observed := x.responses[assertion.Stage]
		var pointer *Response
		if observed {
			pointer = &response
		}
		executionError := c.Error
		if executionError == "" && !observed && assertion.Stage != "fetch" {
			executionError = "stage " + assertion.Stage + " was not reached"
		}
		c.Results = append(c.Results, Grade(assertion, target.Claims, executionError, pointer, func(a Assertion) Result {
			switch a.Kind {
			case "r3-fetched":
				return CompareResult(a, fetched, fmt.Sprintf("%d requests reached the R3 endpoint", len(evidence.Fetches)))
			case "r3-fetch-proof":
				return CompareResult(a, evidence.Proof.ValidProof, evidence.Proof.Error)
			case "r3-auth-token":
				return CompareResult(a, evidence.AuthToken.Valid, evidence.AuthToken.Error)
			case "r3-no-auth-token":
				return CompareResult(a, noR3Token(response, "auth_token"), "")
			case "r3-auth-scope":
				scope, _ := evidence.AuthToken.Claims["scope"].(string)
				if !evidence.AuthToken.Valid {
					return CompareResult(a, scope, "Auth token did not verify: "+evidence.AuthToken.Error)
				}
				return CompareResult(a, scope, "")
			}
			return CompareResult(a, nil, "unknown R3 assertion kind")
		}))
	}
	return c
}
