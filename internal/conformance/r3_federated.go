package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/dunglas/httpsfv"
)

// R3FederatedIssuerRole puts a native four-party PS and AS under test: the AS
// issues the R3 Auth token and the PS consents and delivers it. The harness
// is Agent and Resource and serves the R3 document.
const R3FederatedIssuerRole = "r3.federated-issuer"

// R3FederatedInput selects the served document. altered-as and altered-ps
// serve bytes that do not hash to r3_s256 to that signer only, so one
// party's hash verification is isolated from the other's.
type R3FederatedInput struct {
	Document   string   `json:"document"`
	Operations []string `json:"operations"`
}

func init() {
	RegisterRole(R3FederatedIssuerRole, ExtensionRole{
		Kinds:       []string{"r3-fetched", "r3-fetch-proof", "r3-auth-token", "r3-no-auth-token"},
		Validate:    validateR3FederatedScenario,
		Run:         runR3FederatedIssuers,
		Unavailable: true,
	})
}

func validateR3FederatedScenario(f Fixture, s Scenario) error {
	if _, err := r3Fixture(f); err != nil {
		return err
	}
	var in R3FederatedInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains([]string{"exact", "altered-as", "altered-ps"}, in.Document) || len(in.Operations) == 0 {
		return fmt.Errorf("%s: document exact, altered-as or altered-ps, and operations are required", s.ID)
	}
	for _, a := range s.Assertions {
		if !slices.Contains([]string{"person", "fetch-access", "fetch-person", "token"}, a.Stage) {
			return fmt.Errorf("%s/%s: four-party issuer stages are person, fetch-access, fetch-person and token", s.ID, a.ID)
		}
		fetchStage := strings.HasPrefix(a.Stage, "fetch-")
		fetchKind := a.Kind == "r3-fetched" || a.Kind == "r3-fetch-proof"
		tokenKind := a.Kind == "r3-auth-token" || a.Kind == "r3-no-auth-token"
		if fetchStage != fetchKind || tokenKind && a.Stage != "token" {
			return fmt.Errorf("%s/%s: %s is not graded on %s", s.ID, a.ID, a.Kind, a.Stage)
		}
		if strings.HasPrefix(a.Kind, "r3-") {
			if err := requireBoolean(a); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
			}
		}
	}
	return nil
}

// r3SignerDocuments serves the document at its path, choosing the bytes by
// the jwks_uri id the request names. It never verifies; the proof is graded
// separately from the retained request.
type r3SignerDocuments struct {
	mu         sync.Mutex
	path       string
	exact      []byte
	altered    []byte
	alteredFor string
	captured   []Captured
}

func r3RequestSigner(header http.Header) string {
	keys, err := httpsfv.UnmarshalDictionary(header.Values("Signature-Key"))
	if err != nil {
		return ""
	}
	for _, label := range keys.Names() {
		member, _ := keys.Get(label)
		item, ok := member.(httpsfv.Item)
		if !ok || item.Value != httpsfv.Token("jwks_uri") || item.Params == nil {
			continue
		}
		if id, ok := item.Params.Get("id"); ok {
			text, _ := id.(string)
			return text
		}
	}
	return ""
}

func (d *r3SignerDocuments) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	d.mu.Lock()
	d.captured = append(d.captured, Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body})
	served := d.exact
	if d.alteredFor != "" && r3RequestSigner(r.Header) == d.alteredFor {
		served = d.altered
	}
	path := d.path
	d.mu.Unlock()
	if r.URL.Path != path {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(served)
}

// r3ServerProof independently verifies one GET signed as a server in its own
// right: a jwks_uri member naming issuer, document and one of keys' kids,
// created at the fixture clock (within the skew for a deployed server),
// covering the base components, under that key.
func r3ServerProof(f Fixture, captured Captured, uri, issuer, document string, keys keySet) bool {
	target, err := url.Parse(captured.URL)
	if err != nil || captured.Method != "GET" || captured.URL != uri {
		return false
	}
	members, e1 := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature-Key"))
	inputs, e2 := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature-Input"))
	signatures, e3 := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature"))
	if e1 != nil || e2 != nil || e3 != nil {
		return false
	}
	for _, label := range members.Names() {
		member, _ := members.Get(label)
		key, ok := member.(httpsfv.Item)
		if !ok || key.Value != httpsfv.Token("jwks_uri") || key.Params == nil {
			continue
		}
		id, _ := key.Params.Get("id")
		dwk, _ := key.Params.Get("dwk")
		named, _ := key.Params.Get("kid")
		kid, _ := named.(string)
		if _, known := keys[kid]; id != issuer || dwk != document || !known {
			continue
		}
		member, _ = inputs.Get(label)
		input, ok := member.(httpsfv.InnerList)
		if !ok || input.Params == nil {
			continue
		}
		created, _ := input.Params.Get("created")
		if stamp, isInteger := created.(int64); !isInteger || !f.issuedNow(float64(stamp)) {
			continue
		}
		lines, seen, valid := []string{}, map[string]bool{}, true
		for _, entry := range input.Items {
			component, ok := entry.Value.(string)
			if !ok || seen[component] || entry.Params != nil && len(entry.Params.Names()) != 0 {
				valid = false
				break
			}
			seen[component] = true
			var value string
			switch component {
			case "@method":
				value = captured.Method
			case "@authority":
				value = strings.ToLower(target.Host)
			case "@path":
				value = target.EscapedPath()
			case "signature-key":
				value = canonicalField(captured.Headers, component)
			default:
				valid = false
			}
			lines = append(lines, fmt.Sprintf("%q: %s", component, value))
		}
		for _, required := range []string{"@method", "@authority", "@path", "signature-key"} {
			valid = valid && seen[required]
		}
		params, err := httpsfv.Marshal(input)
		member, _ = signatures.Get(label)
		signature, isItem := member.(httpsfv.Item)
		raw, isBytes := signature.Value.([]byte)
		if err != nil || !valid || !isItem || !isBytes {
			continue
		}
		base := strings.Join(append(lines, `"@signature-params": `+params), "\n")
		if keys.verifyKid(kid, []byte(base), raw) {
			return true
		}
	}
	return false
}

// observeR3IssuedToken verifies an R3 Auth token from the named issuer:
// under one of its keys, typ aa-auth+jwt, its iss and discovery document,
// the PS in ps, the Resource in aud, the Resource token's r3_uri/r3_s256,
// and r3_granted in the vocabulary with operations from the document.
func observeR3IssuedToken(f Fixture, response Response, issuer, document string, keys keySet, uri, digest string, operations []any, vocabulary string) R3TokenObservation {
	compact, err := responseToken(response, "auth_token")
	if err != nil {
		return R3TokenObservation{Error: err.Error()}
	}
	_, claims, err := verifyJWTWith(compact, keys, "aa-auth+jwt")
	if err != nil {
		return R3TokenObservation{Claims: claims, Error: err.Error()}
	}
	o := R3TokenObservation{Claims: claims}
	granted, _ := claims["r3_granted"].(map[string]any)
	listed, ok := granted["operations"].([]any)
	inside := ok
	for _, operation := range listed {
		found := false
		for _, have := range operations {
			found = found || jsonEqual(have, operation)
		}
		inside = inside && found
	}
	switch {
	case claims["iss"] != issuer || claims["dwk"] != document || claims["ps"] != f.Person.Issuer || claims["aud"] != f.Origin:
		o.Error = "Auth token iss, dwk, ps or aud does not name the issuer, the PS and the Resource"
	case claims["r3_uri"] != uri || claims["r3_s256"] != digest:
		o.Error = "Auth token r3_uri/r3_s256 differ from the Resource token"
	case granted == nil || granted["vocabulary"] != vocabulary || !inside:
		o.Error = "Auth token r3_granted is absent, names another vocabulary or an operation outside the document"
	default:
		o.Valid = true
	}
	return o
}

type r3FederatedEvidence struct {
	Resource  string             `json:"harness_resource_token,omitempty"`
	Fetches   []Captured         `json:"native_fetches,omitempty"`
	AuthToken R3TokenObservation `json:"auth_token"`
}

func runR3FederatedIssuers(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	f := s.Fixture
	r, _ := r3Fixture(f)
	return r3Run(ctx, s, targets, o, report, func(target Target, scenario Scenario) Case {
		var in R3FederatedInput
		DecodeInput(scenario, &in)
		documents := &r3SignerDocuments{}
		listener := httptest.NewServer(documents)
		defer listener.Close()
		config := r3Bootstrap(f, r, R3FederatedIssuerRole, ap, r3Extension{PersonSeed: f.Person.Seed, AccessSeed: f.Access.Seed, R3Transport: listener.URL})
		ready, stop, err := startAdapter(ctx, target, config, o)
		c := runR3FederatedCase(ctx, f, r, scenario, in, target, ready.URL, o, documents, err)
		if stop != nil {
			stop()
		}
		return c
	})
}

func runR3FederatedCase(ctx context.Context, f Fixture, r R3Fixture, s Scenario, in R3FederatedInput, target Target, physical string, o Options, documents *r3SignerDocuments, startError error) Case {
	c := Case{ID: s.ID}
	x := &r3Exchanger{ctx: ctx, physical: physical, timeout: o.Timeout, c: &c, responses: map[string]Response{}}
	p, a := *f.Person, *f.Access
	evidence := r3FederatedEvidence{}
	operations := r3Operations(r.Vocabulary, in.Operations)
	exact, _ := json.Marshal(map[string]any{
		"vocabulary": r.Vocabulary, "operations": operations,
		"display": map[string]any{"summary": "Read and export fixture records"},
	})
	digest := r3Digest(exact)
	path := "/r3/c." + digest
	uri := f.Origin + path
	documents.mu.Lock()
	documents.path, documents.exact = path, exact
	documents.altered = bytes.Replace(exact, []byte("fixture records"), []byte("fixture Records"), 1)
	switch in.Document {
	case "altered-as":
		documents.alteredFor = a.Issuer
	case "altered-ps":
		documents.alteredFor = p.Issuer
	}
	documents.mu.Unlock()
	execute := func() error {
		if startError != nil {
			return startError
		}
		agent, err := agentJWT(f, s.ID+"-agent", f.Now-10, f.Now+600, p.Issuer)
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
		resource, err := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", map[string]any{
			"iss": f.Origin, "dwk": "aauth-resource.json", "aud": a.Issuer, "ps": p.Issuer,
			"sub": personClaims["sub"], "presented_jti": personClaims["jti"], "agent_jkt": thumbprint(f.AgentSeed),
			"jti": s.ID + "-resource", "iat": f.Now - 1, "exp": f.Now + 120, "r3_uri": uri, "r3_s256": digest,
		})
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
		evidence.AuthToken = observeR3IssuedToken(f, tokenResponse, a.Issuer, "aauth-access.json", a.keys(), uri, digest, operations, r.Vocabulary)
		return nil
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	documents.mu.Lock()
	evidence.Fetches = append([]Captured(nil), documents.captured...)
	documents.mu.Unlock()
	c.Evidence = evidence
	// Requests are attributed by the server id they name; one that names
	// neither the AS nor the PS fails both proofs.
	type signer struct {
		issuer, document string
		keys             keySet
	}
	signers := map[string]signer{
		"fetch-access": {a.Issuer, "aauth-access.json", a.keys()},
		"fetch-person": {p.Issuer, "aauth-person.json", p.keys()},
	}
	unattributed := false
	for _, fetch := range evidence.Fetches {
		id := r3RequestSigner(fetch.Headers)
		unattributed = unattributed || id != a.Issuer && id != p.Issuer
	}
	for _, assertion := range s.Assertions {
		response, observed := x.responses[assertion.Stage]
		var pointer *Response
		if observed {
			pointer = &response
		}
		executionError := c.Error
		if executionError == "" && !observed && !strings.HasPrefix(assertion.Stage, "fetch-") {
			executionError = "stage " + assertion.Stage + " was not reached"
		}
		c.Results = append(c.Results, Grade(assertion, target.Claims, executionError, pointer, func(a Assertion) Result {
			who := signers[a.Stage]
			mine := []Captured{}
			for _, fetch := range evidence.Fetches {
				if r3RequestSigner(fetch.Headers) == who.issuer {
					mine = append(mine, fetch)
				}
			}
			switch a.Kind {
			case "r3-fetched":
				fetched := len(mine) > 0
				for _, fetch := range mine {
					fetched = fetched && fetch.Method == "GET" && fetch.URL == uri
				}
				return CompareResult(a, fetched, fmt.Sprintf("%d of %d requests named %s", len(mine), len(evidence.Fetches), who.issuer))
			case "r3-fetch-proof":
				// Only a party that fetches must sign; no fetch is not exercised.
				if len(mine) == 0 && !unattributed {
					return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: who.issuer + " made no R3 fetch"}
				}
				proved := !unattributed
				for _, fetch := range mine {
					proved = proved && r3ServerProof(f, fetch, uri, who.issuer, who.document, who.keys)
				}
				return CompareResult(a, proved, "")
			case "r3-auth-token":
				return CompareResult(a, evidence.AuthToken.Valid, evidence.AuthToken.Error)
			case "r3-no-auth-token":
				return CompareResult(a, noR3Token(response, "auth_token"), "")
			}
			return CompareResult(a, nil, "unknown R3 assertion kind")
		}))
	}
	return c
}
