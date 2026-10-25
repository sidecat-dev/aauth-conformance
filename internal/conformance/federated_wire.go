package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

type FederatedSpec struct {
	Mutation  string `json:"mutation"`
	HarnessPS bool   `json:"harness_ps,omitempty"`
	// Budget selects the four-party Budget fixture. Empty keeps the reactive
	// challenge and offers nothing. "grant", "omit", "consume", "header", "usage", and "cap" are the modes.
	Budget string `json:"budget,omitempty"`
}

var federationMutations = []string{
	"none", "short-agent", "as-proof", "as-body", "as-resource-aud",
	"as-resource-jti", "as-resource-ps", "as-resource-key", "as-presented-expired",
	"grant-signature", "grant-iss", "grant-aud", "grant-key", "grant-sub",
	"grant-scope", "grant-exp", "grant-ps", "as-denial",
}

func validFederatedAssertion(a Assertion) bool {
	if a.Kind == "fed-budget" {
		return slices.Contains([]string{"challenge", "access", "token", "step-up", "step-up-other", "second-token"}, a.Stage)
	}
	if a.Kind == "fed-consumed" {
		return a.Stage == "step-up" || a.Stage == "step-up-other"
	}
	if a.Kind == "sfv-integer" || a.Kind == "sfv-trailer-integer" || a.Kind == "sfv-absent" || a.Kind == "sfv-trailer-absent" {
		return slices.Contains([]string{"initial", "person", "challenge", "access", "token", "protected", "step-up", "step-up-other", "reserved", "abandoned", "following", "second-protected", "refusal"}, a.Stage)
	}
	if a.Stage == "handoff" {
		return a.Kind == "fed-ps-proof" || a.Kind == "fed-forwarded"
	}
	if strings.HasPrefix(a.Kind, "fed-") {
		return a.Stage == "challenge" && a.Kind == "fed-challenge"
	}
	if strings.HasPrefix(a.Kind, "ps-") {
		return slices.Contains([]string{"person", "access", "token"}, a.Stage)
	}
	return slices.Contains([]string{"initial", "person", "challenge", "access", "token", "protected", "step-up", "step-up-other", "reserved", "abandoned", "following", "usage", "usage-unknown", "usage-no-ps", "usage-two-keys", "usage-jkts", "second-token", "second-protected", "refusal"}, a.Stage) &&
		slices.Contains([]string{"status", "sfv-token", "sfv-strings", "sfv-string-set", "sfv-integer", "sfv-trailer-integer", "sfv-absent", "sfv-trailer-absent", "json-member", "json-path", "header-equals", "problem-if-present"}, a.Kind)
}

func validateFederatedScenario(f Fixture, s Scenario) error {
	if f.Person == nil || f.Access == nil || s.Federated == nil || s.Person != nil ||
		!reflect.DeepEqual(s.Request, RequestSpec{}) ||
		!slices.Contains(federationMutations, s.Federated.Mutation) ||
		!slices.Contains([]string{"", "grant", "omit", "consume", "header", "usage", "cap"}, s.Federated.Budget) ||
		s.Federated.HarnessPS && strings.HasPrefix(s.Federated.Mutation, "grant-") {
		return fmt.Errorf("invalid four-party fixture or scenario")
	}
	if err := validatePersonFixture(*f.Person); err != nil {
		return err
	}
	u, err := url.Parse(f.Access.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || f.Access.Kid == "" {
		return fmt.Errorf("invalid Access Server fixture")
	}
	seed, err := hex.DecodeString(f.Access.Seed)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("invalid Access Server seed")
	}
	seen := map[string]bool{}
	for _, id := range []string{f.Issuer, f.Origin, f.Person.Issuer, f.Access.Issuer} {
		if seen[id] {
			return fmt.Errorf("four-party fixture requires distinct role identities")
		}
		seen[id] = true
	}
	return nil
}

// signedFixtureRequest is independent of both implementations. All private
// seeds are public test vectors; the adapter receives no expected proof bytes.
func signedFixtureRequest(f Fixture, seed, method, target, credential string, body []byte) (*http.Request, string, error) {
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Signature-Key", credential)
	covered := []string{"@method", "@authority", "@path", "signature-key"}
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		covered = append(covered, "content-type", "content-digest")
	}
	var names, lines []string
	for _, component := range covered {
		value := canonicalField(request.Header, component)
		switch component {
		case "@method":
			value = method
		case "@authority":
			value = request.URL.Host
		case "@path":
			value = request.URL.EscapedPath()
		}
		names = append(names, fmt.Sprintf("%q", component))
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), f.Now)
	lines = append(lines, `"@signature-params": `+params)
	base := strings.Join(lines, "\n")
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(seed), []byte(base)))+":")
	return request, base, nil
}

type FederatedHandoff struct {
	Sent              Captured    `json:"native_ps_request"`
	Delivered         Captured    `json:"delivered_as_request"`
	Proof             Observation `json:"native_ps_proof"`
	Forwarded         bool        `json:"exact_required_tokens"`
	NativeResponse    *Response   `json:"native_as_response,omitempty"`
	DeliveredResponse *Response   `json:"delivered_ps_response,omitempty"`
	Error             string      `json:"error,omitempty"`
}

// The relay keeps original evidence separate from explicit adversarial inputs.
// It never corrects SUT output. Each case runs synchronously, but the mutex also
// makes lifecycle/reset operations safe under the HTTP server's goroutines.
type federationRelay struct {
	mu       sync.Mutex
	fixture  Fixture
	physical string
	mutation string
	expected map[string]string
	timeout  time.Duration
	handoff  *FederatedHandoff
}

func (relay *federationRelay) reset(physical, mutation string, expected map[string]string) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.physical, relay.mutation, relay.expected = physical, mutation, expected
	relay.handoff = nil
}

func (relay *federationRelay) snapshot() *FederatedHandoff {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.handoff
}

func (relay *federationRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	h := &FederatedHandoff{}
	if relay.handoff != nil {
		relay.handoff.Error = "unexpected repeated AS token request"
		http.Error(w, "unexpected repeated AS request", 502)
		return
	}
	relay.handoff = h
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(body) > 65536 {
		h.Error = "cannot capture bounded AS request body"
		http.Error(w, h.Error, 502)
		return
	}
	f := relay.fixture
	h.Sent = Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}
	h.Proof = observePSProof(f, h.Sent)
	var input map[string]string
	if json.Unmarshal(body, &input) == nil {
		h.Forwarded = true
		for _, name := range []string{"resource_token", "agent_token", "presented_token"} {
			h.Forwarded = h.Forwarded && input[name] != "" && input[name] == relay.expected[name]
		}
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, h.Sent.URL, bytes.NewReader(body))
	if err == nil {
		request.Header = r.Header.Clone()
		err = mutateASRequest(f, relay.mutation, request)
	}
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	delivered, err := io.ReadAll(request.Body)
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(delivered))
	h.Delivered = Captured{Method: request.Method, URL: request.URL.String(), Headers: request.Header.Clone(), Body: delivered}
	response, err := Exchange(r.Context(), request, relay.physical, relay.timeout)
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	h.NativeResponse = &response
	final, err := mutateASResponse(f, relay.mutation, response)
	if err != nil {
		h.Error = err.Error()
		http.Error(w, h.Error, 502)
		return
	}
	h.DeliveredResponse = &final
	for name, values := range final.Header {
		if !strings.EqualFold(name, "Content-Length") {
			w.Header()[name] = append([]string(nil), values...)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(final.Body)))
	w.WriteHeader(final.Status)
	w.Write(final.Body)
}

func mutateASRequest(f Fixture, mutation string, r *http.Request) error {
	if mutation == "as-proof" {
		r.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))+":")
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if mutation == "as-body" {
		body = bytes.Replace(body, []byte("resource_token"), []byte("resourcX_token"), 1)
		r.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	if !strings.HasPrefix(mutation, "as-resource-") && mutation != "as-presented-expired" && mutation != "as-denial" {
		return nil
	}
	var input map[string]string
	if err := json.Unmarshal(body, &input); err != nil {
		return err
	}
	field, seed, kid, typ := "resource_token", f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt"
	if mutation == "as-presented-expired" {
		field, seed, kid, typ = "presented_token", f.Person.Seed, f.Person.Kid, "aa-person+jwt"
	}
	_, claims, err := verifyJWT(input[field], seed, kid, typ)
	if err != nil {
		return fmt.Errorf("cannot inject fault into unverified %s: %w", field, err)
	}
	switch mutation {
	case "as-resource-aud":
		claims["aud"] = f.Person.Issuer
	case "as-resource-jti":
		claims["presented_jti"] = "foreign-presented-jti"
	case "as-resource-ps":
		claims["ps"] = "https://foreign.conformance.test"
	case "as-resource-key":
		claims["agent_jkt"] = thumbprint(f.Person.Seed)
	case "as-presented-expired":
		claims["iat"], claims["exp"] = f.Now-120, f.Now-1
	case "as-denial":
		claims["scope"] = "admin"
	}
	input[field], err = mintJWT(seed, kid, typ, claims)
	if err != nil {
		return err
	}
	body, err = json.Marshal(input)
	if err != nil {
		return err
	}
	credential := fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-person.json";kid=%q`, f.Person.Issuer, f.Person.Kid)
	signed, _, err := signedFixtureRequest(f, f.Person.Seed, r.Method, r.URL.String(), credential, body)
	if err == nil {
		*r = *signed.WithContext(r.Context())
	}
	return err
}

func mutateASResponse(f Fixture, mutation string, response Response) (Response, error) {
	if !strings.HasPrefix(mutation, "grant-") || response.Status != 200 {
		return response, nil
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body, &body); err != nil {
		return response, err
	}
	var compact string
	if err := json.Unmarshal(body["auth_token"], &compact); err != nil {
		return response, err
	}
	_, claims, err := verifyJWT(compact, f.Access.Seed, f.Access.Kid, "aa-auth+jwt")
	if err != nil {
		return response, fmt.Errorf("cannot inject fault into unverifiable native AS grant: %w", err)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp < 0 || exp > 1<<33-1 || exp != float64(int64(exp)) {
		return response, fmt.Errorf("cannot inject fault into malformed native AS expiration")
	}
	seed := f.Access.Seed
	switch mutation {
	case "grant-signature":
		seed = f.Person.Seed
	case "grant-iss":
		claims["iss"] = f.Person.Issuer
	case "grant-aud":
		claims["aud"] = "https://foreign.conformance.test"
	case "grant-key":
		claims["cnf"] = map[string]any{"jwk": publicJWK(f.Person.Seed)}
	case "grant-sub":
		claims["sub"] = "foreign-person"
	case "grant-scope":
		claims["scope"] = "read admin"
	case "grant-exp":
		exp = float64(f.Now + f.Person.Lifetime + 1)
		claims["exp"] = exp
	case "grant-ps":
		claims["ps"] = "https://foreign.conformance.test"
	}
	compact, err = mintJWT(seed, f.Access.Kid, "aa-auth+jwt", claims)
	if err != nil {
		return response, err
	}
	body["auth_token"], _ = json.Marshal(compact)
	body["expires_in"], _ = json.Marshal(int64(exp) - f.Now)
	response.Body, err = json.Marshal(body)
	return response, err
}

var _ http.Handler = (*federationRelay)(nil)
