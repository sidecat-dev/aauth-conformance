package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/dunglas/httpsfv"
)

// VectorsRole runs the community test vectors through each library's own
// parsing and verification functions.
const VectorsRole = "vectors.library"

// vectorEndpoint is the logical address of a vectors launcher's one endpoint.
const vectorEndpoint = "https://vectors.conformance.test/vector"

// vectorKinds are the vector files' kind values this role knows how to send.
var vectorKinds = []string{"agent-identifier", "server-identifier", "jwk-thumbprint", "metadata", "signature-error", "requirement", "signature-key", "jwt", "http-signature"}

// VectorInput is a vector scenario's input: the case exactly as the vector
// file carries it, and where it came from.
type VectorInput struct {
	Source VectorSource    `json:"source"`
	Kind   string          `json:"kind"`
	Case   json.RawMessage `json:"case"`
}
type VectorSource struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Index  int    `json:"index"`
}

func init() {
	RegisterRole(VectorsRole, ExtensionRole{Kinds: []string{"vector-result"}, Validate: validateVectorScenario, Run: runVectors})
}

func validateVectorScenario(f Fixture, s Scenario) error {
	var in VectorInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	digest, err := hex.DecodeString(in.Source.SHA256)
	if !strings.HasPrefix(in.Source.File, "vectors/") || !strings.HasSuffix(in.Source.File, ".json") || strings.Contains(in.Source.File, "..") || err != nil || len(digest) != 32 || in.Source.Index < 0 {
		return fmt.Errorf("%s: vector source needs a vectors/ file, its SHA-256 and a case index", s.ID)
	}
	if !slices.Contains(vectorKinds, in.Kind) || !json.Valid(in.Case) {
		return fmt.Errorf("%s: unknown vector kind %q or invalid case", s.ID, in.Kind)
	}
	if _, err := vectorRequest(f, in); err != nil {
		return fmt.Errorf("%s: %w", s.ID, err)
	}
	for _, a := range s.Assertions {
		if a.Kind != "vector-result" {
			return fmt.Errorf("%s/%s: vector scenarios grade only vector-result", s.ID, a.ID)
		}
		if a.Member == "" || a.Stage != "" || a.Header != "" {
			return fmt.Errorf("%s/%s: vector-result needs a result member and no stage or header", s.ID, a.ID)
		}
	}
	return nil
}

// vectorRequest turns one case into the launcher's input. Everything a
// launcher needs is computed here, so launchers only call native functions:
// the full signed request, the verifier's clock and the trusted documents.
func vectorRequest(f Fixture, in VectorInput) (map[string]any, error) {
	var c map[string]json.RawMessage
	if err := json.Unmarshal(in.Case, &c); err != nil {
		return nil, err
	}
	text := func(name string) string {
		var v string
		json.Unmarshal(c[name], &v)
		return v
	}
	request := map[string]any{"kind": in.Kind}
	switch in.Kind {
	case "agent-identifier", "server-identifier":
		request["input"] = text("input")
	case "jwk-thumbprint":
		request["jwk"] = c["jwk"]
	case "metadata":
		var compact bytes.Buffer
		if err := json.Compact(&compact, c["json"]); err != nil {
			return nil, err
		}
		request["document"] = text("document")
		request["json"] = compact.String()
	case "signature-error":
		request["header"] = text("header")
	case "requirement":
		request["header"] = text("header")
		// Deferred requirement values arrive on a 202; this is the framing
		// such a response carries around the vector's header.
		request["framing"] = map[string]any{"status": 202, "endpoint": "https://ps.example/token", "body": `{"status":"pending"}`, "headers": map[string]string{
			"Location": "https://ps.example/pending/vector", "Retry-After": "0", "Cache-Control": "no-store", "Content-Type": "application/json",
		}}
	case "signature-key":
		// A placeholder signature for label sig lets the library reach its
		// Signature-Key processing; nothing here verifies cryptographically.
		request["label"] = "sig"
		request["now"] = f.Now
		request["request"] = map[string]any{"method": "GET", "url": "https://resource.example/", "headers": map[string]string{
			"Signature-Key":   text("header"),
			"Signature-Input": fmt.Sprintf(`sig=("@method" "@authority" "@path" "signature-key");created=%d`, f.Now),
			"Signature":       "sig=:" + base64.StdEncoding.EncodeToString(make([]byte, 64)) + ":",
		}}
	case "jwt":
		return vectorJWTRequest(c, request)
	case "http-signature":
		return vectorHTTPSignatureRequest(c, request)
	}
	return request, nil
}

// vectorPublicJWK drops the private member from a vector key.
func vectorPublicJWK(raw json.RawMessage) (map[string]any, error) {
	var key map[string]any
	if err := json.Unmarshal(raw, &key); err != nil || key["kty"] == nil {
		return nil, fmt.Errorf("vector signing_key is not a JWK")
	}
	delete(key, "d")
	return key, nil
}

// vectorJWTRequest gives the verifier the token's own issuer as the one it
// trusts, with that issuer's metadata and a JWKS holding the vector's key.
// The clock is the token's iat, or 2026-01-01 when it has none, as the
// vector files define.
func vectorJWTRequest(c map[string]json.RawMessage, request map[string]any) (map[string]any, error) {
	var token, typ, kid, audience string
	json.Unmarshal(c["token"], &token)
	json.Unmarshal(c["typ"], &typ)
	json.Unmarshal(c["kid"], &kid)
	json.Unmarshal(c["audience"], &audience)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt vector token is not compact")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		Iss string `json:"iss"`
		DWK string `json:"dwk"`
		Iat int64  `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss == "" || claims.DWK == "" {
		return nil, fmt.Errorf("jwt vector payload needs iss and dwk")
	}
	key, err := vectorPublicJWK(c["signing_key"])
	if err != nil {
		return nil, err
	}
	key["kid"] = kid
	metadata, _ := json.Marshal(map[string]string{"issuer": claims.Iss, "jwks_uri": claims.Iss + "/.well-known/jwks.json"})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{key}})
	now := claims.Iat
	if now == 0 {
		now = 1767225600
	}
	request["typ"] = typ
	request["token"] = token
	request["audience"] = audience
	request["issuer"] = claims.Iss
	request["dwk"] = claims.DWK
	request["kid"] = kid
	request["now"] = now
	request["metadata"] = string(metadata)
	request["jwks"] = string(jwks)
	return request, nil
}

type vectorHTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// vectorHTTPSignatureRequest assembles the received request exactly as the
// vector defines it: the request, the headers signing added, then any tamper.
// The clock is the signature's created plus at_offset; an absent window is
// the profile's 60-second default.
func vectorHTTPSignatureRequest(c map[string]json.RawMessage, request map[string]any) (map[string]any, error) {
	var base vectorHTTPRequest
	var signed map[string]string
	var tamper *vectorHTTPRequest
	var verify struct {
		AtOffset            int64    `json:"at_offset"`
		WindowSeconds       int64    `json:"window_seconds"`
		RequiredComponents  []string `json:"required_components"`
		RequireBodyCoverage bool     `json:"require_body_coverage"`
	}
	if err := json.Unmarshal(c["request"], &base); err != nil {
		return nil, err
	}
	json.Unmarshal(c["signed"], &signed)
	if raw, ok := c["tamper"]; ok {
		if err := json.Unmarshal(raw, &tamper); err != nil {
			return nil, err
		}
	}
	if raw, ok := c["verify"]; ok {
		if err := json.Unmarshal(raw, &verify); err != nil {
			return nil, err
		}
	}
	headers := map[string]string{}
	for k, v := range base.Headers {
		headers[k] = v
	}
	for k, v := range signed {
		headers[k] = v
	}
	if tamper != nil {
		if tamper.Method != "" {
			base.Method = tamper.Method
		}
		if tamper.URL != "" {
			base.URL = tamper.URL
		}
		if tamper.Body != "" {
			base.Body = tamper.Body
		}
		for k, v := range tamper.Headers {
			headers[k] = v
		}
	}
	base.Headers = headers
	inputs, err := httpsfv.UnmarshalDictionary([]string{headers["Signature-Input"]})
	if err != nil {
		return nil, fmt.Errorf("vector Signature-Input: %w", err)
	}
	member, _ := inputs.Get("sig")
	list, ok := member.(httpsfv.InnerList)
	if !ok || list.Params == nil {
		return nil, fmt.Errorf("vector Signature-Input has no sig label")
	}
	createdValue, _ := list.Params.Get("created")
	created, ok := createdValue.(int64)
	if !ok {
		return nil, fmt.Errorf("vector Signature-Input has no created")
	}
	key, err := vectorPublicJWK(c["signing_key"])
	if err != nil {
		return nil, err
	}
	window := verify.WindowSeconds
	if window == 0 {
		window = 60
	}
	required := verify.RequiredComponents
	if required == nil {
		required = []string{}
	}
	request["request"] = base
	request["key"] = key
	request["label"] = "sig"
	request["now"] = created + verify.AtOffset
	request["window"] = window
	request["required_components"] = required
	request["require_body_coverage"] = verify.RequireBodyCoverage
	return request, nil
}

// VectorOutcome is a launcher's normalized native result. Unoffered names
// result members the library has no public function to produce.
type VectorOutcome struct {
	NotOffered string
	Values     map[string]any
	Unoffered  []string
}

func runVectors(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		var ready Ready
		var stop func()
		startError := ""
		if target.Unavailable == "" {
			config := Bootstrap{Version: 1, Role: VectorsRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: vectorEndpoint, APTransport: ap}
			var err error
			ready, stop, err = startAdapter(ctx, target, config, o)
			if err != nil {
				startError = err.Error()
				run.Error = startError
			}
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runVectorCase(ctx, s.Fixture, scenario, target, ready, startError, o))
		}
		if stop != nil {
			stop()
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func runVectorCase(ctx context.Context, f Fixture, scenario Scenario, target Target, ready Ready, startError string, o Options) Case {
	c := Case{ID: scenario.ID}
	var in VectorInput
	execution := startError
	var outcome VectorOutcome
	if err := Decode(scenario.Input, &in); err != nil && execution == "" {
		execution = err.Error()
	}
	if target.Unavailable == "" && execution == "" {
		input, err := vectorRequest(f, in)
		if err == nil {
			var body []byte
			body, err = json.Marshal(input)
			if err == nil {
				var request *http.Request
				request, err = http.NewRequest(http.MethodPost, vectorEndpoint, bytes.NewReader(body))
				if err == nil {
					request.Header.Set("Content-Type", "application/json")
					c.Method, c.URL, c.RequestBody = request.Method, request.URL.String(), body
					var response Response
					response, err = Exchange(ctx, request, ready.URL, o.Timeout)
					if err == nil {
						c.Response = &response
						outcome, err = vectorDecodeOutcome(response)
						c.Evidence = outcome.Values
					}
				}
			}
		}
		if err != nil {
			execution = err.Error()
		}
	}
	c.Error = execution
	for _, a := range scenario.Assertions {
		if target.Unavailable != "" {
			c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: target.Unavailable})
			continue
		}
		c.Results = append(c.Results, Grade(a, target.Claims, execution, c.Response, func(a Assertion) Result {
			return vectorGrade(a, outcome)
		}))
	}
	return c
}

// vectorDecodeOutcome reads a launcher answer: 200 with a result object,
// or 501 when the library has no public function for the vector kind.
func vectorDecodeOutcome(r Response) (VectorOutcome, error) {
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return VectorOutcome{}, fmt.Errorf("launcher answered HTTP %d without a JSON object", r.Status)
	}
	switch r.Status {
	case http.StatusNotImplemented:
		reason, _ := body["not_offered"].(string)
		if reason == "" {
			return VectorOutcome{}, fmt.Errorf("launcher answered 501 without a not_offered reason")
		}
		return VectorOutcome{NotOffered: reason, Values: body}, nil
	case http.StatusOK:
		outcome := VectorOutcome{Values: body}
		if list, ok := body["unoffered"].([]any); ok {
			for _, v := range list {
				if name, ok := v.(string); ok {
					outcome.Unoffered = append(outcome.Unoffered, name)
				}
			}
		}
		if _, ok := body["accepted"].(bool); !ok {
			return outcome, fmt.Errorf("launcher result has no boolean accepted")
		}
		return outcome, nil
	}
	return VectorOutcome{}, fmt.Errorf("launcher answered HTTP %d", r.Status)
}

// vectorGrade compares one result member with the scenario's expectation.
// A kind or member the library does not offer is not exercised, never a pass.
func vectorGrade(a Assertion, outcome VectorOutcome) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals}
	switch {
	case outcome.NotOffered != "":
		result.State = "not_exercised"
		result.Detail = "not offered: " + outcome.NotOffered
		return result
	case slices.Contains(outcome.Unoffered, a.Member):
		result.State = "not_exercised"
		result.Detail = "not offered: the library exposes no " + a.Member
		return result
	}
	actual, present := outcome.Values[a.Member]
	if !present {
		result.State = "fail"
		result.Detail = "result has no " + a.Member
		return result
	}
	detail := ""
	if text, ok := outcome.Values["error"].(string); ok {
		detail = text
	}
	return CompareResult(a, actual, detail)
}

// vectorCaseFromFile returns case index of a vector file and the file's SHA-256.
func vectorCaseFromFile(data []byte, index int) (json.RawMessage, string, error) {
	var file struct {
		Kind  string            `json:"kind"`
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, "", err
	}
	if index >= len(file.Cases) {
		return nil, "", fmt.Errorf("vector file has %d cases", len(file.Cases))
	}
	sum := sha256.Sum256(data)
	return file.Cases[index], hex.EncodeToString(sum[:]), nil
}

// vectorCanonical serializes JSON with sorted object members so two
// encodings of one value compare equal.
func vectorCanonical(raw json.RawMessage) (string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	var sorted func(any) any
	sorted = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out := make([]any, 0, len(keys))
			for _, k := range keys {
				out = append(out, []any{k, sorted(t[k])})
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, item := range t {
				out[i] = sorted(item)
			}
			return out
		}
		return v
	}
	b, err := json.Marshal(sorted(value))
	return string(b), err
}
