package conformance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// R3 roles (draft-hardt-aauth-r3). The harness plays every party except the
// one under test and grades the native role's wire output.
const R3ResourceRole = "r3.resource"
const R3IssuerRole = "r3.issuer"

// R3Fixture is fixture.json extensions.r3: the Resource's authoritative
// operations and a further trusted server that is entitled to no document.
type R3Fixture struct {
	Vocabulary string   `json:"vocabulary"`
	Tools      []string `json:"tools"`
	Grantable  []string `json:"grantable"`
	Other      R3Server `json:"other_server"`
}
type R3Server struct {
	Issuer string `json:"issuer"`
	Seed   string `json:"seed_hex"`
	Kid    string `json:"kid"`
}

// R3ResourceInput drives a native Resource. The harness acts as Agent, PS
// and (four-party) AS: it mints the Person token and the Auth token itself.
type R3ResourceInput struct {
	Topology   string   `json:"topology"`
	Vocabulary string   `json:"vocabulary,omitempty"`
	Operations []string `json:"operations"`
	Fetches    []string `json:"fetches,omitempty"`
	Grant      []string `json:"grant,omitempty"`
	PerCall    []string `json:"per_call,omitempty"`
	Calls      []string `json:"calls,omitempty"`
	// PerCallFlow completes the one per-call call: "complete" retries it with
	// the approved parameters and repeats it; "mismatch" retries it with others.
	PerCallFlow string `json:"per_call_flow,omitempty"`
}

// R3IssuerInput drives a native three-party PS as the Auth-token issuer. The
// harness acts as Agent and Resource and serves the R3 document itself.
type R3IssuerInput struct {
	Document   string   `json:"document"`
	Operations []string `json:"operations"`
	Scope      string   `json:"scope,omitempty"`
}

var r3FetchModes = []string{"access", "person", "other", "agent", "unsigned", "tampered"}
var r3IssuerDocuments = []string{"exact", "altered", "missing"}

func init() {
	RegisterRole(R3ResourceRole, ExtensionRole{
		Kinds:    []string{"r3-resource-token", "r3-no-resource-token", "r3-document-digest", "r3-no-document", "r3-document-fields", "r3-document-covers", "r3-vocabularies", "r3-per-call-challenge", "r3-proposal", "r3-executions"},
		Validate: validateR3ResourceScenario,
		Run:      runR3Resources,
	})
	RegisterRole(R3IssuerRole, ExtensionRole{
		Kinds:    []string{"r3-fetched", "r3-fetch-proof", "r3-auth-token", "r3-auth-scope", "r3-no-auth-token"},
		Validate: validateR3IssuerScenario,
		Run:      runR3Issuers,
	})
}

func r3Fixture(f Fixture) (R3Fixture, error) {
	var r R3Fixture
	if err := DecodeExtension(f, "r3", &r); err != nil {
		return r, err
	}
	if f.Person == nil || f.Access == nil {
		return r, fmt.Errorf("R3 roles require the Person and Access Server fixtures")
	}
	if err := validatePersonFixture(*f.Person); err != nil {
		return r, err
	}
	if r.Vocabulary != "urn:aauth:vocabulary:mcp" || len(r.Tools) == 0 || len(r.Grantable) == 0 {
		return r, fmt.Errorf("extensions.r3 needs the MCP vocabulary, tools and grantable tools")
	}
	for _, tool := range append(slices.Clone(r.Tools), r.Grantable...) {
		if tool == "" || strings.ContainsAny(tool, "/?#% ") {
			return r, fmt.Errorf("extensions.r3 tool %q is not a plain path segment", tool)
		}
	}
	for _, tool := range r.Grantable {
		if !slices.Contains(r.Tools, tool) {
			return r, fmt.Errorf("grantable tool %q is not in tools", tool)
		}
	}
	u, err := url.Parse(r.Other.Issuer)
	seed, seedErr := hex.DecodeString(r.Other.Seed)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || r.Other.Kid == "" || seedErr != nil || len(seed) != 32 {
		return r, fmt.Errorf("extensions.r3 other_server needs an HTTPS issuer, kid and 32-byte seed")
	}
	for _, id := range []string{f.Issuer, f.Origin, f.Person.Issuer, f.Access.Issuer} {
		if id == r.Other.Issuer {
			return r, fmt.Errorf("extensions.r3 other_server must be a distinct identity")
		}
	}
	return r, nil
}

// r3Stages lists the stages a Resource scenario produces, in order.
func r3Stages(in R3ResourceInput) []string {
	stages := []string{"metadata", "authorize"}
	seen := map[string]int{}
	for _, mode := range in.Fetches {
		seen[mode]++
		stage := "fetch-" + mode
		if seen[mode] > 1 {
			stage = fmt.Sprintf("%s-%d", stage, seen[mode])
		}
		stages = append(stages, stage)
	}
	for _, tool := range in.Calls {
		stages = append(stages, "call-"+tool)
	}
	if in.PerCallFlow != "" && len(in.Calls) == 1 {
		tool := in.Calls[0]
		stages = append(stages, "fetch-proposal", "retry-"+tool)
		if in.PerCallFlow == "complete" {
			stages = append(stages, "repeat-"+tool)
		}
		stages = append(stages, "executions")
	}
	return stages
}

func validateR3ResourceScenario(f Fixture, s Scenario) error {
	fixture, err := r3Fixture(f)
	if err != nil {
		return err
	}
	var in R3ResourceInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains([]string{"four-party", "three-party"}, in.Topology) || len(in.Operations) == 0 {
		return fmt.Errorf("%s: topology four-party or three-party and operations are required", s.ID)
	}
	if in.Vocabulary != "" && in.Vocabulary != fixture.Vocabulary && in.Vocabulary != "urn:aauth:vocabulary:openapi" {
		return fmt.Errorf("%s: vocabulary override must be the fixture vocabulary or OpenAPI", s.ID)
	}
	for _, mode := range in.Fetches {
		if !slices.Contains(r3FetchModes, mode) {
			return fmt.Errorf("%s: unknown fetch mode %q", s.ID, mode)
		}
	}
	calls := map[string]bool{}
	for _, list := range [][]string{in.Operations, in.Grant, in.PerCall, in.Calls} {
		for _, tool := range list {
			if tool == "" || strings.ContainsAny(tool, "/?#% ") {
				return fmt.Errorf("%s: operation %q is not a plain path segment", s.ID, tool)
			}
		}
	}
	for _, tool := range in.Calls {
		if calls[tool] {
			return fmt.Errorf("%s: repeated call %q", s.ID, tool)
		}
		calls[tool] = true
	}
	if len(in.Calls) > 0 && len(in.Grant)+len(in.PerCall) == 0 {
		return fmt.Errorf("%s: calls need an Auth token grant", s.ID)
	}
	if in.PerCallFlow != "" && (!slices.Contains([]string{"complete", "mismatch"}, in.PerCallFlow) || in.Topology != "four-party" ||
		len(in.Calls) != 1 || !slices.Contains(in.PerCall, in.Calls[0])) {
		return fmt.Errorf("%s: per_call_flow complete or mismatch follows exactly one four-party call to an r3_per_call operation", s.ID)
	}
	stages := r3Stages(in)
	for _, a := range s.Assertions {
		if !slices.Contains(stages, a.Stage) {
			return fmt.Errorf("%s/%s: stage %q is not produced by this input", s.ID, a.ID, a.Stage)
		}
		if a.Kind == "r3-executions" {
			var value any
			json.Unmarshal(a.Equals, &value)
			if _, ok := value.(float64); !ok || a.Stage != "executions" {
				return fmt.Errorf("%s/%s: r3-executions is a count graded on the executions stage", s.ID, a.ID)
			}
			continue
		}
		if a.Stage == "executions" {
			return fmt.Errorf("%s/%s: the executions stage carries only r3-executions", s.ID, a.ID)
		}
		if strings.HasPrefix(a.Kind, "r3-") {
			if err := requireBoolean(a); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
			}
			want := map[string]string{"r3-resource-token": "authorize", "r3-no-resource-token": "authorize", "r3-vocabularies": "metadata", "r3-per-call-challenge": "call-", "r3-proposal": "fetch-proposal"}[a.Kind]
			if want == "" {
				want = "fetch-"
			}
			if !strings.HasPrefix(a.Stage, want) {
				return fmt.Errorf("%s/%s: %s is graded only on %s stages", s.ID, a.ID, a.Kind, want)
			}
		}
	}
	return nil
}

func validateR3IssuerScenario(f Fixture, s Scenario) error {
	if _, err := r3Fixture(f); err != nil {
		return err
	}
	var in R3IssuerInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains(r3IssuerDocuments, in.Document) || len(in.Operations) == 0 || in.Scope != "" && in.Scope != "read" && in.Scope != "admin" {
		return fmt.Errorf("%s: document exact, altered or missing, operations, and scope read or admin are required", s.ID)
	}
	for _, a := range s.Assertions {
		if !slices.Contains([]string{"person", "fetch", "token"}, a.Stage) {
			return fmt.Errorf("%s/%s: issuer stages are person, fetch and token", s.ID, a.ID)
		}
		switch a.Kind {
		case "r3-fetched", "r3-fetch-proof":
			if a.Stage != "fetch" {
				return fmt.Errorf("%s/%s: %s is graded on the fetch stage", s.ID, a.ID, a.Kind)
			}
		case "r3-auth-token", "r3-no-auth-token", "r3-auth-scope":
			if a.Stage != "token" {
				return fmt.Errorf("%s/%s: %s is graded on the token stage", s.ID, a.ID, a.Kind)
			}
		default:
			if a.Stage == "fetch" {
				return fmt.Errorf("%s/%s: the fetch stage has no response to grade", s.ID, a.ID)
			}
		}
		if a.Kind == "r3-auth-scope" {
			var value any
			json.Unmarshal(a.Equals, &value)
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s/%s: r3-auth-scope equals the expected scope string", s.ID, a.ID)
			}
		} else if strings.HasPrefix(a.Kind, "r3-") {
			if err := requireBoolean(a); err != nil {
				return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
			}
		}
	}
	return nil
}

func requireBoolean(a Assertion) error {
	var value any
	json.Unmarshal(a.Equals, &value)
	if _, ok := value.(bool); !ok {
		return fmt.Errorf("%s requires a boolean", a.Kind)
	}
	return nil
}

// r3Operations is the vocabulary-specific operation list of r3_operations,
// r3_granted and r3_per_call: MCP names a tool, OpenAPI an operationId.
func r3Operations(vocabulary string, tools []string) []any {
	key := "tool"
	if vocabulary == "urn:aauth:vocabulary:openapi" {
		key = "operationId"
	}
	operations := []any{}
	for _, tool := range tools {
		operations = append(operations, map[string]any{key: tool})
	}
	return operations
}

func r3Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// R3TokenObservation is the harness's independent reading of an R3 token.
type R3TokenObservation struct {
	Valid  bool           `json:"valid"`
	Claims map[string]any `json:"claims,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// observeR3ResourceToken verifies the native Resource token: Ed25519 under the
// fixture Resource key, typ aa-resource+jwt, the Resource as issuer, the
// topology's Auth-token issuer as audience, and both R3 claims present
// (Resource Token Extensions).
func observeR3ResourceToken(f Fixture, response Response, audience string) R3TokenObservation {
	compact, err := responseToken(response, "resource_token")
	if err != nil {
		return R3TokenObservation{Error: err.Error()}
	}
	_, claims, err := verifyJWT(compact, f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt")
	if err != nil {
		return R3TokenObservation{Claims: claims, Error: err.Error()}
	}
	o := R3TokenObservation{Claims: claims}
	uri, _ := claims["r3_uri"].(string)
	digest, _ := claims["r3_s256"].(string)
	parsed, err := url.Parse(uri)
	raw, digestErr := base64.RawURLEncoding.Strict().DecodeString(digest)
	switch {
	case claims["iss"] != f.Origin:
		o.Error = "Resource token iss is not the Resource"
	case claims["aud"] != audience:
		o.Error = "Resource token aud is not this topology's Auth-token issuer"
	case err != nil || parsed.Scheme != "https" || parsed.Host == "":
		o.Error = "Resource token lacks an HTTPS r3_uri"
	case digestErr != nil || len(raw) != sha256.Size:
		o.Error = "Resource token lacks a SHA-256 base64url r3_s256"
	default:
		o.Valid = true
	}
	return o
}

// r3DocumentObservation reads one served document against the token's hash,
// the vocabularies the Resource advertised and the operations requested.
type R3DocumentObservation struct {
	Digest   string `json:"served_s256"`
	Matches  bool   `json:"matches_r3_s256"`
	Fields   bool   `json:"required_fields"`
	Covers   bool   `json:"covers_requested"`
	Document any    `json:"document,omitempty"`
	Error    string `json:"error,omitempty"`
}

func observeR3Document(response Response, digest string, advertised map[string]any, vocabulary string, requested []any) R3DocumentObservation {
	o := R3DocumentObservation{Digest: r3Digest(response.Body)}
	o.Matches = response.Status == 200 && digest != "" && o.Digest == digest
	var document map[string]any
	if err := json.Unmarshal(response.Body, &document); err != nil {
		o.Error = "served bytes are not a JSON object"
		return o
	}
	o.Document = document
	v, _ := document["vocabulary"].(string)
	operations, ok := document["operations"].([]any)
	_, isAdvertised := advertised[v]
	o.Fields = v != "" && isAdvertised && ok
	if !o.Fields {
		o.Error = "document lacks vocabulary advertised in r3_vocabularies or an operations array"
	}
	o.Covers = o.Fields && v == vocabulary
	for _, want := range requested {
		found := false
		for _, have := range operations {
			found = found || jsonEqual(have, want)
		}
		o.Covers = o.Covers && found
	}
	return o
}

// r3Vocabularies checks r3_vocabularies: every key is an absolute URI, keys
// in the standard namespace name a vocabulary this document defines, and
// the fixture vocabulary is advertised.
func r3Vocabularies(response Response, vocabulary string) (map[string]any, bool) {
	var metadata map[string]any
	if response.Status != 200 || json.Unmarshal(response.Body, &metadata) != nil {
		return nil, false
	}
	advertised, ok := metadata["r3_vocabularies"].(map[string]any)
	if !ok || len(advertised) == 0 {
		return nil, false
	}
	standard := []string{"mcp", "openapi", "grpc", "graphql", "asyncapi", "wsdl", "odata"}
	for key, endpoint := range advertised {
		u, err := url.Parse(key)
		if _, isString := endpoint.(string); err != nil || u.Scheme == "" || !isString {
			return advertised, false
		}
		if name, isStandard := strings.CutPrefix(key, "urn:aauth:vocabulary:"); isStandard && !slices.Contains(standard, name) {
			return advertised, false
		}
	}
	_, present := advertised[vocabulary]
	return advertised, present
}

// observeR3AuthToken verifies the native PS-issued Auth token: Ed25519 under
// the fixture PS key, typ aa-auth+jwt, PS issuer and ps, Resource audience,
// r3_uri and r3_s256 equal to the Resource token's, and r3_granted naming the
// vocabulary with operations drawn from the document (Issuer Processing step 6).
func observeR3AuthToken(f Fixture, response Response, resourceURI, resourceDigest string, document []any, vocabulary string) R3TokenObservation {
	compact, err := responseToken(response, "auth_token")
	if err != nil {
		return R3TokenObservation{Error: err.Error()}
	}
	_, claims, err := verifyJWT(compact, f.Person.Seed, f.Person.Kid, "aa-auth+jwt")
	if err != nil {
		return R3TokenObservation{Claims: claims, Error: err.Error()}
	}
	o := R3TokenObservation{Claims: claims}
	granted, _ := claims["r3_granted"].(map[string]any)
	operations, ok := granted["operations"].([]any)
	inside := ok
	for _, operation := range operations {
		found := false
		for _, have := range document {
			found = found || jsonEqual(have, operation)
		}
		inside = inside && found
	}
	switch {
	case claims["iss"] != f.Person.Issuer || claims["ps"] != f.Person.Issuer || claims["aud"] != f.Origin:
		o.Error = "Auth token iss, ps or aud does not name the PS and the Resource"
	case claims["r3_uri"] != resourceURI || claims["r3_s256"] != resourceDigest:
		o.Error = "Auth token r3_uri/r3_s256 differ from the Resource token"
	case granted == nil || granted["vocabulary"] != vocabulary || !inside:
		o.Error = "Auth token r3_granted is absent, names another vocabulary or an operation outside the document"
	default:
		o.Valid = true
	}
	return o
}

func noR3Token(response Response, name string) bool {
	var body map[string]any
	if json.Unmarshal(response.Body, &body) != nil {
		return true
	}
	_, present := body[name]
	return !present
}

// observeR3PerCallChallenge reads a per-call challenge: 401 or 202 with
// requirement=auth-token and a native Resource token whose r3_uri names a
// proposal other than the class document, addressed to the AS, whose
// presented_jti names the class Auth token the call carried (Flow, step 1).
func observeR3PerCallChallenge(f Fixture, response Response, classURI, classJTI string) R3TokenObservation {
	if response.Status != 401 && response.Status != 202 {
		return R3TokenObservation{Error: fmt.Sprintf("per-call call answered HTTP %d, not a 401 or 202 AAuth-Requirement", response.Status)}
	}
	compact, err := challengedResourceToken(response)
	if err != nil {
		return R3TokenObservation{Error: err.Error()}
	}
	body, _ := json.Marshal(map[string]string{"resource_token": compact})
	o := observeR3ResourceToken(f, Response{Status: 200, Body: body}, f.Access.Issuer)
	switch {
	case !o.Valid:
	case o.Claims["r3_uri"] == classURI:
		o.Valid, o.Error = false, "per-call Resource token references the class document, not a proposal"
	case o.Claims["presented_jti"] != classJTI:
		o.Valid, o.Error = false, "per-call Resource token presented_jti does not name the class Auth token"
	}
	return o
}

// r3ProposalShape checks a served per-call proposal: operations is exactly
// the invoked operation and parameters carries the call's record value
// (Proposal Document, lines 643-645).
func r3ProposalShape(response Response, vocabulary, tool string, record any) bool {
	var proposal map[string]any
	if response.Status != 200 || json.Unmarshal(response.Body, &proposal) != nil {
		return false
	}
	operations, _ := proposal["operations"].([]any)
	parameters, _ := proposal["parameters"].(map[string]any)
	return proposal["vocabulary"] == vocabulary && len(operations) == 1 &&
		jsonEqual(operations[0], r3Operations(vocabulary, []string{tool})[0]) && jsonEqual(parameters["record"], record)
}
