package conformance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// SigvecRole runs the published Signature-Key test vectors
// (vectors/signature-key/) through each library's native verifier.
const SigvecRole = "vectors.signature-key"

// SigvecFilePath is the published vector file, relative to the suite root.
const SigvecFilePath = "vectors/signature-key/signature-key-vectors.json"

// sigvecEndpoint is the logical address of a launcher's one endpoint.
const sigvecEndpoint = "https://vectors.conformance.test/signature-key"

// SigvecFile is the machine-readable vector file. Every member is described
// in vectors/signature-key/README.md.
type SigvecFile struct {
	Version     int              `json:"version"`
	Title       string           `json:"title"`
	Description []string         `json:"description"`
	Drafts      []SigvecDraft    `json:"drafts"`
	Generated   SigvecGenerated  `json:"generated"`
	Verifier    SigvecVerifier   `json:"verifier"`
	Keys        []SigvecKey      `json:"keys"`
	Documents   []SigvecDocument `json:"documents"`
	X509        SigvecX509       `json:"x509"`
	Vectors     []SigvecVector   `json:"vectors"`
}

// SigvecDraft pins one draft the expectations were read from.
type SigvecDraft struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// SigvecGenerated records which library builds produced and checked the file.
type SigvecGenerated struct {
	Libraries []SigvecLibrary `json:"libraries"`
	Harness   string          `json:"harness"`
}
type SigvecLibrary struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// SigvecVerifier is the verifier configuration the expectations assume.
type SigvecVerifier struct {
	Resource      string   `json:"resource"`
	AgentProvider string   `json:"agent_provider"`
	SelfJWTTyp    string   `json:"self_jwt_typ"`
	Label         string   `json:"label"`
	WindowSeconds int64    `json:"window_seconds"`
	Schemes       []string `json:"schemes"`
	Algorithms    []string `json:"algorithms"`
}

// SigvecKey is one test key with its private material.
type SigvecKey struct {
	ID         string         `json:"id"`
	Alg        string         `json:"alg"`
	PublicJWK  map[string]any `json:"public_jwk"`
	PrivateJWK map[string]any `json:"private_jwk,omitempty"`
	SeedHex    string         `json:"seed_hex,omitempty"`
	PKCS8      string         `json:"pkcs8_base64,omitempty"`
	Derivation string         `json:"derivation"`
}

// SigvecDocument is one document a verifier would fetch, served from memory.
type SigvecDocument struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// SigvecX509 is the verifier's x509 trust configuration.
type SigvecX509 struct {
	TrustAnchors []string `json:"trust_anchors_der_base64"`
	CRLs         []string `json:"crls_der_base64"`
}

// SigvecVector is one test vector.
type SigvecVector struct {
	ID                  string            `json:"id"`
	Title               string            `json:"title"`
	Category            int               `json:"category"`
	Scheme              string            `json:"scheme,omitempty"`
	Alg                 string            `json:"alg"`
	Now                 int64             `json:"now"`
	Request             SigvecRequest     `json:"request"`
	Signed              map[string]string `json:"signed"`
	SignatureBase       string            `json:"signature_base,omitempty"`
	SignatureBaseSHA256 string            `json:"signature_base_sha256,omitempty"`
	SignatureBaseLength int               `json:"signature_base_length,omitempty"`
	SignatureVerifies   *bool             `json:"signature_verifies,omitempty"`
	SigningKey          string            `json:"signing_key,omitempty"`
	Signatures          []SigvecSignature `json:"signatures,omitempty"`
	Assertion           *SigvecAssertion  `json:"assertion,omitempty"`
	Documents           []SigvecDocument  `json:"documents,omitempty"`
	Resolves            []string          `json:"resolves,omitempty"`
	Expect              SigvecExpect      `json:"expect"`
	// Optional, when present, says why an implementation may skip the
	// vector's category check, and what it is still graded on.
	Optional   string           `json:"optional,omitempty"`
	Provenance SigvecProvenance `json:"provenance"`
}

// SigvecSignature is one signature of a vector that carries more than one.
// The verifier verifies every listed label, each over its own base; the
// vector's top-level scheme, signing_key and signature base are then absent.
type SigvecSignature struct {
	Label               string   `json:"label"`
	Scheme              string   `json:"scheme"`
	Alg                 string   `json:"alg"`
	SigningKey          string   `json:"signing_key"`
	SignatureBase       string   `json:"signature_base"`
	SignatureBaseSHA256 string   `json:"signature_base_sha256"`
	SignatureBaseLength int      `json:"signature_base_length"`
	SignatureVerifies   *bool    `json:"signature_verifies,omitempty"`
	Resolves            []string `json:"resolves,omitempty"`
}

// SigvecLabels is the labels a vector's verifier verifies: every label of a
// multi-signature vector, or nil for the configured label alone.
func SigvecLabels(v SigvecVector) []string {
	labels := []string{}
	for _, s := range v.Signatures {
		labels = append(labels, s.Label)
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// SigvecRequest is the request before signing. The received request is this
// request with the `signed` header fields added.
type SigvecRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// SigvecAssertion is a JWT a vector carries, decoded for reading.
type SigvecAssertion struct {
	Compact  string         `json:"compact"`
	Header   map[string]any `json:"header"`
	Payload  map[string]any `json:"payload"`
	SignedBy string         `json:"signed_by"`
}

// SigvecExpect is the verification result the drafts fix.
type SigvecExpect struct {
	Outcome               string   `json:"outcome"`
	Error                 string   `json:"error,omitempty"`
	RequiredInputIncludes []string `json:"required_input_includes,omitempty"`
	Basis                 string   `json:"basis"`
}

// SigvecProvenance says who produced the vector's signature.
type SigvecProvenance struct {
	SignedBy     string   `json:"signed_by"`
	ReproducedBy []string `json:"reproduced_by,omitempty"`
	Mutation     string   `json:"mutation,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// SigvecInput is a vector scenario's input: the vector and the verifier
// environment exactly as the file defines them, and where they came from.
type SigvecInput struct {
	Source      VectorSource      `json:"source"`
	Vector      SigvecVector      `json:"vector"`
	Environment SigvecEnvironment `json:"environment"`
}

// SigvecEnvironment is what a verifier holds before the request arrives:
// its configuration, the documents it can fetch, and its x509 trust.
type SigvecEnvironment struct {
	Verifier  SigvecVerifier   `json:"verifier"`
	Documents []SigvecDocument `json:"documents"`
	X509      SigvecX509       `json:"x509"`
}

var sigvecOutcomes = []string{"verify", "reject", "verify-or-reject"}

func init() {
	RegisterRole(SigvecRole, ExtensionRole{Kinds: []string{"sigkey-pq"}, Validate: validateSigvecScenario, Run: runSigvec})
}

// SigvecEnvironmentFor returns the environment for one vector: the file's
// documents, with the vector's own documents replacing those at the same URL.
func SigvecEnvironmentFor(file SigvecFile, v SigvecVector) SigvecEnvironment {
	documents := []SigvecDocument{}
	replaced := map[string]bool{}
	for _, d := range v.Documents {
		replaced[d.URL] = true
	}
	for _, d := range file.Documents {
		if !replaced[d.URL] {
			documents = append(documents, d)
		}
	}
	documents = append(documents, v.Documents...)
	slices.SortFunc(documents, func(a, b SigvecDocument) int { return strings.Compare(a.URL, b.URL) })
	return SigvecEnvironment{Verifier: file.Verifier, Documents: documents, X509: file.X509}
}

func validateSigvecScenario(_ Fixture, s Scenario) error {
	var in SigvecInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	digest, err := hex.DecodeString(in.Source.SHA256)
	if in.Source.File != SigvecFilePath || err != nil || len(digest) != 32 || in.Source.Index < 0 {
		return fmt.Errorf("%s: source must name %s, its SHA-256 and a vector index", s.ID, SigvecFilePath)
	}
	v := in.Vector
	if v.ID == "" || !slices.Contains(sigvecOutcomes, v.Expect.Outcome) || v.Category < 1 || v.Category > 3 || v.Request.Method == "" || len(v.Signed) == 0 {
		return fmt.Errorf("%s: vector needs an id, a category, an outcome, a request and signed fields", s.ID)
	}
	if !strings.HasPrefix(v.Request.URL, "https://") || in.Environment.Verifier.Resource == "" || in.Environment.Verifier.Label == "" {
		return fmt.Errorf("%s: vector request and verifier need HTTPS URLs and a label", s.ID)
	}
	for _, a := range s.Assertions {
		if a.Stage != "" {
			return fmt.Errorf("%s/%s: vector assertions have no stage", s.ID, a.ID)
		}
	}
	return nil
}

// SigvecVerifyJob is the launcher input for one vector: the received request,
// the verifier clock, the environment and, for a multi-signature vector, the
// labels to verify.
type SigvecVerifyJob struct {
	Op          string            `json:"op"`
	Now         int64             `json:"now"`
	Request     SigvecRequest     `json:"request"`
	Environment SigvecEnvironment `json:"environment"`
	// Labels, when present, replaces the configured label: the launcher
	// verifies every one and answers 200 only when all verify.
	Labels []string `json:"labels,omitempty"`
}

// SigvecReceived is the request a verifier receives for a vector.
func SigvecReceived(v SigvecVector) SigvecRequest {
	received := SigvecRequest{Method: v.Request.Method, URL: v.Request.URL, Body: v.Request.Body, Headers: map[string]string{}}
	for name, value := range v.Request.Headers {
		received.Headers[name] = value
	}
	for name, value := range v.Signed {
		received.Headers[name] = value
	}
	return received
}

func runSigvec(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		var ready Ready
		var stop func()
		startError := ""
		if target.Unavailable == "" {
			config := Bootstrap{Version: 1, Role: SigvecRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: sigvecEndpoint, APTransport: ap}
			var err error
			ready, stop, err = startAdapter(ctx, target, config, o)
			if err != nil {
				startError = err.Error()
				run.Error = startError
			}
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runSigvecCase(ctx, scenario, target, ready, startError, o))
		}
		if stop != nil {
			stop()
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func runSigvecCase(ctx context.Context, scenario Scenario, target Target, ready Ready, startError string, o Options) Case {
	c := Case{ID: scenario.ID}
	claimed := false
	for _, a := range scenario.Assertions {
		claimed = claimed || slices.Contains(target.Claims, a.Clause)
	}
	var in SigvecInput
	execution := startError
	if err := Decode(scenario.Input, &in); err != nil && execution == "" {
		execution = err.Error()
	}
	if target.Unavailable == "" && claimed && execution == "" {
		received := SigvecReceived(in.Vector)
		c.SignatureBase = in.Vector.SignatureBase
		body, err := json.Marshal(SigvecVerifyJob{Op: "verify", Now: in.Vector.Now, Request: received, Environment: in.Environment, Labels: SigvecLabels(in.Vector)})
		if err == nil {
			var request *http.Request
			request, err = http.NewRequest(http.MethodPost, sigvecEndpoint, bytes.NewReader(body))
			if err == nil {
				request.Header.Set("Content-Type", "application/json")
				c.Method, c.URL, c.RequestBody = request.Method, request.URL.String(), body
				var response Response
				response, err = Exchange(ctx, request, ready.URL, o.Timeout)
				if err == nil {
					c.Response = &response
					if response.Status == http.StatusNotImplemented || response.Status == http.StatusUnprocessableEntity {
						err = fmt.Errorf("launcher answered %d: %s", response.Status, strings.TrimSpace(string(response.Body)))
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
			return sigkeyCheckPQ(a, c.Response)
		}))
	}
	return c
}
