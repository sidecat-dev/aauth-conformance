package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// sigkeyBody is the JSON body of the verifier and signer cases that carry one.
var sigkeyBody = []byte(`{"note":"signature-key conformance"}`)

// sigkeyLaunch is the verifier and signer launchers' extension bootstrap.
// Documents maps each logical HTTPS origin to the loopback transport serving
// its discovery documents; the launcher's host transport routes there.
type sigkeyLaunch struct {
	Verifier      string            `json:"verifier,omitempty"`
	AgentProvider string            `json:"agent_provider"`
	Signer        string            `json:"signer"`
	SignerDWK     string            `json:"signer_dwk"`
	JWKSURL       string            `json:"jwks_url"`
	SelfJWTTyp    string            `json:"self_jwt_typ"`
	Algorithms    []string          `json:"algorithms"`
	Documents     map[string]string `json:"documents"`
}

// sigkeyDocuments serves the fixture discovery documents for one case: the
// Agent Provider, the jwks_uri signer and the direct JWKS URL, each origin on
// its own loopback listener. keySet selects the plain, mixed or
// post-quantum-only key set for the Agent Provider (jwt) or the signer (jwks_uri).
func sigkeyDocuments(f Fixture, k SigkeyFixture, scheme, keySet string) (map[string]string, func(), error) {
	pq, pqErr := sigkeyMLDSA44(k.PQSeed)
	member := func(key sigkeyKey, kid string) map[string]any { return sigkeyCloneJWK(key.public, "kid", kid) }
	set := func(classical map[string]any, pqKid string, variant string) ([]any, error) {
		switch variant {
		case "mixed", "pq-only":
			if pqErr != nil {
				return nil, pqErr
			}
			if variant == "mixed" {
				return []any{classical, member(pq, pqKid)}, nil
			}
			return []any{member(pq, pqKid)}, nil
		}
		return []any{classical}, nil
	}
	apVariant, signerVariant := "", ""
	if scheme == "jwt" {
		apVariant = keySet
	}
	if scheme == "jwks_uri" {
		signerVariant = keySet
	}
	apKeys, err := set(member(sigkeyEd25519(f.APSeed), f.Kid), k.APPQKid, apVariant)
	if err != nil {
		return nil, nil, err
	}
	signerKeys, err := set(member(sigkeyEd25519(k.Signer.Seed), k.Signer.Kid), k.PQKid, signerVariant)
	if err != nil {
		return nil, nil, err
	}
	jwksURL, _ := url.Parse(k.JWKSURL)
	documents := map[string]map[string]any{
		f.Issuer: {
			"/.well-known/aauth-agent.json": map[string]any{"issuer": f.Issuer, "jwks_uri": f.Issuer + "/.well-known/jwks.json"},
			"/.well-known/jwks.json":        map[string]any{"keys": apKeys},
		},
		k.Signer.Issuer: {
			"/.well-known/" + k.Signer.DWK: map[string]any{"issuer": k.Signer.Issuer, "jwks_uri": k.Signer.Issuer + "/.well-known/jwks.json"},
			"/.well-known/jwks.json":       map[string]any{"keys": signerKeys},
		},
		"https://" + jwksURL.Host: {
			jwksURL.Path: map[string]any{"keys": []any{member(sigkeyEd25519(k.Signer.Seed), k.Signer.Kid)}},
		},
	}
	transports := map[string]string{}
	var stops []func()
	stopAll := func() {
		for _, stop := range stops {
			stop()
		}
	}
	for origin, paths := range documents {
		mux := http.NewServeMux()
		for path, document := range paths {
			body, _ := json.Marshal(document)
			mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "max-age=300")
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				w.Write(body)
			})
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			stopAll()
			return nil, nil, err
		}
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		done := make(chan struct{})
		go func() { defer close(done); server.Serve(listener) }()
		stops = append(stops, func() { server.Close(); <-done })
		transports[origin] = "http://" + listener.Addr().String()
	}
	return transports, stopAll, nil
}

// sigkeyMember serializes one Signature-Key member: a scheme Token with
// String parameters in the given order.
func sigkeyMember(label, scheme string, params ...string) string {
	member := label + "=" + scheme
	for i := 0; i+1 < len(params); i += 2 {
		member += ";" + params[i] + "=" + fmt.Sprintf("%q", params[i+1])
	}
	return member
}

// sigkeyHWKParams lists an inline JWK's members in the scheme's order.
func sigkeyHWKParams(key map[string]any) []string {
	var params []string
	for _, name := range []string{"kty", "crv", "x", "y", "n", "e", "k", "alg", "kid"} {
		if value, ok := key[name].(string); ok {
			params = append(params, name, value)
		}
	}
	return params
}

// sigkeyCredential builds the Signature-Key member value (without label) and
// the key that signs the HTTP request for one verifier case.
func sigkeyCredential(f Fixture, k SigkeyFixture, in sigkeyVerifierInput, id string) (string, []string, sigkeyKey, error) {
	agent := sigkeyEd25519(f.AgentSeed)
	signer := sigkeyEd25519(k.Signer.Seed)
	switch in.Scheme {
	case "hwk":
		key, err := sigkeyAlgKey(k, in.Alg, f.AgentSeed)
		if err != nil {
			return "", nil, key, err
		}
		inline := key.public
		switch in.Mutation {
		case "hwk-kid":
			inline = sigkeyCloneJWK(inline, "kid", "hwk-1")
		case "alg-eddsa":
			inline = sigkeyCloneJWK(inline, "alg", "EdDSA")
		case "alg-kty":
			inline = sigkeyCloneJWK(inline, "alg", "ES256")
		case "alg-crv":
			if key, err = sigkeyFixtureKey(k, "ES384"); err != nil {
				return "", nil, key, err
			}
			inline = sigkeyCloneJWK(key.public, "alg", "ES256")
		case "symmetric":
			key = sigkeySymmetric()
			inline = key.public
		}
		return "hwk", sigkeyHWKParams(inline), key, nil
	case "jwt":
		header := map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": f.Kid}
		issuer := sigkeyEd25519(f.APSeed)
		httpKey, err := sigkeyAlgKey(k, in.Alg, f.AgentSeed)
		if err != nil {
			return "", nil, agent, err
		}
		confirmation := httpKey.public
		claims := map[string]any{"iss": f.Issuer, "sub": f.Subject, "dwk": "aauth-agent.json", "jti": id, "iat": f.Now - 10, "exp": f.Now + 300}
		switch in.Mutation {
		case "alg-eddsa":
			confirmation = sigkeyCloneJWK(confirmation, "alg", "EdDSA")
		case "alg-kty":
			confirmation = sigkeyCloneJWK(confirmation, "alg", "ES256")
		case "symmetric":
			httpKey = sigkeySymmetric()
			confirmation = httpKey.public
		case "no-exp":
			delete(claims, "exp")
		case "header-eddsa":
			header["alg"] = "EdDSA"
		}
		if in.JWKS == "pq-only" {
			pq, err := sigkeyMLDSA44(k.PQSeed)
			if err != nil {
				return "", nil, agent, err
			}
			header["alg"], header["kid"], issuer = "ML-DSA-44", k.APPQKid, pq
		}
		claims["cnf"] = map[string]any{"jwk": confirmation}
		token, err := sigkeyJWS(header, claims, issuer)
		return "jwt", []string{"jwt", token}, httpKey, err
	case "jwks_uri":
		kid, key := k.Signer.Kid, signer
		if in.JWKS == "pq-only" {
			pq, err := sigkeyMLDSA44(k.PQSeed)
			if err != nil {
				return "", nil, signer, err
			}
			kid, key = k.PQKid, pq
		}
		if in.Mutation == "unknown-kid" {
			kid = "signer-absent"
		}
		return "jwks_uri", []string{"id", k.Signer.Issuer, "dwk", k.Signer.DWK, "kid", kid}, key, nil
	case "jwks":
		return "jwks", []string{"url", k.JWKSURL, "kid", k.Signer.Kid}, signer, nil
	case "self-jwt":
		verifier, _ := url.Parse(k.Verifier)
		token, err := sigkeyJWS(
			map[string]any{"alg": "Ed25519", "kid": k.Signer.Kid, "typ": k.SelfJWTTyp},
			map[string]any{"iss": k.Signer.Issuer, "dwk": k.Signer.DWK, "aud": "https://" + verifier.Host, "jti": id, "iat": f.Now - 10, "exp": f.Now + 300},
			signer)
		return "self-jwt", []string{"jwt", token}, signer, err
	case "jkt-jwt":
		token, err := sigkeyJKT(f, k, agent, id)
		return "jkt-jwt", []string{"jwt", token}, agent, err
	}
	return in.Scheme, nil, agent, nil
}

// sigkeyJKT mints a jkt-s256+jwt delegation from the fixture identity key to
// the request key (signature-key "JKT JWT Self-Issued Key Delegation").
func sigkeyJKT(f Fixture, k SigkeyFixture, delegated sigkeyKey, id string) (string, error) {
	identity := sigkeyEd25519(k.JKTSeed)
	return sigkeyJWS(
		map[string]any{"typ": "jkt-s256+jwt", "alg": "Ed25519", "jwk": identity.public},
		map[string]any{"iss": "urn:jkt:sha-256:" + sigkeyThumbprint(identity.public), "iat": f.Now - 10, "exp": f.Now + 300, "jti": id, "cnf": map[string]any{"jwk": delegated.public}},
		identity)
}

// sigkeyVerifierRequest signs one verifier case with independent code.
func sigkeyVerifierRequest(f Fixture, k SigkeyFixture, s Scenario) (*requestRecord, error) {
	var in sigkeyVerifierInput
	if err := DecodeInput(s, &in); err != nil {
		return nil, err
	}
	scheme, params, key, err := sigkeyCredential(f, k, in, s.ID)
	if err != nil {
		return nil, err
	}
	label := "sig"
	if in.Mutation == "missing-member" {
		label = "sig1"
	}
	method, body := "GET", []byte(nil)
	if in.Body {
		method, body = "POST", sigkeyBody
	}
	request, err := http.NewRequest(method, k.Verifier, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Signature-Key", sigkeyMember(label, scheme, params...))
	covered := []string{"@method", "@authority", "@path", "signature-key"}
	if in.Mutation == "uncovered-signature-key" {
		covered = covered[:3]
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		covered = append(covered, "content-type", "content-digest")
	}
	params2 := fmt.Sprintf("(%s);created=%d", sigkeyQuoted(covered), f.Now)
	base := sigkeyBase(request, covered, params2)
	signature, err := key.sign([]byte(base))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Signature-Input", "sig="+params2)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return &requestRecord{stage: "verify", request: request, body: body, base: base}, nil
}

func sigkeyQuoted(components []string) string {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	return strings.Join(quoted, " ")
}

// sigkeyBase builds the RFC 9421 signature base for the components this
// harness signs: the three derived components and plain header fields.
func sigkeyBase(request *http.Request, covered []string, params string) string {
	var lines []string
	for _, component := range covered {
		var value string
		switch component {
		case "@method":
			value = request.Method
		case "@authority":
			value = strings.ToLower(request.URL.Host)
		case "@path":
			value = request.URL.EscapedPath()
		case "@query":
			value = "?" + request.URL.RawQuery
		default:
			value = canonicalField(request.Header, component)
		}
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	return strings.Join(append(lines, `"@signature-params": `+params), "\n")
}

func runSigkeyVerifier(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	k, fixtureErr := sigkeyFixture(s.Fixture)
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			c := Case{ID: scenario.ID}
			var response *Response
			execution := ""
			offered := sigkeyOffered(scenario, target)
			if offered {
				if fixtureErr != nil {
					execution = fixtureErr.Error()
				} else {
					response, execution = sigkeyVerifierCase(ctx, s.Fixture, k, scenario, target, ap, o, &c)
				}
			}
			c.Error = execution
			c.Response = response
			for _, a := range scenario.Assertions {
				if !offered {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: sigkeyNotOffered(target)})
					continue
				}
				c.Results = append(c.Results, Grade(a, target.Claims, execution, response, func(a Assertion) Result {
					return sigkeyCheckPQ(a, response)
				}))
			}
			run.Cases = append(run.Cases, c)
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func sigkeyVerifierCase(ctx context.Context, f Fixture, k SigkeyFixture, s Scenario, target Target, ap string, o Options, c *Case) (*Response, string) {
	var in sigkeyVerifierInput
	DecodeInput(s, &in)
	documents, stop, err := sigkeyDocuments(f, k, in.Scheme, in.JWKS)
	if err != nil {
		return nil, err.Error()
	}
	defer stop()
	record, err := sigkeyVerifierRequest(f, k, s)
	if err != nil {
		return nil, err.Error()
	}
	config := Bootstrap{Version: 1, Role: SigkeyVerifierRole, Now: f.Now, Issuer: f.Issuer, Resource: k.Verifier, APTransport: ap, AgentSeed: f.AgentSeed, Subject: f.Subject}
	config.Extension, _ = json.Marshal(sigkeyLaunch{Verifier: k.Verifier, AgentProvider: f.Issuer, Signer: k.Signer.Issuer, SignerDWK: k.Signer.DWK, JWKSURL: k.JWKSURL, SelfJWTTyp: k.SelfJWTTyp, Algorithms: []string{"Ed25519", "ES256", "ES384", "RS256", "PS256"}, Documents: documents})
	ready, stopAdapter, err := startAdapter(ctx, target, config, o)
	if err != nil {
		return nil, err.Error()
	}
	defer stopAdapter()
	c.Method, c.URL, c.Headers, c.SignatureBase, c.RequestBody = record.request.Method, record.request.URL.String(), record.request.Header.Clone(), record.base, record.body
	response, err := Exchange(ctx, record.request, ready.URL, o.Timeout)
	if err != nil {
		return nil, err.Error()
	}
	return &response, ""
}

// sigkeyCheckPQ grades a case whose key the verifier may not implement: it
// passes when the request verified (2xx), or when the verifier refused with
// 401 and a Signature-Error Token, which must equal the expected code when one
// is given (signature-key "Algorithm Determination": an unimplemented key type
// is rejected with defined error feedback and never fails in an undefined manner).
func sigkeyCheckPQ(a Assertion, r *Response) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	if a.Kind != "sigkey-pq" || r == nil {
		result.State, result.Detail = "error", "no observation for this assertion"
		return result
	}
	var want string
	json.Unmarshal(a.Equals, &want)
	code := ""
	if dictionary, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature-Error")); err == nil {
		if member, ok := dictionary.Get("error"); ok {
			if item, ok := member.(httpsfv.Item); ok {
				if token, ok := item.Value.(httpsfv.Token); ok {
					code = string(token)
				}
			}
		}
	}
	result.Actual = map[string]any{"status": r.Status, "error": code}
	switch {
	case r.Status/100 == 2:
		result.State = "pass"
	case r.Status == 401 && code != "" && (want == "" || code == want):
		result.State = "pass"
	default:
		result.Detail = "neither verified nor refused with 401 and the defined Signature-Error"
	}
	return result
}
