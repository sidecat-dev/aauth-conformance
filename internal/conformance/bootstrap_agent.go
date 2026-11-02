package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
)

// signedRequest is one received request's RFC 9421 signature, read without
// trusting any key it names.
type signedRequest struct {
	Scheme  string            `json:"scheme"`
	Params  map[string]string `json:"params,omitempty"`
	Covered []string          `json:"covered,omitempty"`
	Created int64             `json:"created"`
	Base    string            `json:"signature_base,omitempty"`
	Error   string            `json:"error,omitempty"`
	sig     []byte
}

// readSignedRequest takes the first Signature-Key label that also has a
// Signature-Input and Signature, and builds its signature base for the
// derived components and plain header fields this oracle supports.
func readSignedRequest(c Captured) signedRequest {
	out := signedRequest{Params: map[string]string{}}
	keys, e1 := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Key"))
	inputs, e2 := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Input"))
	signatures, e3 := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature"))
	target, e4 := url.Parse(c.URL)
	for _, e := range []error{e1, e2, e3, e4} {
		if e != nil {
			out.Error = e.Error()
			return out
		}
	}
	for _, label := range keys.Names() {
		member, _ := keys.Get(label)
		key, ok := member.(httpsfv.Item)
		input, okInput := inputs.Get(label)
		signature, okSignature := signatures.Get(label)
		if !ok || !okInput || !okSignature {
			continue
		}
		scheme, _ := key.Value.(httpsfv.Token)
		out.Scheme = string(scheme)
		if key.Params != nil {
			for _, name := range key.Params.Names() {
				value, _ := key.Params.Get(name)
				if text, isText := value.(string); isText {
					out.Params[name] = text
				}
			}
		}
		list, ok := input.(httpsfv.InnerList)
		if !ok || list.Params == nil {
			out.Error = "Signature-Input member is not an inner list with parameters"
			return out
		}
		if created, present := list.Params.Get("created"); present {
			out.Created, _ = created.(int64)
		}
		lines := []string{}
		for _, item := range list.Items {
			component, ok := item.Value.(string)
			if !ok || slices.Contains(out.Covered, component) || item.Params != nil && len(item.Params.Names()) > 0 {
				out.Error = "unsupported or repeated covered component"
				return out
			}
			out.Covered = append(out.Covered, component)
			var value string
			switch {
			case component == "@method":
				value = c.Method
			case component == "@authority":
				value = strings.ToLower(target.Host)
			case component == "@path":
				value = target.EscapedPath()
			case component == "@query":
				value = "?" + target.RawQuery
			case !strings.HasPrefix(component, "@") && component == strings.ToLower(component):
				value = canonicalField(c.Headers, component)
			default:
				out.Error = "unsupported derived component " + component
				return out
			}
			lines = append(lines, fmt.Sprintf("%q: %s", component, value))
		}
		params, err := httpsfv.Marshal(list)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Base = strings.Join(append(lines, `"@signature-params": `+params), "\n")
		item, ok := signature.(httpsfv.Item)
		if raw, isBytes := item.Value.([]byte); ok && isBytes {
			out.sig = raw
		}
		return out
	}
	out.Error = "no Signature-Key label with matching Signature-Input and Signature"
	return out
}

// verifiedBy reports whether key signed the base, at the fixture clock and
// covering the components every AAuth signature covers (core Covered
// Components), plus extra.
func (r signedRequest) verifiedBy(f Fixture, key ed25519.PublicKey, extra ...string) bool {
	if r.Error != "" || len(key) != ed25519.PublicKeySize || r.Created < f.Now-60 || r.Created > f.Now+60 || !ed25519.Verify(key, []byte(r.Base), r.sig) {
		return false
	}
	for _, component := range append([]string{"@method", "@authority", "@path", "signature-key"}, extra...) {
		if !slices.Contains(r.Covered, component) {
			return false
		}
	}
	return true
}

// coversBody reports content-type and content-digest coverage of a JSON
// body whose sha-256 Content-Digest matches its bytes.
func (r signedRequest) coversBody(c Captured) bool {
	if len(c.Body) == 0 || !slices.Contains(r.Covered, "content-type") || !slices.Contains(r.Covered, "content-digest") {
		return false
	}
	digest := sha256.Sum256(c.Body)
	return slices.Contains(strings.Split(strings.ReplaceAll(canonicalField(c.Headers, "content-digest"), " ", ""), ","), "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
}

// hwkKey is the Ed25519 key an hwk member carries.
func (r signedRequest) hwkKey() ed25519.PublicKey {
	if r.Scheme != "hwk" {
		return nil
	}
	return confirmationPublicKey(map[string]any{"kty": r.Params["kty"], "crv": r.Params["crv"], "x": r.Params["x"], "alg": r.Params["alg"]})
}

// namingObservation is a jkt-jwt naming JWT read independently: the header
// key that signed it and the delegated cnf key.
type namingObservation struct {
	Header             map[string]any `json:"header,omitempty"`
	Claims             map[string]any `json:"claims,omitempty"`
	Valid              bool           `json:"valid"`
	Error              string         `json:"error,omitempty"`
	durable, delegated ed25519.PublicKey
}

// readNamingJWT applies Signature-Key's jkt-jwt verification steps 1-10
// (lines 412-430) for typ jkt-s256+jwt and an Ed25519 header key.
func readNamingJWT(f Fixture, compact string) namingObservation {
	o := namingObservation{}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		o.Error = "naming JWT needs three parts"
		return o
	}
	decoded := make([][]byte, 3)
	for i, p := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil {
			o.Error = err.Error()
			return o
		}
		decoded[i] = b
	}
	json.Unmarshal(decoded[0], &o.Header)
	json.Unmarshal(decoded[1], &o.Claims)
	o.durable = confirmationPublicKey(o.Header["jwk"])
	cnf, _ := o.Claims["cnf"].(map[string]any)
	if cnf != nil {
		o.delegated = confirmationPublicKey(cnf["jwk"])
	}
	iat, iatOK := o.Claims["iat"].(float64)
	exp, expOK := o.Claims["exp"].(float64)
	switch {
	case o.Header["typ"] != "jkt-s256+jwt":
		o.Error = "typ is not jkt-s256+jwt"
	case o.Header["alg"] != "Ed25519" || o.durable == nil:
		o.Error = "header jwk is not an Ed25519 key with alg, or alg differs"
	case o.Claims["iss"] != "urn:jkt:sha-256:"+jwkThumbprint(o.durable):
		o.Error = "iss is not the JWK Thumbprint URI of the header jwk"
	case !ed25519.Verify(o.durable, []byte(parts[0]+"."+parts[1]), decoded[2]):
		o.Error = "the header jwk did not sign the naming JWT"
	case !iatOK || !expOK || exp <= iat || exp <= float64(f.Now):
		o.Error = "iat and an unexpired exp are required"
	case o.delegated == nil:
		o.Error = "cnf.jwk is not an Ed25519 key with alg"
	default:
		o.Valid = true
	}
	return o
}

// agentArrival is one request the SUT Agent sent the harness.
type agentArrival struct {
	Stage    string        `json:"stage"`
	Path     string        `json:"path"`
	Captured Captured      `json:"-"`
	Status   int           `json:"status"`
	Signed   signedRequest `json:"signature"`
}

// bootstrapAP plays the Agent Provider for one bootstrap.agent scenario:
// enrollment, two-key refresh and sub-agent issuance at the fixture paths,
// and the Resource a refreshed agent calls. It issues fixture-key tokens to
// requests that verify, and records every arrival for grading.
type bootstrapAP struct {
	f        Fixture
	b        BootstrapFixture
	mu       sync.Mutex
	stage    string
	arrivals []agentArrival
	durable  ed25519.PublicKey
	token    string
	tokenKey ed25519.PublicKey
	issued   int
}

func (h *bootstrapAP) setStage(stage string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stage = stage
}

func (h *bootstrapAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/aauth-agent.json":
		writeJSON(w, http.StatusOK, map[string]any{"issuer": h.f.Issuer, "jwks_uri": h.f.Issuer + "/.well-known/jwks.json"})
		return
	case "/.well-known/jwks.json":
		key := publicJWK(h.f.APSeed)
		key["kid"] = h.f.Kid
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{key}})
		return
	}
	c, err := capturedRequest(r, 65536)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signed := readSignedRequest(c)
	h.mu.Lock()
	defer h.mu.Unlock()
	status, body := h.answer(r.URL.Path, c, signed)
	h.arrivals = append(h.arrivals, agentArrival{Stage: h.stage, Path: r.URL.Path, Captured: c, Status: status, Signed: signed})
	if status == http.StatusUnauthorized {
		w.Header().Set("Signature-Error", "error=invalid_signature")
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, body)
}

// answer is the fixture AP's decision; the grade does not depend on it.
func (h *bootstrapAP) answer(path string, c Captured, signed signedRequest) (int, map[string]any) {
	switch {
	case path == h.b.EnrollmentPath && c.Method == http.MethodPost:
		key := signed.hwkKey()
		if !signed.verifiedBy(h.f, key) {
			return http.StatusUnauthorized, map[string]any{"error": "invalid_signature"}
		}
		h.durable = key
		return http.StatusCreated, map[string]any{"agent": h.f.Subject}
	case path == h.b.RefreshPath && c.Method == http.MethodPost:
		naming := readNamingJWT(h.f, signed.Params["jwt"])
		if signed.Scheme != "jkt-jwt" || !naming.Valid || !signed.verifiedBy(h.f, naming.delegated) {
			return http.StatusUnauthorized, map[string]any{"error": "invalid_signature"}
		}
		if h.durable == nil || !bytes.Equal(naming.durable, h.durable) {
			return http.StatusNotFound, map[string]any{"error": "enrollment_not_found"}
		}
		var request map[string]any
		json.Unmarshal(c.Body, &request)
		claims := map[string]any{"iss": h.f.Issuer, "dwk": "aauth-agent.json", "sub": h.f.Subject, "jti": h.nextJTI(), "iat": h.f.Now, "exp": h.f.Now + h.b.AgentLifetime, "cnf": map[string]any{"jwk": naming.Claims["cnf"].(map[string]any)["jwk"]}}
		if ps, ok := request["ps"].(string); ok && ps != "" {
			claims["ps"] = ps
		}
		h.token = mintJOSE(h.f.APSeed, map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": h.f.Kid}, claims)
		h.tokenKey = naming.delegated
		return http.StatusOK, map[string]any{"agent_token": h.token}
	case path == h.b.SubagentPath && c.Method == http.MethodPost:
		if signed.Scheme != "jwt" || h.token == "" || signed.Params["jwt"] != h.token || !signed.verifiedBy(h.f, h.tokenKey) {
			return http.StatusUnauthorized, map[string]any{"error": "invalid_signature"}
		}
		var request struct {
			JWK           map[string]any `json:"jwk"`
			Discriminator string         `json:"discriminator"`
		}
		json.Unmarshal(c.Body, &request)
		if confirmationPublicKey(request.JWK) == nil {
			return http.StatusBadRequest, map[string]any{"error": "invalid_request"}
		}
		discriminator := request.Discriminator
		if discriminator == "" || !agentLocalRE.MatchString(discriminator) || strings.Contains(discriminator, "+") {
			discriminator = "sub1"
		}
		local, domain, _ := splitAgentIdentifier(h.f.Subject)
		parent := unverifiedClaims(h.token)
		token := mintJOSE(h.f.APSeed, map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": h.f.Kid}, map[string]any{
			"iss": h.f.Issuer, "dwk": "aauth-agent.json", "sub": "aauth:" + local + "+" + discriminator + "@" + domain, "parent_agent": h.f.Subject,
			"ps": parent["ps"], "jti": h.nextJTI(), "iat": h.f.Now, "exp": parent["exp"], "cnf": map[string]any{"jwk": request.JWK}})
		return http.StatusOK, map[string]any{"agent_token": token}
	case strings.HasPrefix(c.URL, h.f.Origin+"/"):
		if signed.Scheme != "jwt" || signed.Params["jwt"] != h.token || !signed.verifiedBy(h.f, h.tokenKey) {
			return http.StatusUnauthorized, map[string]any{"error": "invalid_signature"}
		}
		return http.StatusOK, map[string]any{"sub": h.f.Subject}
	}
	return http.StatusNotFound, map[string]any{"error": "not_found"}
}

func (h *bootstrapAP) nextJTI() string {
	h.issued++
	return fmt.Sprintf("bootstrap-ap-%d", h.issued)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, _ := json.Marshal(value)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

// serveLoopback serves handler on an ephemeral loopback listener.
func serveLoopback(handler http.Handler) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() { server.Close(); <-done }, nil
}

func runBootstrapAgent(ctx context.Context, s Suite, targets Targets, o Options, _ string, report Report) Report {
	return runBootstrapRole(ctx, s, targets, o, report, prepareBootstrapAgent)
}

// prepareBootstrapAgent starts the scenario's harness AP and the Resource
// listener before the launcher, whose bootstrap names the AP's transport.
func prepareBootstrapAgent(f Fixture, b BootstrapFixture, s Scenario) (bootstrapCase, error) {
	harness := &bootstrapAP{f: f, b: b}
	apTransport, stopAP, err := serveLoopback(harness)
	if err != nil {
		return bootstrapCase{}, err
	}
	resourceTransport, stopResource, err := serveLoopback(harness)
	if err != nil {
		stopAP()
		return bootstrapCase{}, err
	}
	return bootstrapCase{
		config: func() Bootstrap {
			config := Bootstrap{Version: 1, Role: BootstrapAgentRole, Now: f.Now, Issuer: f.Issuer, Resource: f.Origin + "/control", APTransport: apTransport}
			config.Extension, _ = json.Marshal(bootstrapLauncher{EnrollmentPath: b.EnrollmentPath, RefreshPath: b.RefreshPath, SubagentPath: b.SubagentPath, PersonServer: f.Person.Issuer})
			return config
		},
		run: func(ctx context.Context, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
			return bootstrapAgentCase(ctx, f, b, s, harness, resourceTransport, ready, o)
		},
		close: func() { stopAP(); stopResource() },
	}, nil
}

// bootstrapAgentCase sends each operation to the launcher's control and
// grades the request it caused at the harness AP or Resource.
func bootstrapAgentCase(ctx context.Context, f Fixture, b BootstrapFixture, s Scenario, h *bootstrapAP, resourceTransport string, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
	var in bootstrapAgentInput
	DecodeInput(s, &in)
	stageNames, _ := bootstrapAgentStages(in)
	stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
	keys := map[string]ed25519.PublicKey{}
	for i, op := range in.Operations {
		stage := stageNames[i]
		h.setStage(stage)
		job := map[string]any{"operation": op}
		switch op {
		case "subagent":
			job["jwk"], job["discriminator"] = publicJWK(b.Seeds["subagent"]), b.Discriminator
		case "call":
			job["method"], job["url"], job["transport"] = http.MethodGet, f.Origin+f.Path, resourceTransport
		}
		control, err := controlRequest("control-"+stage, ready.URL, job)
		if err != nil {
			return stages, exchanges, own, err
		}
		// The control answer is evidence only: an Agent may report the
		// fixture AP's refusal of a request it graded.
		response, err := Exchange(ctx, control.request, ready.URL, o.Timeout)
		exchange := PersonExchange{Stage: control.stage, Method: http.MethodPost, URL: ready.URL, Body: control.body}
		if err != nil {
			exchange.Error = err.Error()
		} else {
			exchange.Response = &response
		}
		exchanges = append(exchanges, exchange)
		h.mu.Lock()
		arrival, found := agentArrival{}, false
		for _, a := range h.arrivals {
			if a.Stage == stage && !found {
				arrival, found = a, true
			}
		}
		token, tokenKey := h.token, h.tokenKey
		h.mu.Unlock()
		if found {
			exchanges = append(exchanges, PersonExchange{Stage: stage, Method: arrival.Captured.Method, URL: arrival.Captured.URL, Headers: arrival.Captured.Headers, Body: arrival.Captured.Body, SignatureBase: arrival.Signed.Base, Response: &Response{Status: arrival.Status}})
		}
		properties, detail := observeAgentStage(f, b, op, arrival, found, keys, token, tokenKey)
		for _, a := range s.Assertions {
			if a.Stage == stage {
				result := CompareResult(a, properties[a.Member], detail[a.Member])
				result.Actual = arrival.Signed
				own[a.ID] = result
			}
		}
	}
	return stages, exchanges, own, nil
}

// observeAgentStage reads the properties of the request one operation
// caused. keys keeps the durable key from enrollment and each refresh's
// delegated key; token is the agent token the harness issued last.
func observeAgentStage(f Fixture, b BootstrapFixture, op string, a agentArrival, found bool, keys map[string]ed25519.PublicKey, token string, tokenKey ed25519.PublicKey) (map[string]bool, map[string]string) {
	properties, detail := map[string]bool{}, map[string]string{}
	if !found {
		for _, p := range bootstrapAgentProperties[op] {
			detail[p] = "no request arrived for this operation"
		}
		return properties, detail
	}
	signed, c := a.Signed, a.Captured
	set := func(p string, ok bool, why string) {
		properties[p] = ok
		if !ok {
			detail[p] = why
		}
	}
	set("body-coverage", signed.coversBody(c), "content-type and content-digest must be covered and the digest must match the body")
	switch op {
	case "enroll":
		key := signed.hwkKey()
		set("hwk-proof", c.Method == http.MethodPost && a.Path == b.EnrollmentPath && signed.verifiedBy(f, key), "a POST to the enrollment path signed under hwk by the key it carries")
		keys["durable"] = key
	case "refresh":
		naming := readNamingJWT(f, signed.Params["jwt"])
		set("naming-jwt", signed.Scheme == "jkt-jwt" && naming.Valid, "jkt-jwt naming JWT: "+naming.Error)
		set("durable-anchor", naming.durable != nil && bytes.Equal(naming.durable, keys["durable"]), "the naming JWT's header key is not the enrolled durable key")
		set("ephemeral-proof", c.Method == http.MethodPost && a.Path == b.RefreshPath && signed.verifiedBy(f, naming.delegated), "the HTTP signature does not verify with the delegated cnf.jwk")
		jti, _ := naming.Claims["jti"].(string)
		set("naming-jti", jti != "", "the naming JWT carries no jti")
		fresh := naming.delegated != nil && !bytes.Equal(naming.delegated, keys["durable"])
		for name, key := range keys {
			if strings.HasPrefix(name, "ephemeral") && bytes.Equal(key, naming.delegated) {
				fresh = false
			}
		}
		set("fresh-ephemeral", fresh, "the delegated key repeats the durable key or an earlier ephemeral key")
		keys[fmt.Sprintf("ephemeral-%d", len(keys))] = naming.delegated
	case "subagent":
		set("parent-proof", c.Method == http.MethodPost && a.Path == b.SubagentPath && signed.Scheme == "jwt" && token != "" && signed.Params["jwt"] == token && signed.verifiedBy(f, tokenKey), "jwt scheme with the agent token issued at the last refresh, signed by its cnf key")
		var body map[string]any
		json.Unmarshal(c.Body, &body)
		set("subagent-key", bytes.Equal(confirmationPublicKey(body["jwk"]), seedPublic(b.Seeds["subagent"])), "the body jwk is not the sub-agent's public key")
		set("durable-absent", signed.Scheme == "jwt" && !signed.verifiedBy(f, keys["durable"]), "the durable key signed or keyed the request")
	case "call":
		set("refreshed-token", signed.Scheme == "jwt" && token != "" && signed.Params["jwt"] == token && signed.verifiedBy(f, tokenKey), "jwt scheme with the agent token issued at the last refresh, signed by its cnf key")
	}
	return properties, detail
}
