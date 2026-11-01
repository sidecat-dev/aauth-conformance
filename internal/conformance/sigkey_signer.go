package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// sigkeySignJob is the signer launcher's control input. The key is a public
// fixture test key; the credential members are what the signer presents.
type sigkeySignJob struct {
	Scheme      string `json:"scheme"`
	Alg         string `json:"alg"`
	Kid         string `json:"kid"`
	Seed        string `json:"seed_hex,omitempty"`
	PKCS8       string `json:"pkcs8_hex,omitempty"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	JWT         string `json:"jwt,omitempty"`
	ID          string `json:"id,omitempty"`
	DWK         string `json:"dwk,omitempty"`
	JWKSURL     string `json:"jwks_url,omitempty"`
	Transport   string `json:"transport"`
}

// sigkeySignerObservation is the independent verdict on one received request.
type sigkeySignerObservation struct {
	Label   string   `json:"label,omitempty"`
	Covered []string `json:"covered,omitempty"`
	Created int64    `json:"created"`
	Signed  bool     `json:"signed"`
	Member  bool     `json:"member"`
	Base    string   `json:"signature_base,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// sigkeySignerJob builds the control input and the key the received request
// must verify under.
func sigkeySignerJob(f Fixture, k SigkeyFixture, s Scenario) (sigkeySignJob, sigkeyKey, error) {
	var in sigkeySignerInput
	if err := DecodeInput(s, &in); err != nil {
		return sigkeySignJob{}, sigkeyKey{}, err
	}
	job := sigkeySignJob{Scheme: in.Scheme, Alg: in.Alg, Method: in.Method, URL: k.Receiver}
	if in.Body {
		job.Body, job.ContentType = string(sigkeyBody), "application/json"
	}
	seed := f.AgentSeed
	if slices.Contains([]string{"jwks_uri", "jwks", "self-jwt"}, in.Scheme) {
		seed, job.Kid = k.Signer.Seed, k.Signer.Kid
	}
	key, err := sigkeyAlgKey(k, in.Alg, seed)
	if err != nil {
		return job, key, err
	}
	if in.Alg == "Ed25519" {
		job.Seed = seed
		if job.Kid == "" {
			job.Kid = "ed25519-1"
		}
	} else {
		der, _ := base64.StdEncoding.DecodeString(k.Keys[in.Alg].PKCS8)
		job.PKCS8, job.Kid = hex.EncodeToString(der), k.Keys[in.Alg].Kid
	}
	switch in.Scheme {
	case "jwt":
		job.JWT, err = sigkeyJWS(map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": f.Kid},
			map[string]any{"iss": f.Issuer, "sub": f.Subject, "dwk": "aauth-agent.json", "jti": s.ID, "iat": f.Now - 10, "exp": f.Now + 300, "cnf": map[string]any{"jwk": key.public}},
			sigkeyEd25519(f.APSeed))
	case "jwks_uri":
		job.ID, job.DWK = k.Signer.Issuer, k.Signer.DWK
	case "jwks":
		job.JWKSURL = k.JWKSURL
	case "self-jwt":
		receiver, _ := url.Parse(k.Receiver)
		job.JWT, err = sigkeyJWS(map[string]any{"alg": "Ed25519", "kid": k.Signer.Kid, "typ": k.SelfJWTTyp},
			map[string]any{"iss": k.Signer.Issuer, "dwk": k.Signer.DWK, "aud": "https://" + receiver.Host, "jti": s.ID, "iat": f.Now - 10, "exp": f.Now + 300},
			key)
	case "jkt-jwt":
		job.JWT, err = sigkeyJKT(f, k, key, s.ID)
	}
	return job, key, err
}

// sigkeyObserveSigned verifies a received request independently: the
// selected member must carry exactly the expected credential, the signature
// must verify under the expected key over the received components, the
// coverage must include the base components and signature-key, and a covered
// Content-Digest must match the received body.
func sigkeyObserveSigned(job sigkeySignJob, key sigkeyKey, c Captured) sigkeySignerObservation {
	o := sigkeySignerObservation{}
	keys, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Key"))
	if err != nil {
		o.Error = "Signature-Key: " + err.Error()
		return o
	}
	inputs, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Input"))
	if err != nil {
		o.Error = "Signature-Input: " + err.Error()
		return o
	}
	signatures, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature"))
	if err != nil {
		o.Error = "Signature: " + err.Error()
		return o
	}
	names := inputs.Names()
	if len(names) != 1 {
		o.Error = "expected exactly one signature label"
		return o
	}
	o.Label = names[0]
	keyMember, ok := keys.Get(o.Label)
	item, isItem := keyMember.(httpsfv.Item)
	if !ok || !isItem {
		o.Error = "no Signature-Key Item for the signature label"
		return o
	}
	o.Member = sigkeyMemberMatches(job, key, item)
	inputMember, _ := inputs.Get(o.Label)
	input, ok := inputMember.(httpsfv.InnerList)
	if !ok || input.Params == nil {
		o.Error = "no Signature-Input Inner List for the label"
		return o
	}
	if created, ok := input.Params.Get("created"); ok {
		o.Created, _ = created.(int64)
	}
	target, err := url.Parse(c.URL)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	var lines []string
	valid := true
	for _, entry := range input.Items {
		component, ok := entry.Value.(string)
		if !ok || slices.Contains(o.Covered, component) || entry.Params != nil && len(entry.Params.Names()) > 0 {
			valid = false
			break
		}
		o.Covered = append(o.Covered, component)
		var value string
		switch component {
		case "@method":
			value = c.Method
		case "@authority":
			value = strings.ToLower(target.Host)
		case "@path":
			value = target.EscapedPath()
		case "@query":
			value = "?" + target.RawQuery
		default:
			if strings.HasPrefix(component, "@") || len(c.Headers.Values(component)) == 0 {
				valid = false
			}
			value = canonicalField(c.Headers, component)
		}
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	params, err := httpsfv.Marshal(input)
	if err != nil {
		valid = false
	}
	o.Base = strings.Join(append(lines, `"@signature-params": `+params), "\n")
	for _, component := range []string{"@method", "@authority", "@path", "signature-key"} {
		valid = valid && slices.Contains(o.Covered, component)
	}
	if slices.Contains(o.Covered, "content-digest") {
		sum := sha256.Sum256(c.Body)
		valid = valid && contentDigestMatches(c.Headers.Values("Content-Digest"), sum[:])
	}
	signatureMember, _ := signatures.Get(o.Label)
	signature, ok := signatureMember.(httpsfv.Item)
	raw, isBytes := signature.Value.([]byte)
	o.Signed = valid && ok && isBytes && key.verify([]byte(o.Base), raw)
	if !o.Signed {
		o.Error = "the received signature does not verify under the expected key with the required coverage"
	}
	return o
}

func sigkeyMemberMatches(job sigkeySignJob, key sigkeyKey, item httpsfv.Item) bool {
	if item.Value != httpsfv.Token(job.Scheme) || item.Params == nil {
		return false
	}
	got := map[string]string{}
	for _, name := range item.Params.Names() {
		value, _ := item.Params.Get(name)
		text, ok := value.(string)
		if !ok {
			return false
		}
		got[name] = text
	}
	want := map[string]string{}
	switch job.Scheme {
	case "hwk":
		for name, value := range key.public {
			want[name] = value.(string)
		}
	case "jwt", "self-jwt", "jkt-jwt":
		want["jwt"] = job.JWT
	case "jwks_uri":
		want["id"], want["dwk"], want["kid"] = job.ID, job.DWK, job.Kid
	case "jwks":
		want["url"], want["kid"] = job.JWKSURL, job.Kid
	}
	return jsonEqual(got, want)
}

func runSigkeySigner(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	k, fixtureErr := sigkeyFixture(s.Fixture)
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		var ready Ready
		var stopAdapter func()
		startError := fixtureErr
		transport, received, stopCapture, captureErr := sigkeyCapture()
		if startError == nil && captureErr != nil {
			startError = captureErr
		}
		if startError == nil && target.Unavailable == "" {
			receiver, _ := url.Parse(k.Receiver)
			config := Bootstrap{Version: 1, Role: SigkeySignerRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: "https://" + receiver.Host + "/control", APTransport: ap, AgentSeed: s.Fixture.AgentSeed, Subject: s.Fixture.Subject}
			config.Extension, _ = json.Marshal(sigkeyLaunch{AgentProvider: s.Fixture.Issuer, Signer: k.Signer.Issuer, SignerDWK: k.Signer.DWK, JWKSURL: k.JWKSURL, SelfJWTTyp: k.SelfJWTTyp})
			ready, stopAdapter, startError = startAdapter(ctx, target, config, o)
			if startError != nil {
				run.Error = startError.Error()
			}
		}
		for _, scenario := range s.Scenarios {
			c := Case{ID: scenario.ID}
			execution := ""
			var observed sigkeySignerObservation
			offered := sigkeyOffered(scenario, target)
			if offered {
				if startError != nil {
					execution = startError.Error()
				} else {
					observed, execution = sigkeySignerCase(ctx, s.Fixture, k, scenario, ready, transport, received, o, &c)
				}
			}
			c.Error = execution
			c.Evidence = observed
			for _, a := range scenario.Assertions {
				if !offered {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: sigkeyNotOffered(target)})
					continue
				}
				c.Results = append(c.Results, Grade(a, target.Claims, execution, nil, func(a Assertion) Result {
					switch a.Kind {
					case "sigkey-signed":
						return CompareResult(a, observed.Signed, observed.Error)
					case "sigkey-member":
						return CompareResult(a, observed.Member, "")
					case "sigkey-created":
						return CompareResult(a, observed.Created, "")
					}
					return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "unknown signer assertion"}
				}))
			}
			run.Cases = append(run.Cases, c)
		}
		if stopAdapter != nil {
			stopAdapter()
		}
		if stopCapture != nil {
			stopCapture()
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func sigkeySignerCase(ctx context.Context, f Fixture, k SigkeyFixture, s Scenario, ready Ready, transport string, received <-chan Captured, o Options, c *Case) (sigkeySignerObservation, string) {
	job, key, err := sigkeySignerJob(f, k, s)
	if err != nil {
		return sigkeySignerObservation{}, err.Error()
	}
	job.Transport = transport
	encoded, _ := json.Marshal(job)
	request, _ := http.NewRequest("POST", ready.URL, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response, err := Exchange(ctx, request, ready.URL, o.Timeout)
	if err != nil {
		return sigkeySignerObservation{}, err.Error()
	}
	c.ControlResponse = &response
	if response.Status != 200 {
		return sigkeySignerObservation{}, fmt.Sprintf("signer control returned HTTP %d: %s", response.Status, response.Body)
	}
	var capture Captured
	select {
	case capture = <-received:
	case <-time.After(o.Timeout):
		return sigkeySignerObservation{}, "signer produced no outbound request"
	case <-ctx.Done():
		return sigkeySignerObservation{}, ctx.Err().Error()
	}
	select {
	case <-received:
		return sigkeySignerObservation{}, "signer sent more than one request for one command"
	default:
	}
	c.Method, c.URL, c.Headers, c.RequestBody = capture.Method, capture.URL, capture.Headers, capture.Body
	observed := sigkeyObserveSigned(job, key, capture)
	c.SignatureBase = observed.Base
	if capture.Method != job.Method || capture.URL != job.URL || !bytes.Equal(capture.Body, []byte(job.Body)) {
		observed.Signed = false
		observed.Error = "the received method, URL or body differs from the command"
	}
	return observed, ""
}

// sigkeyCapture receives the signer's requests and answers 200; grading is
// independent of that answer.
func sigkeyCapture() (string, <-chan Captured, func(), error) {
	received := make(chan Captured, 8)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(body) > 65536 {
			http.Error(w, "body read", 400)
			return
		}
		select {
		case received <- Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body}:
		default:
			http.Error(w, "capture overflow", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"received":true}`)
	})}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	return "http://" + listener.Addr().String(), received, func() { server.Close(); <-done }, nil
}
