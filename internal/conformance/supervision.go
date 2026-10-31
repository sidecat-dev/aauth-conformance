package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Supervision roles (draft-hardt-aauth-supervision). In the first the native
// supervision server (SS) is under test and the harness is the Person Server;
// in the second the native Person Server is under test and the harness is
// its supervision server, its Agent and the Agent Provider.
const SupervisionServerRole = "supervision.server"
const SupervisionPersonServerRole = "supervision.person-server"

// SupervisionFixture is fixture.json extensions.supervision. Every seed is a
// public test vector. The harness Person Server of the SS role is
// fixture.person_server; OtherPS is a second, separately keyed Person Server
// the SS's host does not accept; Foreign is a second supervisor whose keys a
// Person Server admits but which it never called.
type SupervisionFixture struct {
	Issuer  string               `json:"issuer"`
	Seed    string               `json:"seed_hex"`
	Kid     string               `json:"kid"`
	Subject string               `json:"subject"`
	OtherPS SupervisionPeer      `json:"other_person_server"`
	Foreign SupervisionPeer      `json:"foreign_supervisor"`
	Mission SupervisionMissionFx `json:"mission"`
}
type SupervisionPeer struct {
	Issuer string `json:"issuer"`
	Seed   string `json:"seed_hex"`
	Kid    string `json:"kid"`
}

// SupervisionMissionFx is the fixed mission blob a harness Person Server
// reports as approved; its bytes are serialized once and hashed.
type SupervisionMissionFx struct {
	ApprovedAt  string `json:"approved_at"`
	Description string `json:"description"`
}

func init() {
	RegisterRole(SupervisionServerRole, ExtensionRole{
		Kinds:    []string{"ss-signed", "ss-same-response", "ss-pending", "ss-same-location", "ss-metadata-endpoints", "ss-retry-after", "ss-no-decision"},
		Validate: validateSupervisionServerScenario,
		Run:      runSupervisionServers,
	})
	RegisterRole(SupervisionPersonServerRole, ExtensionRole{
		Kinds:    []string{"ps-credential", "ps-credential-exp", "ss-request-proof", "ss-request-has", "ss-request-equals", "ss-request-token", "ss-sdi-distinct"},
		Validate: validateSupervisionPSScenario,
		Run:      runSupervisionPersonServers,
	})
}

func supervisionFixture(f Fixture) (SupervisionFixture, error) {
	var s SupervisionFixture
	if err := DecodeExtension(f, "supervision", &s); err != nil {
		return s, err
	}
	if f.Person == nil {
		return s, fmt.Errorf("supervision roles need fixture.person_server")
	}
	issuers := map[string]bool{f.Issuer: true, f.Origin: true, f.Person.Issuer: true}
	if f.Access != nil {
		issuers[f.Access.Issuer] = true
	}
	for _, peer := range []SupervisionPeer{{s.Issuer, s.Seed, s.Kid}, s.OtherPS, s.Foreign} {
		u, err := url.Parse(peer.Issuer)
		seed, seedErr := hex.DecodeString(peer.Seed)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || seedErr != nil || len(seed) != 32 || peer.Kid == "" || issuers[peer.Issuer] {
			return s, fmt.Errorf("supervision fixture identities must be distinct HTTPS server identifiers with 32-byte seeds and kids")
		}
		issuers[peer.Issuer] = true
	}
	if s.Subject == "" || s.Mission.ApprovedAt == "" || s.Mission.Description == "" {
		return s, fmt.Errorf("supervision fixture needs subject and mission")
	}
	return s, nil
}

// supervisionMission is the blob the harness Person Server reports, its
// base64url encoding and its s256, computed over the exact serialized bytes.
func supervisionMission(f Fixture, s SupervisionFixture) (blob []byte, encoded, s256 string) {
	blob, _ = json.Marshal(map[string]any{"agent": f.Subject, "approved_at": s.Mission.ApprovedAt, "description": s.Mission.Description})
	digest := sha256.Sum256(blob)
	return blob, base64.RawURLEncoding.EncodeToString(blob), base64.RawURLEncoding.EncodeToString(digest[:])
}

// supervisionTokens mints the forwarded credentials a supervision request
// carries. The SS treats them as opaque; they are well formed and signed by
// the fixture issuers so a library that inspects them sees real tokens.
func supervisionTokens(f Fixture, id string) map[string]string {
	p := *f.Person
	agent, _ := mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": id + "-agent", "iat": f.Now - 10, "exp": f.Now + 600, "ps": p.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}})
	person, _ := mintJWT(p.Seed, p.Kid, "aa-person+jwt", map[string]any{"iss": p.Issuer, "dwk": "aauth-person.json", "sub": p.Subject, "aud": f.Origin, "jti": id + "-person", "iat": f.Now - 5, "exp": f.Now + 60, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}})
	resource, _ := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", map[string]any{"iss": f.Origin, "dwk": "aauth-resource.json", "aud": p.Issuer, "ps": p.Issuer, "sub": p.Subject, "presented_jti": id + "-person", "agent_jkt": thumbprint(f.AgentSeed), "jti": id + "-resource", "iat": f.Now - 1, "exp": f.Now + 120, "scope": "read"})
	return map[string]string{"$agent_token": agent, "$presented_token": person, "$resource_token": resource}
}

// substitute replaces every JSON string that is exactly a known placeholder.
// "$now" becomes the fixture clock as a number; an unknown "$" name is an error.
func substitute(value any, values map[string]any) (any, error) {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "$") {
			replacement, ok := values[v]
			if !ok {
				return nil, fmt.Errorf("unknown placeholder %s", v)
			}
			return replacement, nil
		}
		return v, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			replaced, err := substitute(item, values)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for key, item := range v {
			replaced, err := substitute(item, values)
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil
	}
	return value, nil
}

// signServerRequest signs as a server under jwks_uri, naming dwk and kid.
// With omitBodyComponents the body's content-type and content-digest are
// still sent but left uncovered, a request the drafts require the SS to refuse.
func signServerRequest(f Fixture, seed, issuer, dwk, kid, method, target string, body []byte, acceptSignature string, omitBodyComponents bool) (*http.Request, string, error) {
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Signature-Key", fmt.Sprintf(`sig=jwks_uri;id=%q;dwk=%q;kid=%q`, issuer, dwk, kid))
	if acceptSignature != "" {
		request.Header.Set("Accept-Signature", acceptSignature)
	}
	covered := []string{"@method", "@authority", "@path", "signature-key"}
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		if !omitBodyComponents {
			covered = append(covered, "content-type", "content-digest")
		}
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

// ResponseSignature is the independent observation of a signed response.
type ResponseSignature struct {
	Label    string   `json:"label,omitempty"`
	ID       string   `json:"id,omitempty"`
	Dwk      string   `json:"dwk,omitempty"`
	Kid      string   `json:"kid,omitempty"`
	Covered  []string `json:"covered,omitempty"`
	Base     string   `json:"signature_base,omitempty"`
	Digest   bool     `json:"content_digest_matches"`
	Verified bool     `json:"verified"`
	Error    string   `json:"error,omitempty"`
}

// responseComponent is the value of one covered component of a response,
// taking `;req` components from the request it answers (RFC 9421 2.4).
func responseComponent(item httpsfv.Item, status int, response http.Header, request Captured) (string, bool) {
	name, ok := item.Value.(string)
	if !ok {
		return "", false
	}
	fromRequest := false
	if item.Params != nil {
		for _, param := range item.Params.Names() {
			value, _ := item.Params.Get(param)
			if param != "req" || value != true {
				return "", false
			}
			fromRequest = true
		}
	}
	if !fromRequest {
		switch {
		case name == "@status":
			return strconv.Itoa(status), true
		case strings.HasPrefix(name, "@"):
			return "", false
		default:
			if len(response.Values(name)) == 0 {
				return "", false
			}
			return canonicalField(response, name), true
		}
	}
	target, err := url.Parse(request.URL)
	if err != nil {
		return "", false
	}
	switch name {
	case "@method":
		return request.Method, true
	case "@authority":
		return strings.ToLower(target.Host), true
	case "@path":
		path := target.EscapedPath()
		if path == "" {
			path = "/"
		}
		return path, true
	case "@query":
		return "?" + target.RawQuery, true
	}
	if strings.HasPrefix(name, "@") || len(request.Headers.Values(name)) == 0 {
		return "", false
	}
	return canonicalField(request.Headers, name), true
}

// ObserveResponseSignature verifies a response signature under the jwks_uri
// key identified by its Signature-Key member, with the public key of seed.
func ObserveResponseSignature(r Response, request Captured, seed string) ResponseSignature {
	observed := ResponseSignature{}
	if digest, ok := contentDigestMatches(r.Header, r.Body); ok {
		observed.Digest = digest
	}
	keys, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature-Key"))
	if err != nil || len(keys.Names()) == 0 {
		observed.Error = "response carries no parseable Signature-Key"
		return observed
	}
	inputs, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature-Input"))
	if err != nil {
		observed.Error = "response Signature-Input does not parse"
		return observed
	}
	signatures, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature"))
	if err != nil {
		observed.Error = "response Signature does not parse"
		return observed
	}
	for _, label := range keys.Names() {
		member, _ := keys.Get(label)
		key, ok := member.(httpsfv.Item)
		if !ok || key.Value != httpsfv.Token("jwks_uri") || key.Params == nil {
			continue
		}
		id, _ := key.Params.Get("id")
		dwk, _ := key.Params.Get("dwk")
		kid, _ := key.Params.Get("kid")
		observed = ResponseSignature{Label: label, Digest: observed.Digest}
		observed.ID, _ = id.(string)
		observed.Dwk, _ = dwk.(string)
		observed.Kid, _ = kid.(string)
		member, _ = inputs.Get(label)
		input, ok := member.(httpsfv.InnerList)
		if !ok {
			observed.Error = "no Signature-Input for the Signature-Key label"
			continue
		}
		lines := []string{}
		valid := true
		for _, item := range input.Items {
			identifier, err := httpsfv.Marshal(item)
			value, present := responseComponent(item, r.Status, r.Header, request)
			if err != nil || !present {
				valid = false
				break
			}
			if item.Params == nil || len(item.Params.Names()) == 0 {
				observed.Covered = append(observed.Covered, item.Value.(string))
			} else {
				observed.Covered = append(observed.Covered, identifier)
			}
			lines = append(lines, identifier+": "+value)
		}
		params, err := httpsfv.Marshal(input)
		if err != nil || !valid {
			observed.Error = "a covered component is absent or unsupported"
			continue
		}
		lines = append(lines, `"@signature-params": `+params)
		observed.Base = strings.Join(lines, "\n")
		member, _ = signatures.Get(label)
		signature, ok := member.(httpsfv.Item)
		raw, isBytes := signature.Value.([]byte)
		if !ok || !isBytes {
			observed.Error = "no Signature for the label"
			continue
		}
		observed.Verified = ed25519.Verify(seedKey(seed).Public().(ed25519.PublicKey), []byte(observed.Base), raw)
		if observed.Verified {
			return observed
		}
		observed.Error = "response signature does not verify under the fixture key"
	}
	if observed.Error == "" {
		observed.Error = "no jwks_uri Signature-Key member"
	}
	return observed
}

func contentDigestMatches(header http.Header, body []byte) (bool, bool) {
	values := header.Values("Content-Digest")
	if len(values) == 0 {
		return false, false
	}
	digests, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return false, true
	}
	member, ok := digests.Get("sha-256")
	item, isItem := member.(httpsfv.Item)
	raw, isBytes := item.Value.([]byte)
	expected := sha256.Sum256(body)
	return ok && isItem && isBytes && bytes.Equal(raw, expected[:]), true
}

// signedDecision reports whether a response is a decision signed by the
// supervisor fixture: jwks_uri naming its issuer and aauth-supervisor.json,
// a verifying signature over at least @status, content-type and
// content-digest, and a Content-Digest of the actual body.
func signedDecision(s SupervisionFixture, r Response, request Captured) (bool, ResponseSignature) {
	observed := ObserveResponseSignature(r, request, s.Seed)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	ok := observed.Verified && observed.Digest && observed.ID == s.Issuer && observed.Dwk == "aauth-supervisor.json" && observed.Kid == s.Kid && media == "application/json"
	for _, required := range []string{"@status", "content-type", "content-digest"} {
		ok = ok && slices.Contains(observed.Covered, required)
	}
	if !ok && observed.Error == "" {
		observed.Error = "signature, issuer, coverage or digest does not meet the signed-decision profile"
	}
	return ok, observed
}

func jsonObject(body []byte) (map[string]any, bool) {
	var object map[string]any
	if json.Unmarshal(body, &object) != nil {
		return nil, false
	}
	return object, true
}

// validRetryAfter is a nonnegative integer number of seconds.
func validRetryAfter(r Response) bool {
	values := r.Header.Values("Retry-After")
	if len(values) != 1 {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(values[0]), 10, 32)
	return err == nil && n < 1<<31
}

// pendingLocation resolves a Location against the logical origin it came from.
func pendingLocation(r Response, origin string) (string, bool) {
	location := r.Header.Get("Location")
	if location == "" {
		return "", false
	}
	base, err := url.Parse(origin)
	if err != nil {
		return "", false
	}
	resolved, err := base.Parse(location)
	if err != nil || resolved.Scheme != "https" || resolved.Host != base.Host {
		return "", false
	}
	return resolved.String(), true
}

func boolEquals(a Assertion) error {
	var b any
	json.Unmarshal(a.Equals, &b)
	if _, ok := b.(bool); !ok {
		return fmt.Errorf("%s requires a boolean", a.Kind)
	}
	return nil
}
