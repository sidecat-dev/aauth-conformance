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
)

// PersonFixture is public, deterministic test configuration. Private seeds must
// never be used outside this isolated conformance fixture.
type PersonFixture struct {
	Issuer          string   `json:"issuer"`
	Seed            string   `json:"seed_hex"`
	Kid             string   `json:"kid"`
	Subject         string   `json:"subject"`
	Lifetime        int64    `json:"person_lifetime"`
	AuthLifetime    int64    `json:"auth_lifetime"`
	PermittedScopes []string `json:"permitted_scopes"`
	ResourceSeed    string   `json:"resource_seed_hex"`
	ResourceKid     string   `json:"resource_kid"`
}
type PersonSpec struct {
	Mutation string `json:"mutation"`
}

func validatePersonFixture(p PersonFixture) error {
	u, e := url.Parse(p.Issuer)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || p.Kid == "" || p.ResourceKid == "" || p.Subject == "" || p.Lifetime <= 0 || p.Lifetime > 3600 || p.AuthLifetime <= 0 || p.AuthLifetime > 3600 || !reflect.DeepEqual(p.PermittedScopes, []string{"read"}) {
		return fmt.Errorf("invalid Person Server fixture")
	}
	for _, s := range []string{p.Seed, p.ResourceSeed} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 {
			return fmt.Errorf("invalid Person Server fixture seed")
		}
	}
	return nil
}
func mintJWT(seed, kid, typ string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "Ed25519", "typ": typ, "kid": kid})
	body, e := json.Marshal(claims)
	if e != nil {
		return "", e
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(seedKey(seed), []byte(signed))), nil
}
func verifyJWT(compact, seed, kid, typ string) (map[string]any, map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("JWT needs three parts")
	}
	decoded := make([][]byte, 3)
	for i, p := range parts {
		b, e := base64.RawURLEncoding.Strict().DecodeString(p)
		if e != nil {
			return nil, nil, e
		}
		decoded[i] = b
	}
	var head, claims map[string]any
	if e := json.Unmarshal(decoded[0], &head); e != nil {
		return nil, nil, e
	}
	if e := json.Unmarshal(decoded[1], &claims); e != nil {
		return nil, nil, e
	}
	if head["alg"] != "Ed25519" || head["typ"] != typ || head["kid"] != kid || !ed25519.Verify(seedKey(seed).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), decoded[2]) {
		return head, claims, fmt.Errorf("JWT signature/alg/type/kid did not verify")
	}
	return head, claims, nil
}
func thumbprint(seed string) string {
	jwk := publicJWK(seed)
	// RFC 7638 canonical required public members, deliberately excluding alg.
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + jwk["x"].(string) + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
func buildPersonExchange(f Fixture, p PersonFixture, s Scenario, stage, person string, claims map[string]any) (*http.Request, []byte, error) {
	exp := s.Token.EXPOffset
	if s.Person.Mutation == "short-parent" {
		exp = 45
	}
	agent, _ := mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": s.ID + "-agent", "iat": f.Now + s.Token.IATOffset, "exp": f.Now + exp, "ps": p.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}})
	path := "/person"
	body := map[string]any{"resource": f.Origin}
	if stage == "token" {
		path = "/token"
		resource := map[string]any{"iss": f.Origin, "dwk": "aauth-resource.json", "aud": p.Issuer, "ps": p.Issuer, "sub": claims["sub"], "presented_jti": claims["jti"], "agent_jkt": thumbprint(f.AgentSeed), "jti": s.ID + "-resource", "iat": f.Now - 1, "exp": f.Now + 120, "scope": "read"}
		switch s.Person.Mutation {
		case "wrong-aud":
			resource["aud"] = "https://foreign.conformance.test"
		case "wrong-jkt":
			resource["agent_jkt"] = thumbprint(strings.Repeat("08", 32))
		case "wrong-sub":
			resource["sub"] = "foreign-person"
		case "wrong-jti":
			resource["presented_jti"] = "foreign-jti"
		case "wrong-ps":
			resource["ps"] = "https://foreign.conformance.test"
		case "expired-resource":
			resource["iat"] = f.Now - 120
			resource["exp"] = f.Now - 1
		case "expired-presented":
			expired := map[string]any{}
			for k, v := range claims {
				expired[k] = v
			}
			expired["iat"] = f.Now - 120
			expired["exp"] = f.Now - 1
			person, _ = mintJWT(p.Seed, p.Kid, "aa-person+jwt", expired)
		case "denied-scope":
			resource["scope"] = "admin"
		}
		token, _ := mintJWT(p.ResourceSeed, p.ResourceKid, "aa-resource+jwt", resource)
		body = map[string]any{"resource_token": token, "presented_token": person}
	}
	encoded, _ := json.Marshal(body)
	req, e := http.NewRequest("POST", p.Issuer+path, bytes.NewReader(encoded))
	if e != nil {
		return nil, nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	digest := sha256.Sum256(encoded)
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	req.Header.Set("Signature-Key", `sig=jwt;jwt="`+agent+`"`)
	covered := []string{"@method", "@authority", "@path", "signature-key", "content-type", "content-digest"}
	var names, lines []string
	for _, c := range covered {
		value := canonicalField(req.Header, c)
		switch c {
		case "@method":
			value = req.Method
		case "@authority":
			value = req.URL.Host
		case "@path":
			value = req.URL.EscapedPath()
		}
		names = append(names, fmt.Sprintf("%q", c))
		lines = append(lines, fmt.Sprintf("%q: %s", c, value))
	}
	params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), f.Now)
	lines = append(lines, `"@signature-params": `+params)
	base := []byte(strings.Join(lines, "\n"))
	signature := ed25519.Sign(seedKey(f.AgentSeed), base)
	if stage == "person" && s.Person.Mutation == "tampered-proof" {
		signature[0] ^= 1
	}
	req.Header.Set("Signature-Input", "sig="+params)
	req.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	if stage == "person" && s.Person.Mutation == "tampered-body" {
		// Equal-length, valid JSON mutation preserves framing and signature headers.
		encoded = bytes.ReplaceAll(encoded, []byte("resource.conformance.test"), []byte("resource.conformance.tesX"))
		req.Body = io.NopCloser(bytes.NewReader(encoded))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(encoded)), nil }
	}
	return req, base, nil
}

type PersonObservation struct {
	Subject         bool           `json:"configured_subject"`
	Valid           bool           `json:"valid"`
	Signature       bool           `json:"signature"`
	Identity        bool           `json:"identity"`
	Key             bool           `json:"key"`
	Lifetime        bool           `json:"lifetime"`
	Scope           bool           `json:"scope"`
	NoAuthorization bool           `json:"no_authorization"`
	Claims          map[string]any `json:"claims,omitempty"`
	Error           string         `json:"error,omitempty"`
}

func observePersonJWT(f Fixture, p PersonFixture, compact, kind string, parent map[string]any, agentExp int64) PersonObservation {
	typ := "aa-person+jwt"
	if kind == "auth" {
		typ = "aa-auth+jwt"
	}
	_, c, e := verifyJWT(compact, p.Seed, p.Kid, typ)
	o := PersonObservation{Claims: c}
	if e != nil {
		o.Error = e.Error()
		return o
	}
	o.Signature = true
	jti, ok := c["jti"].(string)
	o.Identity = c["iss"] == p.Issuer && c["dwk"] == "aauth-person.json" && c["aud"] == f.Origin && ok && jti != ""
	sub, subOK := c["sub"].(string)
	o.Identity = o.Identity && subOK && sub != ""
	o.Subject = c["sub"] == p.Subject
	if kind == "auth" {
		o.Identity = o.Identity && parent != nil && c["sub"] == parent["sub"] && c["ps"] == p.Issuer
	}
	cnf, ok := c["cnf"].(map[string]any)
	if ok {
		o.Key = bytes.Equal(confirmationPublicKey(cnf["jwk"]), seedKey(f.AgentSeed).Public().(ed25519.PublicKey))
	}
	iat, iatOK := c["iat"].(float64)
	exp, expOK := c["exp"].(float64)
	ceiling := min(f.Now+3600, agentExp)
	if kind == "auth" {
		if pe, ok := parent["exp"].(float64); ok {
			ceiling = min(ceiling, int64(pe))
		} else {
			return o
		}
	}
	o.Lifetime = iatOK && expOK && iat == float64(f.Now) && exp == float64(int64(exp)) && exp > float64(f.Now) && exp <= float64(ceiling)
	_, hasScope := c["scope"]
	_, hasAccount := c["account"]
	o.NoAuthorization = !hasScope && !hasAccount
	o.Scope = true
	if kind == "auth" {
		scope, ok := c["scope"].(string)
		o.Scope = ok && scope == "read"
		for _, s := range strings.Fields(scope) {
			o.Scope = o.Scope && slices.Contains(p.PermittedScopes, s)
		}
		o.Scope = o.Scope && !hasAccount
	}
	// No mission, tenant or delegation is configured in this profile.
	for _, name := range []string{"mission_s256", "tenant", "agent", "parent_agent"} {
		if _, ok := c[name]; ok {
			o.Identity = false
		}
	}
	o.Valid = o.Signature && o.Identity && o.Subject && o.Key && o.Lifetime && o.Scope && (kind == "auth" || o.NoAuthorization)
	if !o.Valid {
		o.Error = "JWT violates this suite's identity/key/authorization/lifetime profile"
	}
	return o
}

// Confirmation equality is key material, not optional public JWK metadata.
func confirmationPublicKey(value any) ed25519.PublicKey {
	key, ok := value.(map[string]any)
	if !ok || key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["alg"] != "Ed25519" {
		return nil
	}
	if _, private := key["d"]; private {
		return nil
	}
	encoded, ok := key["x"].(string)
	if !ok {
		return nil
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(material) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(material) != encoded {
		return nil
	}
	return ed25519.PublicKey(material)
}

func checkPerson(a Assertion, r Response, o PersonObservation) Result {
	if a.Kind == "ps-no-token" {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
		var body map[string]any
		if json.Unmarshal(r.Body, &body) != nil || body == nil {
			result.Detail = "no JSON object to inspect for issued credentials"
			return result
		}
		_, person := body["person_token"]
		_, auth := body["auth_token"]
		actual := !person && !auth
		result.Actual = actual
		var want bool
		json.Unmarshal(a.Equals, &want)
		if actual == want {
			result.State = "pass"
		}
		return result
	}
	if !strings.HasPrefix(a.Kind, "ps-jwt") {
		return Check(a, r)
	}
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail", Detail: o.Error}
	var want bool
	json.Unmarshal(a.Equals, &want)
	actual := o.Valid
	switch a.Kind {
	case "ps-jwt-subject":
		actual = o.Subject
	case "ps-jwt-signature":
		actual = o.Signature
	case "ps-jwt-identity":
		actual = o.Identity
	case "ps-jwt-key":
		actual = o.Key
	case "ps-jwt-lifetime":
		actual = o.Lifetime
	case "ps-jwt-scope":
		actual = o.Scope
	case "ps-jwt-no-authorization":
		actual = o.NoAuthorization
	}
	result.Actual = actual
	if actual == want {
		result.State = "pass"
		result.Detail = ""
	}
	return result
}
