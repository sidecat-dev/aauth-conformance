package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/dunglas/httpsfv"
)

type AgentJob struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Token     string            `json:"token"`
	Transport string            `json:"transport"`
}
type Captured struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}
type Observation struct {
	Token                  string
	ValidToken, ValidProof bool
	Created                int64
	Covered                []string
	Base, Error            string
}

// ObserveAgent verifies received bytes without calling either implementation.
// It is a deliberately limited oracle for this suite's Ed25519/bodyless profile.
func ObserveAgent(f Fixture, c Captured) Observation {
	failed := Observation{}
	keys, e := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Key"))
	if e != nil {
		failed.Error = e.Error()
		return failed
	}
	inputs, e := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Input"))
	if e != nil {
		failed.Error = e.Error()
		return failed
	}
	signatures, e := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature"))
	if e != nil {
		failed.Error = e.Error()
		return failed
	}
	target, e := url.Parse(c.URL)
	if e != nil {
		failed.Error = e.Error()
		return failed
	}
	for _, label := range keys.Names() {
		member, _ := keys.Get(label)
		key, ok := member.(httpsfv.Item)
		if !ok || key.Value != httpsfv.Token("jwt") || key.Params == nil {
			continue
		}
		value, _ := key.Params.Get("jwt")
		token, ok := value.(string)
		if !ok {
			continue
		}
		observed := Observation{Token: token, ValidToken: validFixtureToken(f, token)}
		member, _ = inputs.Get(label)
		input, ok := member.(httpsfv.InnerList)
		if !ok || input.Params == nil {
			observed.Error = "missing matching Signature-Input"
			failed = observed
			continue
		}
		created, ok := input.Params.Get("created")
		if ok {
			observed.Created, _ = created.(int64)
		}
		lines := []string{}
		seen := map[string]bool{}
		valid := true
		for _, item := range input.Items {
			component, ok := item.Value.(string)
			if !ok || seen[component] || item.Params != nil && len(item.Params.Names()) > 0 {
				valid = false
				break
			}
			seen[component] = true
			observed.Covered = append(observed.Covered, component)
			var value string
			switch component {
			case "@method":
				value = c.Method
			case "@authority":
				value = strings.ToLower(target.Host)
			case "@path":
				value = target.EscapedPath()
				if value == "" {
					value = "/"
				}
			case "@query":
				value = "?" + target.RawQuery
			case "signature-key", "authorization":
				value = canonicalField(c.Headers, component)
			default:
				valid = false
			}
			lines = append(lines, fmt.Sprintf("%q: %s", component, value))
		}
		params, err := httpsfv.Marshal(input)
		if err != nil {
			valid = false
		}
		lines = append(lines, `"@signature-params": `+params)
		observed.Base = strings.Join(lines, "\n")
		member, _ = signatures.Get(label)
		signature, ok := member.(httpsfv.Item)
		if ok {
			raw, ok := signature.Value.([]byte)
			if ok && valid && observed.ValidToken {
				observed.ValidProof = ed25519.Verify(seedKey(f.AgentSeed).Public().(ed25519.PublicKey), []byte(observed.Base), raw)
			}
		}
		if observed.ValidProof {
			return observed
		}
		observed.Error = "HTTP proof or AP-issued confirmation-key binding did not verify"
		failed = observed
	}
	if failed.Error == "" {
		failed.Error = "no matching jwt proof labels"
	}
	return failed
}
func canonicalField(header http.Header, name string) string {
	values := []string{}
	for _, value := range header.Values(name) {
		values = append(values, strings.Trim(value, " \t"))
	}
	return strings.Join(values, ", ")
}
func validFixtureToken(f Fixture, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	head, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return false
	}
	body, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return false
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if e != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		DWK string `json:"dwk"`
		Exp int64  `json:"exp"`
		CNF struct {
			JWK struct{ Kty, Crv, Alg, X string } `json:"jwk"`
		} `json:"cnf"`
	}
	if json.Unmarshal(head, &header) != nil || json.Unmarshal(body, &claims) != nil {
		return false
	}
	key := claims.CNF.JWK
	return header.Alg == "Ed25519" && header.Typ == "aa-agent+jwt" && header.Kid == f.Kid && claims.Iss == f.Issuer && claims.Sub == f.Subject && claims.DWK == "aauth-agent.json" && claims.Exp > f.Now && key.Kty == "OKP" && key.Crv == "Ed25519" && key.Alg == "Ed25519" && key.X == publicJWK(f.AgentSeed)["x"] && ed25519.Verify(seedKey(f.APSeed).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature)
}
func CheckAgent(a Assertion, o Observation, c Captured, job AgentJob) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	var expected, actual any
	json.Unmarshal(a.Equals, &expected)
	switch a.Kind {
	case "wire-preserved":
		preserved := c.Method == job.Method && c.URL == job.URL && len(c.Body) == 0 && o.Token == job.Token
		expectedAuthorization := ""
		for key, value := range job.Headers {
			preserved = preserved && canonicalField(c.Headers, key) == strings.Trim(value, " \t")
			if strings.EqualFold(key, "Authorization") {
				expectedAuthorization = strings.Trim(value, " \t")
			}
		}
		preserved = preserved && canonicalField(c.Headers, "Authorization") == expectedAuthorization
		actual = preserved
	case "wire-proof":
		actual = o.ValidProof
	case "wire-token":
		actual = o.ValidToken
	case "wire-created":
		actual = float64(o.Created)
	case "wire-covers":
		values, ok := expected.([]any)
		if !ok {
			result.Detail = "expected component list"
			return result
		}
		covered := true
		for _, value := range values {
			text, ok := value.(string)
			covered = covered && ok && slices.Contains(o.Covered, text)
		}
		result.Actual = o.Covered
		if covered {
			result.State = "pass"
		}
		return result
	default:
		result.Detail = "unknown Agent assertion"
		return result
	}
	result.Actual = actual
	if reflect.DeepEqual(actual, expected) {
		result.State = "pass"
	} else {
		result.Detail = o.Error
	}
	return result
}
