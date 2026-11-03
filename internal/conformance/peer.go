package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func seedKey(seed string) ed25519.PrivateKey {
	// Suite validation checks length and encoding before constructing peers.
	b, _ := hex.DecodeString(seed)
	return ed25519.NewKeyFromSeed(b)
}
func publicJWK(seed string) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(seedKey(seed).Public().(ed25519.PublicKey))}
}
func MintToken(f Fixture, spec TokenSpec, id string) (string, error) {
	if f.Enrolled != nil {
		if spec.IATOffset > 0 || spec.EXPOffset <= 0 {
			return "", fmt.Errorf("enrolled agent token cannot represent %s", id)
		}
		return f.Enrolled.Token, nil
	}
	head, _ := json.Marshal(map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": f.Kid})
	claims := map[string]any{"iss": f.Issuer, "sub": f.Subject, "dwk": "aauth-agent.json", "jti": id, "iat": f.Now + spec.IATOffset, "exp": f.Now + spec.EXPOffset, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}}
	if spec.PS {
		if f.Person == nil {
			return "", fmt.Errorf("the fixture names no Person Server")
		}
		claims["ps"] = f.Person.Issuer
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(seedKey(f.APSeed), []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// MintPersonToken is the fixture Person Server's Person token for the
// fixture Resource, confirming the Agent key, with the spec's lifetime.
func MintPersonToken(f Fixture, spec TokenSpec, id string) (string, error) {
	if f.Person == nil {
		return "", fmt.Errorf("the fixture names no Person Server")
	}
	return mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{
		"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin, "sub": f.Person.Subject,
		"jti": id, "iat": f.Now + spec.IATOffset, "exp": f.Now + spec.EXPOffset, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
	})
}

func BuildRequest(f Fixture, s Scenario) (*http.Request, []byte, error) {
	// Validation holds the request path to the fixture's; remote mode
	// rebases the fixture path onto the deployed Resource.
	path := f.Path
	if s.Request.Endpoint == personEndpoint {
		path = f.PersonPath
	}
	request, err := http.NewRequest(s.Request.Method, f.Origin+path, nil)
	if err != nil {
		return nil, nil, err
	}
	var token string
	switch s.Request.Proof {
	case "unsigned":
		return request, nil, nil
	case "jwt":
		token, err = MintToken(f, s.Token, s.ID)
	case "person":
		token, err = MintPersonToken(f, s.Token, s.ID)
	default:
		return nil, nil, fmt.Errorf("unknown proof %q", s.Request.Proof)
	}
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Signature-Key", `sig=jwt;jwt="`+token+`"`)
	var names, lines []string
	for _, component := range s.Request.Covered {
		var value string
		switch component {
		case "@method":
			value = request.Method
		case "@authority":
			value = request.URL.Host
		case "@path":
			value = request.URL.EscapedPath()
		case "signature-key":
			value = request.Header.Get("Signature-Key")
		default:
			return nil, nil, fmt.Errorf("unsupported component %q", component)
		}
		names = append(names, `"`+component+`"`)
		lines = append(lines, `"`+component+`": `+value)
	}
	params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), f.Now+s.Request.CreatedOffset)
	lines = append(lines, `"@signature-params": `+params)
	base := []byte(strings.Join(lines, "\n"))
	signature := ed25519.Sign(seedKey(f.AgentSeed), base)
	if s.Request.Tamper {
		signature[0] ^= 1
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return request, base, nil
}
