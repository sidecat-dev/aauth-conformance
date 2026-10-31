package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"mime"
	"net/url"
	"strings"

	"github.com/dunglas/httpsfv"
)

type AccessFixture struct {
	Issuer string `json:"issuer"`
	Seed   string `json:"seed_hex"`
	Kid    string `json:"kid"`
}

func observeFederatedAuth(f Fixture, compact string, parent map[string]any, agentExp int64) PersonObservation {
	_, c, err := verifyJWT(compact, f.Access.Seed, f.Access.Kid, "aa-auth+jwt")
	o := PersonObservation{Claims: c}
	if err != nil {
		o.Error = err.Error()
		return o
	}
	o.Signature = true
	jti, _ := c["jti"].(string)
	o.Identity = c["iss"] == f.Access.Issuer && c["dwk"] == "aauth-access.json" &&
		audienceNames(c["aud"], f.Origin) && c["ps"] == f.Person.Issuer && jti != ""
	o.Subject = c["sub"] == parent["sub"] && c["sub"] == f.Person.Subject
	if cnf, ok := c["cnf"].(map[string]any); ok {
		o.Key = bytes.Equal(confirmationPublicKey(cnf["jwk"]), seedKey(f.AgentSeed).Public().(ed25519.PublicKey))
	}
	iat, iatOK := c["iat"].(float64)
	exp, expOK := c["exp"].(float64)
	parentExp, parentOK := parent["exp"].(float64)
	o.Lifetime = iatOK && expOK && parentOK && iat == float64(f.Now) &&
		exp == float64(int64(exp)) && exp > float64(f.Now) &&
		exp <= float64(min(f.Now+3600, agentExp)) && exp <= parentExp
	o.Scope = c["scope"] == "read"
	for _, name := range []string{"mission_s256", "tenant", "agent", "parent_agent", "account"} {
		if _, present := c[name]; present {
			o.Identity = false
		}
	}
	// The composite grades the protocol's subject lineage; the configured
	// fixture subject is the host's choice, graded only as ps-jwt-subject.
	o.Valid = o.Signature && o.Identity && c["sub"] == parent["sub"] && parent["sub"] != nil && o.Key && o.Lifetime && o.Scope
	if !o.Valid {
		o.Error = "AS grant violates the fixture's delivery bindings"
	}
	return o
}

func observeFederatedResource(f Fixture, compact string, parent map[string]any) PersonObservation {
	_, c, err := verifyJWT(compact, f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt")
	o := PersonObservation{Claims: c}
	if err != nil {
		o.Error = err.Error()
		return o
	}
	o.Signature = true
	jti, _ := c["jti"].(string)
	o.Identity = c["iss"] == f.Origin && c["dwk"] == "aauth-resource.json" &&
		audienceNames(c["aud"], f.Access.Issuer) && c["ps"] == f.Person.Issuer &&
		c["presented_jti"] == parent["jti"] && parent["jti"] != nil && jti != ""
	o.Subject = c["sub"] == parent["sub"] && c["sub"] == f.Person.Subject
	o.Key = c["agent_jkt"] == thumbprint(f.AgentSeed)
	iat, iatOK := c["iat"].(float64)
	exp, expOK := c["exp"].(float64)
	o.Lifetime = iatOK && expOK && iat == float64(f.Now) &&
		exp == float64(int64(exp)) && exp > float64(f.Now)
	o.Scope = c["scope"] == "read"
	for _, name := range []string{"mission_s256", "tenant", "account"} {
		if _, present := c[name]; present {
			o.Identity = false
		}
	}
	// The composite grades the protocol's subject lineage; the configured
	// fixture subject is the host's choice, graded only as ps-jwt-subject.
	o.Valid = o.Signature && o.Identity && c["sub"] == parent["sub"] && parent["sub"] != nil && o.Key && o.Lifetime && o.Scope
	if !o.Valid {
		o.Error = "Resource challenge violates the fixture's presented-token bindings"
	}
	return o
}

func observePSProof(f Fixture, captured Captured) Observation {
	return observePSRequestProof(f, captured, f.Access.Issuer+"/token", "POST")
}
func observePSPollProof(f Fixture, captured Captured, location string) Observation {
	if len(captured.Body) != 0 {
		return Observation{Error: "poll carried a body"}
	}
	return observePSRequestProof(f, captured, location, "GET")
}
func observePSRequestProof(f Fixture, captured Captured, location, method string) Observation {
	failed := Observation{Error: "PS proof, coverage or actual body digest did not verify"}
	target, err := url.Parse(captured.URL)
	if err != nil || captured.URL != location || captured.Method != method {
		return failed
	}
	if method == "POST" {
		mediaType, _, err := mime.ParseMediaType(canonicalField(captured.Headers, "Content-Type"))
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			return failed
		}
		digests, err := httpsfv.UnmarshalDictionary(captured.Headers.Values("Content-Digest"))
		if err != nil || len(digests.Names()) != 1 {
			return failed
		}
		digestValue, _ := digests.Get("sha-256")
		digestItem, ok := digestValue.(httpsfv.Item)
		if !ok || digestItem.Params != nil && len(digestItem.Params.Names()) != 0 {
			return failed
		}
		digestBytes, ok := digestItem.Value.([]byte)
		expectedDigest := sha256.Sum256(captured.Body)
		if !ok || !bytes.Equal(digestBytes, expectedDigest[:]) {
			return failed
		}
	}
	keys, err := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature-Key"))
	if err != nil {
		return failed
	}
	inputs, err := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature-Input"))
	if err != nil {
		return failed
	}
	signatures, err := httpsfv.UnmarshalDictionary(captured.Headers.Values("Signature"))
	if err != nil {
		return failed
	}
	for _, label := range keys.Names() {
		value, _ := keys.Get(label)
		key, ok := value.(httpsfv.Item)
		if !ok || key.Value != httpsfv.Token("jwks_uri") || key.Params == nil {
			continue
		}
		id, _ := key.Params.Get("id")
		dwk, _ := key.Params.Get("dwk")
		kid, _ := key.Params.Get("kid")
		if id != f.Person.Issuer || dwk != "aauth-person.json" || kid != f.Person.Kid {
			continue
		}
		value, _ = inputs.Get(label)
		input, ok := value.(httpsfv.InnerList)
		if !ok || input.Params == nil {
			continue
		}
		created, _ := input.Params.Get("created")
		if created != f.Now {
			continue
		}
		observed := Observation{Created: f.Now}
		lines := []string{}
		seen := map[string]bool{}
		valid := true
		for _, item := range input.Items {
			component, ok := item.Value.(string)
			if !ok || seen[component] || item.Params != nil && len(item.Params.Names()) != 0 {
				valid = false
				break
			}
			seen[component] = true
			observed.Covered = append(observed.Covered, component)
			var field string
			switch component {
			case "@method":
				field = captured.Method
			case "@authority":
				field = strings.ToLower(target.Host)
			case "@path":
				field = target.EscapedPath()
			case "signature-key", "content-type", "content-digest":
				field = canonicalField(captured.Headers, component)
			default:
				valid = false
			}
			lines = append(lines, fmt.Sprintf("%q: %s", component, field))
		}
		requiredComponents := []string{"@method", "@authority", "@path", "signature-key"}
		if method == "POST" {
			requiredComponents = append(requiredComponents, "content-type", "content-digest")
		}
		for _, required := range requiredComponents {
			valid = valid && seen[required]
		}
		params, err := httpsfv.Marshal(input)
		if err != nil {
			continue
		}
		lines = append(lines, `"@signature-params": `+params)
		observed.Base = strings.Join(lines, "\n")
		value, _ = signatures.Get(label)
		signature, ok := value.(httpsfv.Item)
		if !ok {
			continue
		}
		raw, ok := signature.Value.([]byte)
		observed.ValidProof = ok && valid &&
			ed25519.Verify(seedKey(f.Person.Seed).Public().(ed25519.PublicKey), []byte(observed.Base), raw)
		if observed.ValidProof {
			return observed
		}
	}
	return failed
}
