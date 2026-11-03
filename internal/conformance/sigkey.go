package conformance

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

// Signature-Key roles grade draft-hardt-httpbis-signature-key and the AAuth
// HTTP Message Signatures profile at the pinned commits. The verifier role is
// a native AAuth Resource that also accepts the schemes AAuth does not use
// (protocol "Signature-Key Scheme Rejection"); the signer role is the native
// request signer for each scheme.
const (
	SigkeyVerifierRole = "sigkey.verifier"
	SigkeySignerRole   = "sigkey.signer"
)

// SigkeyIdentity is one fixture server identity with an Ed25519 test seed.
type SigkeyIdentity struct {
	Issuer string `json:"issuer"`
	DWK    string `json:"dwk"`
	Kid    string `json:"kid"`
	Seed   string `json:"seed_hex"`
}

// SigkeyKey is one fixture non-Ed25519 test key: PKCS #8 DER, base64.
type SigkeyKey struct {
	Kid   string `json:"kid"`
	PKCS8 string `json:"pkcs8_base64"`
}

// SigkeyFixture is fixture.json extensions.sigkey.
type SigkeyFixture struct {
	Verifier   string               `json:"verifier"`
	Receiver   string               `json:"receiver"`
	Signer     SigkeyIdentity       `json:"signer"`
	JWKSURL    string               `json:"jwks_url"`
	Keys       map[string]SigkeyKey `json:"keys"`
	PQSeed     string               `json:"pq_seed_hex"`
	PQKid      string               `json:"pq_kid"`
	APPQKid    string               `json:"ap_pq_kid"`
	JKTSeed    string               `json:"jkt_identity_seed_hex"`
	SelfJWTTyp string               `json:"self_jwt_typ"`
}

type sigkeyVerifierInput struct {
	Scheme   string `json:"scheme"`
	Alg      string `json:"alg"`
	Mutation string `json:"mutation"`
	JWKS     string `json:"jwks,omitempty"`
	Body     bool   `json:"body,omitempty"`
}

type sigkeySignerInput struct {
	Scheme string `json:"scheme"`
	Alg    string `json:"alg"`
	Method string `json:"method"`
	Body   bool   `json:"body,omitempty"`
}

var (
	sigkeySchemes   = []string{"hwk", "jwt", "jwks_uri", "jwks", "self-jwt", "jkt-jwt", "x-unregistered"}
	sigkeyAlgs      = []string{"Ed25519", "ES256", "ES384", "RS256", "PS256", "ML-DSA-44"}
	sigkeyMutations = map[string][]string{
		"none":                    nil,
		"uncovered-signature-key": {"hwk", "jwt", "jwks_uri"},
		"missing-member":          {"hwk", "jwt"},
		"hwk-kid":                 {"hwk"},
		"alg-eddsa":               {"hwk", "jwt"},
		"header-eddsa":            {"jwt"},
		"alg-kty":                 {"hwk", "jwt"},
		"alg-crv":                 {"hwk"},
		"symmetric":               {"hwk", "jwt"},
		"no-exp":                  {"jwt"},
		"unknown-kid":             {"jwks_uri"},
		"named-document":          {"jwks_uri"},
	}
	sigkeySignerSchemes = []string{"hwk", "jwt", "jwks_uri", "jwks", "self-jwt", "jkt-jwt"}
)

// sigkeyNamedDocument is the metadata document the jwks_uri signer also
// publishes for the named-document mutation. Signature-Key makes dwk any
// document name under /.well-known/ (JWKS URI Discovery, line 454), and this
// is the name of that section's own example (line 479), not an AAuth role's.
const sigkeyNamedDocument = "example-configuration"

// sigkeySignerDocument is the document the jwks_uri signer names in one
// verifier case.
func sigkeySignerDocument(k SigkeyFixture, in sigkeyVerifierInput) string {
	if in.Mutation == "named-document" {
		return sigkeyNamedDocument
	}
	return k.Signer.DWK
}

func init() {
	RegisterRole(SigkeyVerifierRole, ExtensionRole{Kinds: []string{"sigkey-pq"}, Validate: validateSigkeyVerifier, Run: runSigkeyVerifier})
	RegisterRole(SigkeySignerRole, ExtensionRole{Kinds: []string{"sigkey-signed", "sigkey-member", "sigkey-created"}, Validate: validateSigkeySigner, Run: runSigkeySigner})
}

func sigkeyFixture(f Fixture) (SigkeyFixture, error) {
	var k SigkeyFixture
	if err := DecodeExtension(f, "sigkey", &k); err != nil {
		return k, err
	}
	for _, target := range []string{k.Verifier, k.Receiver, k.JWKSURL} {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
			return k, fmt.Errorf("sigkey verifier, receiver and jwks_url must be HTTPS URLs with a path")
		}
	}
	signer, err := url.Parse(k.Signer.Issuer)
	if err != nil || signer.Scheme != "https" || signer.Host == "" || signer.Path != "" || signer.Port() != "" || k.Signer.DWK != "aauth-resource.json" || k.Signer.Kid == "" || !validSeed(k.Signer.Seed) {
		return k, fmt.Errorf("invalid sigkey signer identity")
	}
	if !validSeed(k.PQSeed) || !validSeed(k.JKTSeed) || k.PQKid == "" || k.APPQKid == "" || k.PQKid == k.Signer.Kid || k.APPQKid == f.Kid || k.SelfJWTTyp == "" {
		return k, fmt.Errorf("invalid sigkey post-quantum, jkt-jwt or self-jwt fixture")
	}
	for _, alg := range []string{"ES256", "ES384", "RS256", "PS256"} {
		key, ok := k.Keys[alg]
		der, decodeErr := base64.StdEncoding.DecodeString(key.PKCS8)
		if !ok || key.Kid == "" || decodeErr != nil {
			return k, fmt.Errorf("sigkey fixture key %s is missing", alg)
		}
		if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
			return k, fmt.Errorf("sigkey fixture key %s: %w", alg, err)
		}
	}
	return k, nil
}

func validateSigkeyVerifier(f Fixture, s Scenario) error {
	if _, err := sigkeyFixture(f); err != nil {
		return err
	}
	var in sigkeyVerifierInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	schemes, known := sigkeyMutations[in.Mutation]
	if !slices.Contains(sigkeySchemes, in.Scheme) || !slices.Contains(sigkeyAlgs, in.Alg) || !known || schemes != nil && !slices.Contains(schemes, in.Scheme) {
		return fmt.Errorf("%s: unsupported sigkey scheme, algorithm or mutation", s.ID)
	}
	if in.Alg != "Ed25519" && in.Scheme != "hwk" && !(in.Alg == "ES256" && in.Scheme == "jwt" && in.Mutation == "none") && !(in.Alg == "ML-DSA-44" && in.JWKS == "pq-only") {
		return fmt.Errorf("%s: hwk varies the algorithm, jwt may confirm an ES256 key, and ML-DSA-44 needs a pq-only key set", s.ID)
	}
	if in.JWKS != "" && (!slices.Contains([]string{"mixed", "pq-only"}, in.JWKS) || in.Scheme != "jwt" && in.Scheme != "jwks_uri") {
		return fmt.Errorf("%s: mixed or pq-only key sets apply to the jwt Agent Provider or the jwks_uri signer", s.ID)
	}
	for _, a := range s.Assertions {
		if a.Stage != "" {
			return fmt.Errorf("%s/%s: the verifier role has one exchange and no stages", s.ID, a.ID)
		}
		if a.Kind == "sigkey-pq" {
			var code string
			if json.Unmarshal(a.Equals, &code) != nil || in.JWKS != "pq-only" {
				return fmt.Errorf("%s/%s: sigkey-pq needs a code string on a pq-only scenario", s.ID, a.ID)
			}
		}
	}
	return nil
}

func validateSigkeySigner(f Fixture, s Scenario) error {
	if _, err := sigkeyFixture(f); err != nil {
		return err
	}
	var in sigkeySignerInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains(sigkeySignerSchemes, in.Scheme) || !slices.Contains(sigkeyAlgs[:5], in.Alg) || !slices.Contains([]string{"GET", "POST"}, in.Method) || in.Body && in.Method != "POST" {
		return fmt.Errorf("%s: unsupported signer scheme, algorithm or method", s.ID)
	}
	if in.Alg != "Ed25519" && in.Scheme != "hwk" && !(in.Alg == "ES256" && in.Scheme == "jwt") {
		return fmt.Errorf("%s: hwk varies the signer algorithm and jwt may confirm an ES256 key", s.ID)
	}
	for _, a := range s.Assertions {
		var value any
		json.Unmarshal(a.Equals, &value)
		switch a.Kind {
		case "sigkey-signed", "sigkey-member":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s/%s: %s needs a boolean", s.ID, a.ID, a.Kind)
			}
		case "sigkey-created":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("%s/%s: sigkey-created needs a number", s.ID, a.ID)
			}
		}
		if a.Stage != "" {
			return fmt.Errorf("%s/%s: the signer role has no stages", s.ID, a.ID)
		}
	}
	return nil
}

// sigkeyOffered reports whether a target claims a scenario's own clause, which
// its first assertion names; later assertions may share a role-wide clause such
// as the adapter-contract echo. A scheme or algorithm a library does not offer
// is left unclaimed for it, and its scenario is not run: an unclaimed case
// cannot pass, and running it would only exercise the launcher's refusal to
// sign or route it.
func sigkeyOffered(s Scenario, t Target) bool {
	return t.Unavailable == "" && len(s.Assertions) > 0 && slices.Contains(t.Claims, s.Assertions[0].Clause)
}

func sigkeyNotOffered(t Target) string {
	if t.Unavailable != "" {
		return t.Unavailable
	}
	return "not offered by this implementation; the scenario was not run"
}
