package conformance

import (
	"encoding/base64"
	"fmt"
)

// sigvecPart is one labeled signature of a vector: the key that signs it and
// the Signature-Key member that conveys or references that key.
type sigvecPart struct {
	Label  string
	Key    string // vector key id that signs the HTTP request
	Scheme string
	JWT    string
	Cache  bool
	ID     string
	DWK    string
	Kid    string
	URL    string
	X5U    string
	Cert   []byte
	CID    string
	// Member, when set, is the exact Signature-Key member value the harness
	// writes (only the harness signs malformed or forbidden members).
	Member string
}

// sigvecCase is one vector definition. Signers lists the libraries that sign
// it, in preference order; an empty list means only the harness can produce
// it, because a conforming signer refuses to.
type sigvecCase struct {
	ID, Title, Clause string
	Alg               string
	Signers           []string
	HarnessReason     string
	Method            string
	Query             string
	Body              string
	ContentType       string
	CreatedOffset     int64
	Nonce             string
	Parts             func(b *sigvecBuild) ([]sigvecPart, error)
	Covered           []string // harness signing only; nil means the draft's set
	Mutation          string   // after signing: tamper-signature, rename-label
	Documents         func(b *sigvecBuild) []SigvecDocument
	Expect            SigvecExpect
	Category          int // 0 derives it from the algorithm
	Assertion         string
}

const (
	libRust = "aauth-rust"
	libGo   = "aauth-go"
)

var bothLibraries = []string{libRust, libGo}

// sigvecAgentToken mints the Agent Provider's aa-agent+jwt binding key.
func (b *sigvecBuild) agentToken(confirmation map[string]any, jti string, edit func(claims map[string]any)) (string, error) {
	if reused, ok := b.reuse[b.current]; ok {
		return reused, nil
	}
	claims := map[string]any{"iss": sigvecAP, "sub": sigvecAgent, "dwk": "aauth-agent.json", "jti": jti, "iat": sigvecNow - 300, "exp": sigvecNow + 3000, "cnf": map[string]any{"jwk": confirmation}}
	if edit != nil {
		edit(claims)
	}
	return sigkeyJWS(map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": "ap-ed25519"}, claims, b.keys["ap-ed25519"].key)
}

// jktToken mints a jkt-s256+jwt delegation from identity to the request key.
func (b *sigvecBuild) jktToken(identity, request, jti string, edit func(claims map[string]any)) (string, error) {
	if reused, ok := b.reuse[b.current]; ok {
		return reused, nil
	}
	id := b.keys[identity].key
	claims := map[string]any{"iss": "urn:jkt:sha-256:" + sigkeyThumbprint(id.public), "iat": sigvecNow - 300, "exp": sigvecNow + 3000, "jti": jti, "cnf": map[string]any{"jwk": b.keys[request].key.public}}
	if edit != nil {
		edit(claims)
	}
	return sigkeyJWS(map[string]any{"typ": "jkt-s256+jwt", "alg": id.alg, "jwk": id.public}, claims, id)
}

// selfToken mints a self-jwt for the signer key with the given kid.
func (b *sigvecBuild) selfToken(key, jti string, edit func(claims map[string]any)) (string, error) {
	if reused, ok := b.reuse[b.current]; ok {
		return reused, nil
	}
	k := b.keys[key]
	claims := map[string]any{"iss": sigvecSigner, "dwk": sigvecSignerDWK, "aud": sigvecOrigin, "jti": jti, "iat": sigvecNow - 30, "exp": sigvecNow + 300}
	if edit != nil {
		edit(claims)
	}
	return sigkeyJWS(map[string]any{"alg": k.key.alg, "kid": k.def.kid, "typ": sigvecSelfJWTTyp}, claims, k.key)
}

func one(p sigvecPart, err error) ([]sigvecPart, error) {
	if p.Label == "" {
		p.Label = sigvecLabel
	}
	return []sigvecPart{p}, err
}

func hwkPart(key string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(*sigvecBuild) ([]sigvecPart, error) { return one(sigvecPart{Key: key, Scheme: "hwk"}, nil) }
}

func jwtPart(key, jti string, cache bool) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(b *sigvecBuild) ([]sigvecPart, error) {
		token, err := b.agentToken(b.keys[key].key.public, jti, nil)
		return one(sigvecPart{Key: key, Scheme: "jwt", JWT: token, Cache: cache}, err)
	}
}

func jwksURIPart(key, kid string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(*sigvecBuild) ([]sigvecPart, error) {
		return one(sigvecPart{Key: key, Scheme: "jwks_uri", ID: sigvecSigner, DWK: sigvecSignerDWK, Kid: kid}, nil)
	}
}

func jwksPart(key, kid string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(*sigvecBuild) ([]sigvecPart, error) {
		return one(sigvecPart{Key: key, Scheme: "jwks", URL: sigvecJWKSURL, Kid: kid}, nil)
	}
}

func selfPart(key, jti string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(b *sigvecBuild) ([]sigvecPart, error) {
		token, err := b.selfToken(key, jti, nil)
		return one(sigvecPart{Key: key, Scheme: "self-jwt", JWT: token}, err)
	}
}

func jktPart(identity, key, jti string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(b *sigvecBuild) ([]sigvecPart, error) {
		token, err := b.jktToken(identity, key, jti, nil)
		return one(sigvecPart{Key: key, Scheme: "jkt-jwt", JWT: token}, err)
	}
}

func x509Part(key string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(b *sigvecBuild) ([]sigvecPart, error) {
		return one(sigvecPart{Key: key, Scheme: "x509", X5U: sigvecX5U(key), Cert: b.certs.leaves[key]}, nil)
	}
}

// memberPart is a harness-written member: the exact Signature-Key value.
func memberPart(key, scheme string, member func(b *sigvecBuild) string) func(*sigvecBuild) ([]sigvecPart, error) {
	return func(b *sigvecBuild) ([]sigvecPart, error) {
		return one(sigvecPart{Key: key, Scheme: scheme, Member: member(b)}, nil)
	}
}

// hwkMember serializes an inline JWK as hwk parameters, in the draft's order.
func hwkMember(key map[string]any) string {
	return sigkeyMember("", "hwk", sigkeyHWKParams(key)...)[1:]
}

func replaceSignerJWKS(keys ...map[string]any) func(*sigvecBuild) []SigvecDocument {
	return func(*sigvecBuild) []SigvecDocument {
		set := []any{}
		for _, k := range keys {
			set = append(set, k)
		}
		return []SigvecDocument{sigvecDocument(sigvecSigner+"/.well-known/jwks.json", map[string]any{"keys": set})}
	}
}

const (
	basisVerify = "a correctly signed request under this scheme verifies"
	harnessHWK  = "both libraries emit hwk members only for the signing key's own JWK, with alg and without kid"
)

// sigvecCases is the whole vector set, in publication order.
func sigvecCases() []sigvecCase {
	post := func(c sigvecCase) sigvecCase {
		c.Method, c.Query, c.Body, c.ContentType = "POST", "page=2&sort=name", `{"name":"widget","quantity":3}`, "application/json"
		return c
	}
	verify := SigvecExpect{Outcome: "verify", Basis: basisVerify}
	reject := func(code, basis string) SigvecExpect {
		return SigvecExpect{Outcome: "reject", Error: code, Basis: basis}
	}
	cases := []sigvecCase{
		// Positive vectors, one or more per scheme and algorithm.
		{ID: "hwk-ed25519", Title: "hwk, Ed25519, GET", Clause: "sigvec.hwk", Alg: "Ed25519", Signers: bothLibraries, Parts: hwkPart("agent-ed25519"), Expect: verify},
		post(sigvecCase{ID: "hwk-ed25519-post", Title: "hwk, Ed25519, POST with query, Content-Type and Content-Digest", Clause: "sigvec.hwk", Alg: "Ed25519", Signers: bothLibraries, Parts: hwkPart("agent-ed25519"), Expect: verify}),
		{ID: "hwk-ed25519-nonce", Title: "hwk, Ed25519, with a nonce signature parameter", Clause: "sigvec.hwk", Alg: "Ed25519", Signers: []string{libGo}, Nonce: "n-0001", Parts: hwkPart("agent-ed25519"), Expect: verify},
		{ID: "hwk-es256", Title: "hwk, ES256", Clause: "sigvec.hwk.es256", Alg: "ES256", Signers: bothLibraries, Parts: hwkPart("agent-es256"), Expect: verify},
		{ID: "hwk-es384", Title: "hwk, ES384", Clause: "sigvec.hwk.es384", Alg: "ES384", Signers: bothLibraries, Parts: hwkPart("agent-es384"), Expect: verify},
		{ID: "hwk-rs256", Title: "hwk, RS256", Clause: "sigvec.hwk.rs256", Alg: "RS256", Signers: bothLibraries, Parts: hwkPart("agent-rs256"), Expect: verify},
		{ID: "hwk-ps256", Title: "hwk, PS256", Clause: "sigvec.hwk.ps256", Alg: "PS256", Signers: bothLibraries, Parts: hwkPart("agent-ps256"), Expect: verify},
		{ID: "jwt-ed25519", Title: "jwt (AAuth agent token), Ed25519 confirmation key", Clause: "sigvec.jwt", Alg: "Ed25519", Signers: bothLibraries, Parts: jwtPart("agent-ed25519", "jwt-ed25519", false), Expect: verify, Assertion: "agent token"},
		post(sigvecCase{ID: "jwt-ed25519-post", Title: "jwt, Ed25519, POST with query, Content-Type and Content-Digest", Clause: "sigvec.jwt", Alg: "Ed25519", Signers: bothLibraries, Parts: jwtPart("agent-ed25519", "jwt-ed25519-post", false), Expect: verify}),
		{ID: "jwt-ed25519-cache", Title: "jwt with the bare cache parameter and a jti", Clause: "sigvec.jwt.cache", Alg: "Ed25519", Signers: bothLibraries, Parts: jwtPart("agent-ed25519", "jwt-ed25519-cache", true), Expect: verify},
		{ID: "jwt-es256", Title: "jwt, ES256 confirmation key", Clause: "sigvec.jwt.es256", Alg: "ES256", Signers: bothLibraries, Parts: jwtPart("agent-es256", "jwt-es256", false), Expect: verify},
		{ID: "jwks-uri-ed25519", Title: "jwks_uri, Ed25519", Clause: "sigvec.jwks-uri", Alg: "Ed25519", Signers: bothLibraries, Parts: jwksURIPart("signer-ed25519", "signer-ed25519"), Expect: verify},
		{ID: "jwks-uri-es256", Title: "jwks_uri, ES256", Clause: "sigvec.jwks-uri.es256", Alg: "ES256", Signers: bothLibraries, Parts: jwksURIPart("signer-es256", "signer-es256"), Expect: verify},
		{ID: "jwks-ed25519", Title: "jwks, Ed25519", Clause: "sigvec.jwks", Alg: "Ed25519", Signers: bothLibraries, Parts: jwksPart("signer-ed25519", "signer-ed25519"), Expect: verify},
		{ID: "jwks-es256", Title: "jwks, ES256", Clause: "sigvec.jwks.es256", Alg: "ES256", Signers: bothLibraries, Parts: jwksPart("signer-es256", "signer-es256"), Expect: verify},
		{ID: "self-jwt-ed25519", Title: "self-jwt, Ed25519", Clause: "sigvec.self-jwt", Alg: "Ed25519", Signers: bothLibraries, Parts: selfPart("signer-ed25519", "self-jwt-ed25519"), Expect: verify},
		{ID: "self-jwt-es256", Title: "self-jwt, ES256", Clause: "sigvec.self-jwt.es256", Alg: "ES256", Signers: bothLibraries, Parts: selfPart("signer-es256", "self-jwt-es256"), Expect: verify},
		{ID: "jkt-jwt-ed25519", Title: "jkt-jwt, Ed25519 identity key delegating to an Ed25519 request key", Clause: "sigvec.jkt-jwt", Alg: "Ed25519", Signers: bothLibraries, Parts: jktPart("jkt-identity-ed25519", "agent-ed25519", "jkt-jwt-ed25519"), Expect: verify},
		{ID: "jkt-jwt-es256-identity", Title: "jkt-jwt, ES256 identity key delegating to an Ed25519 request key (the draft's example shape)", Clause: "sigvec.jkt-jwt.es256", Alg: "Ed25519", Signers: bothLibraries, Parts: jktPart("jkt-identity-es256", "agent-ed25519", "jkt-jwt-es256-identity"), Expect: verify},
		{ID: "jkt-jwt-es256", Title: "jkt-jwt, Ed25519 identity key delegating to an ES256 request key", Clause: "sigvec.jkt-jwt.es256", Alg: "ES256", Signers: bothLibraries, Parts: jktPart("jkt-identity-ed25519", "agent-es256", "jkt-jwt-es256"), Expect: verify},
		{ID: "x509-ed25519", Title: "x509, Ed25519 end-entity certificate", Clause: "sigvec.x509", Alg: "Ed25519", Signers: bothLibraries, Parts: x509Part("x509-ed25519"), Expect: verify},
		{ID: "x509-es256", Title: "x509, ES256 end-entity certificate", Clause: "sigvec.x509.es256", Alg: "ES256", Signers: bothLibraries, Parts: x509Part("x509-es256"), Expect: verify},
		// Key-handling vectors (category 1).
		{ID: "jwks-uri-mixed-ml-dsa", Title: "jwks_uri whose JWKS also holds an ML-DSA-44 key; kid selects the Ed25519 key", Clause: "sigvec.mixed-jwks", Alg: "Ed25519", Category: 1, Signers: bothLibraries, Parts: jwksURIPart("signer-ed25519", "signer-ed25519"),
			Documents: func(b *sigvecBuild) []SigvecDocument {
				return replaceSignerJWKS(b.keys["signer-ml-dsa-44"].public(), b.keys["signer-ed25519"].public())(b)
			},
			Expect: SigvecExpect{Outcome: "verify", Basis: "signature-key line 235: select the member matching kid; MUST NOT fail because an unselected member names a kty or alg the verifier does not implement"}},
		{ID: "jwks-uri-ml-dsa-only", Title: "jwks_uri whose only key is ML-DSA-44, signed with it", Clause: "sigvec.reject.pq-only", Alg: "ML-DSA-44", Category: 1, HarnessReason: "neither library signs with ML-DSA-44", Parts: jwksURIPart("signer-ml-dsa-44", "signer-ml-dsa-44"),
			Documents: func(b *sigvecBuild) []SigvecDocument {
				return replaceSignerJWKS(b.keys["signer-ml-dsa-44"].public())(b)
			},
			Expect: SigvecExpect{Outcome: "verify-or-reject", Error: "unsupported_algorithm", Basis: "signature-key line 233 and protocol Verification step 6: a verifier that does not implement the AKP key type MUST reject it with unsupported_algorithm and MUST NOT fail in an undefined manner; one that implements ML-DSA-44 verifies"}},
		// Negative vectors.
		{ID: "reject-uncovered-signature-key", Title: "hwk signature that does not cover signature-key", Clause: "sigvec.reject.uncovered", Alg: "Ed25519", HarnessReason: "both libraries always cover signature-key", Parts: hwkPart("agent-ed25519"), Covered: []string{"@method", "@authority", "@path"},
			Expect: SigvecExpect{Outcome: "reject", Error: "invalid_input", RequiredInputIncludes: []string{"signature-key"}, Basis: "signature-key line 1301: verifiers MUST reject requests where signature-key is not covered; protocol Verification step 2: invalid_input with required_input"}},
		{ID: "reject-hwk-kid", Title: "hwk member carrying a kid parameter", Clause: "sigvec.reject.hwk-kid", Alg: "Ed25519", HarnessReason: harnessHWK,
			Parts: memberPart("agent-ed25519", "hwk", func(b *sigvecBuild) string {
				return hwkMember(sigkeyCloneJWK(b.keys["agent-ed25519"].key.public, "kid", "agent-1"))
			}),
			Expect: reject("", "signature-key line 295: the kid parameter MUST NOT be used; no code is fixed, and any failure is a 401 with Signature-Error (protocol Verification)")},
		{ID: "reject-hwk-alg-eddsa", Title: "hwk member naming the polymorphic EdDSA", Clause: "sigvec.reject.alg", Alg: "Ed25519", HarnessReason: harnessHWK,
			Parts: memberPart("agent-ed25519", "hwk", func(b *sigvecBuild) string {
				return hwkMember(sigkeyCloneJWK(b.keys["agent-ed25519"].key.public, "alg", "EdDSA"))
			}),
			Expect: reject("unsupported_algorithm", "signature-key lines 203 and 211; protocol Verification step 6: unsupported_algorithm for a polymorphic alg")},
		{ID: "reject-hwk-alg-absent", Title: "hwk member without alg", Clause: "sigvec.reject.alg", Alg: "Ed25519", HarnessReason: harnessHWK,
			Parts: memberPart("agent-ed25519", "hwk", func(b *sigvecBuild) string {
				return hwkMember(sigkeyCloneJWK(b.keys["agent-ed25519"].key.public, "alg", nil))
			}),
			Expect: reject("unsupported_algorithm", "signature-key lines 203 and 293: alg is REQUIRED and a verifier MUST reject a JWK without it; protocol Verification step 6: unsupported_algorithm if alg is absent")},
		{ID: "reject-hwk-kty-mismatch", Title: "hwk OKP key naming ES256", Clause: "sigvec.reject.kty-crv", Alg: "Ed25519", HarnessReason: harnessHWK,
			Parts: memberPart("agent-ed25519", "hwk", func(b *sigvecBuild) string {
				return hwkMember(sigkeyCloneJWK(b.keys["agent-ed25519"].key.public, "alg", "ES256"))
			}),
			Expect: reject("invalid_key", "signature-key line 229; protocol Verification step 6: invalid_key when kty disagrees with alg")},
		{ID: "reject-hwk-crv-mismatch", Title: "hwk P-384 key naming ES256", Clause: "sigvec.reject.kty-crv", Alg: "ES384", HarnessReason: harnessHWK,
			Parts: memberPart("agent-es384", "hwk", func(b *sigvecBuild) string {
				return hwkMember(sigkeyCloneJWK(b.keys["agent-es384"].key.public, "alg", "ES256"))
			}),
			Expect: reject("invalid_key", "signature-key line 229; protocol Verification step 6: invalid_key when crv disagrees with alg")},
		{ID: "reject-hwk-symmetric", Title: "hwk conveying an oct HS256 key, HMAC signature", Clause: "sigvec.reject.symmetric", Alg: "HS256", HarnessReason: "neither library signs with a symmetric key",
			Parts:  memberPart("", "hwk", func(*sigvecBuild) string { return hwkMember(sigkeySymmetric().public) }),
			Expect: reject("", "signature-key line 217 and protocol Signature Algorithms: symmetric keys MUST NOT be used and a verifier MUST reject them; no code is fixed")},
		{ID: "reject-unknown-scheme", Title: "unregistered scheme token", Clause: "sigvec.reject.unknown-scheme", Alg: "Ed25519", HarnessReason: "neither library signs under an unregistered scheme",
			Parts: memberPart("agent-ed25519", "x-unregistered", func(b *sigvecBuild) string {
				return "x-unregistered;key=" + fmt.Sprintf("%q", b.keys["agent-ed25519"].key.public["x"])
			}),
			Expect: reject("unsupported_scheme", "signature-key line 155 and protocol Verification step 4: unsupported_scheme")},
		{ID: "reject-wrong-label", Title: "Signature-Key member under sig1 while the signature is labelled sig", Clause: "sigvec.reject.signature", Alg: "Ed25519", Signers: []string{libGo, libRust}, Mutation: "rename-label",
			Parts: func(*sigvecBuild) ([]sigvecPart, error) {
				return []sigvecPart{{Label: "sig1", Key: "agent-ed25519", Scheme: "hwk"}}, nil
			},
			Expect: reject("invalid_signature", "signature-key lines 179 and 187: no member for the verified label MUST fail; line 1018 assigns missing Signature-Key material to invalid_signature")},
		{ID: "reject-tampered-signature", Title: "hwk signature with one bit flipped", Clause: "sigvec.reject.signature", Alg: "Ed25519", Signers: []string{libGo, libRust}, Mutation: "tamper-signature", Parts: hwkPart("agent-ed25519"),
			Expect: reject("invalid_signature", "protocol Verification step 7: invalid_signature if verification fails")},
		{ID: "reject-wrong-key", Title: "jwt whose cnf names one key while another key signs", Clause: "sigvec.reject.signature", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.agentToken(b.keys["agent-ed25519"].key.public, "reject-wrong-key", nil)
				return one(sigvecPart{Key: "other-ed25519", Scheme: "jwt", JWT: token}, err)
			},
			Expect: reject("invalid_signature", "protocol Verification step 7: the signature does not verify under the key the member conveys")},
		{ID: "reject-created-future", Title: "created 300 seconds ahead of the verifier clock (window 60)", Clause: "sigvec.reject.window", Alg: "Ed25519", Signers: []string{libGo, libRust}, CreatedOffset: 300, Parts: hwkPart("agent-ed25519"),
			Expect: reject("clock_skew", "signature-key line 1106 and protocol Verification step 3: clock_skew when created is further ahead than the window")},
		{ID: "reject-created-stale", Title: "created 300 seconds before the verifier clock (window 60)", Clause: "sigvec.reject.window", Alg: "Ed25519", Signers: []string{libGo, libRust}, CreatedOffset: -300, Parts: hwkPart("agent-ed25519"),
			Expect: reject("invalid_signature", "signature-key line 1114 and protocol Verification step 3: invalid_signature when created is older than the window")},
		{ID: "reject-jwt-expired", Title: "jwt whose exp is one second before the verifier clock", Clause: "sigvec.reject.jwt-expired", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.agentToken(b.keys["agent-ed25519"].key.public, "reject-jwt-expired", func(c map[string]any) { c["iat"], c["exp"] = sigvecNow-3600, sigvecNow-1 })
				return one(sigvecPart{Key: "agent-ed25519", Scheme: "jwt", JWT: token}, err)
			},
			Expect: reject("expired_jwt", "signature-key line 1084 and protocol Verification step 5: expired_jwt")},
		{ID: "reject-jwt-no-exp", Title: "jwt without exp", Clause: "sigvec.reject.jwt-exp", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.agentToken(b.keys["agent-ed25519"].key.public, "reject-jwt-no-exp", func(c map[string]any) { delete(c, "exp") })
				return one(sigvecPart{Key: "agent-ed25519", Scheme: "jwt", JWT: token}, err)
			},
			Expect: reject("invalid_jwt", "signature-key line 552: the JWT MUST contain exp; protocol Verification step 5: invalid_jwt when a JWT scheme fails verification")},
		{ID: "reject-jwt-cnf-eddsa", Title: "jwt whose cnf.jwk names the polymorphic EdDSA", Clause: "sigvec.reject.alg", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.agentToken(sigkeyCloneJWK(b.keys["agent-ed25519"].key.public, "alg", "EdDSA"), "reject-jwt-cnf-eddsa", nil)
				return one(sigvecPart{Key: "agent-ed25519", Scheme: "jwt", JWT: token}, err)
			},
			Expect: reject("unsupported_algorithm", "signature-key line 211 and protocol Verification step 6, for the cnf.jwk the jwt scheme conveys")},
		{ID: "reject-jwks-uri-unknown-kid", Title: "jwks_uri naming a kid the JWKS does not hold", Clause: "sigvec.reject.unknown-kid", Alg: "Ed25519", Signers: []string{libGo, libRust}, Parts: jwksURIPart("signer-ed25519", "signer-absent"),
			Expect: reject("unknown_key", "signature-key line 1054 and protocol Verification step 5: unknown_key")},
		{ID: "reject-jwks-unknown-kid", Title: "jwks naming a kid the JWKS does not hold", Clause: "sigvec.reject.unknown-kid", Alg: "Ed25519", Signers: []string{libGo, libRust}, Parts: jwksPart("signer-ed25519", "signer-absent"),
			Expect: reject("unknown_key", "signature-key line 1054 (applicable to jwks): unknown_key")},
		{ID: "reject-jwks-uri-issuer-mismatch", Title: "jwks_uri whose metadata names another issuer", Clause: "sigvec.reject.issuer", Alg: "Ed25519", Signers: []string{libGo, libRust}, Parts: jwksURIPart("signer-ed25519", "signer-ed25519"),
			Documents: func(*sigvecBuild) []SigvecDocument {
				return []SigvecDocument{sigvecDocument(sigvecSigner+"/.well-known/"+sigvecSignerDWK, map[string]any{"issuer": "https://other-signer.example", "jwks_uri": sigvecSigner + "/.well-known/jwks.json"})}
			},
			Expect: reject("issuer_mismatch", "signature-key line 464: issuer MUST equal id, else issuer_mismatch")},
		{ID: "reject-jwks-uri-issuer-missing", Title: "jwks_uri whose metadata has no issuer", Clause: "sigvec.reject.issuer", Alg: "Ed25519", Signers: []string{libGo, libRust}, Parts: jwksURIPart("signer-ed25519", "signer-ed25519"),
			Documents: func(*sigvecBuild) []SigvecDocument {
				return []SigvecDocument{sigvecDocument(sigvecSigner+"/.well-known/"+sigvecSignerDWK, map[string]any{"jwks_uri": sigvecSigner + "/.well-known/jwks.json"})}
			},
			Expect: reject("issuer_missing", "signature-key line 462: the document MUST contain issuer, else issuer_missing")},
		{ID: "reject-jwks-uri-alg-absent", Title: "jwks_uri whose selected JWKS key has no alg", Clause: "sigvec.reject.alg", Alg: "Ed25519", Signers: []string{libGo, libRust}, Parts: jwksURIPart("signer-ed25519", "signer-ed25519"),
			Documents: func(b *sigvecBuild) []SigvecDocument {
				return replaceSignerJWKS(sigkeyCloneJWK(b.keys["signer-ed25519"].public(), "alg", nil))(b)
			},
			Expect: reject("unsupported_algorithm", "signature-key line 227: the resolved JWKS entry MUST carry alg; protocol Verification step 6: unsupported_algorithm if alg is absent")},
		{ID: "reject-self-jwt-cnf", Title: "self-jwt carrying a cnf claim", Clause: "sigvec.reject.self-jwt-cnf", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.selfToken("signer-ed25519", "reject-self-jwt-cnf", func(c map[string]any) { c["cnf"] = map[string]any{"jwk": b.keys["signer-ed25519"].key.public} })
				return one(sigvecPart{Key: "signer-ed25519", Scheme: "self-jwt", JWT: token}, err)
			},
			Expect: reject("invalid_jwt", "signature-key lines 629 and 651: a self-jwt MUST NOT contain cnf; invalid_jwt (line 1078) for a JWT that fails verification")},
		{ID: "reject-jkt-jwt-iss-mismatch", Title: "jkt-jwt whose iss is not the thumbprint of its header jwk", Clause: "sigvec.reject.jkt-iss", Alg: "Ed25519", Signers: []string{libGo, libRust},
			Parts: func(b *sigvecBuild) ([]sigvecPart, error) {
				token, err := b.jktToken("jkt-identity-ed25519", "agent-ed25519", "reject-jkt-jwt-iss-mismatch", func(c map[string]any) {
					c["iss"] = "urn:jkt:sha-256:" + sigkeyThumbprint(b.keys["other-ed25519"].key.public)
				})
				return one(sigvecPart{Key: "agent-ed25519", Scheme: "jkt-jwt", JWT: token}, err)
			},
			Expect: reject("invalid_jwt", "signature-key lines 339 and 424: iss MUST equal the thumbprint URI of the header jwk; invalid_jwt (line 1078)")},
		{ID: "reject-cached-unknown-cid", Title: "cached member whose cid this verifier never issued", Clause: "sigvec.reject.cache-miss", Alg: "Ed25519", Signers: []string{libRust, libGo},
			Parts: func(*sigvecBuild) ([]sigvecPart, error) {
				return one(sigvecPart{Key: "agent-ed25519", Scheme: "cached", CID: "never-issued-0001"}, nil)
			},
			Expect: reject("cache_miss", "signature-key lines 1008-1014: cache_miss when a cache identifier cannot be resolved")},
		// Multiple signatures, appended so earlier scenario numbers stay.
		{ID: "multi-hwk-jwks", Title: "two signatures on one request, sig1 under hwk and sig2 under jwks, both Ed25519; the verifier is configured to verify sig1 and sig2", Clause: "sigvec.multi", Alg: "Ed25519", Signers: bothLibraries,
			Parts: func(*sigvecBuild) ([]sigvecPart, error) {
				return []sigvecPart{
					{Label: "sig1", Key: "agent-ed25519", Scheme: "hwk"},
					{Label: "sig2", Key: "signer-ed25519", Scheme: "jwks", URL: sigvecJWKSURL, Kid: "signer-ed25519"},
				}, nil
			},
			Expect: SigvecExpect{Outcome: "verify", Basis: "signature-key lines 173 and 181 leave the labels a verifier checks to application context, so this vector's verifier is configured to verify sig1 and sig2 in place of sig; lines 191 and 199: each signature has its own member keyed by its label, the complete Signature-Key is populated before any signature is created and each signature covers signature-key; line 177: the verifier selects each label's member, and each signature verifies over its own base"}},
	}
	return cases
}

func sigvecB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
