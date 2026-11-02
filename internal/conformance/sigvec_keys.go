package conformance

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// The vector identities. They are example names (RFC 2606): nothing is
// fetched, and every document a verifier needs is in the vector file.
const (
	sigvecNow        = 1800000000
	sigvecResource   = "https://resource.example/api/items"
	sigvecOrigin     = "https://resource.example"
	sigvecAP         = "https://agent-provider.example"
	sigvecAgent      = "aauth:assistant@agent-provider.example"
	sigvecSigner     = "https://signer.example"
	sigvecSignerDWK  = "aauth-resource.json"
	sigvecJWKSURL    = "https://keys.example/signer.jwks"
	sigvecSelfJWTTyp = "vector-self+jwt"
	sigvecLabel      = "sig"
	sigvecWindow     = 60
	sigvecSeedPrefix = "aauth-conformance signature-key vectors "
)

// sigvecKeyDef names one vector key and how its private material is made.
type sigvecKeyDef struct {
	id, alg, kid string
	// fixture names a sigkey fixture PKCS #8 key (RSA, which cannot be
	// derived from a short seed); otherwise the key is derived from the id.
	fixture string
}

var sigvecKeyDefs = []sigvecKeyDef{
	{id: "agent-ed25519", alg: "Ed25519"},
	{id: "agent-es256", alg: "ES256"},
	{id: "agent-es384", alg: "ES384"},
	{id: "agent-rs256", alg: "RS256", fixture: "RS256"},
	{id: "agent-ps256", alg: "PS256", fixture: "PS256"},
	{id: "other-ed25519", alg: "Ed25519"},
	{id: "ap-ed25519", alg: "Ed25519", kid: "ap-ed25519"},
	{id: "signer-ed25519", alg: "Ed25519", kid: "signer-ed25519"},
	{id: "signer-es256", alg: "ES256", kid: "signer-es256"},
	{id: "signer-ml-dsa-44", alg: "ML-DSA-44", kid: "signer-ml-dsa-44"},
	{id: "jkt-identity-ed25519", alg: "Ed25519"},
	{id: "jkt-identity-es256", alg: "ES256"},
	{id: "ca-ed25519", alg: "Ed25519"},
	{id: "x509-ed25519", alg: "Ed25519"},
	{id: "x509-es256", alg: "ES256"},
}

// sigvecKey is one vector key: the harness signer and its published form.
type sigvecKey struct {
	def       sigvecKeyDef
	key       sigkeyKey
	published SigvecKey
	signer    any // crypto.Signer for certificates
}

// public returns the public JWK with the key's kid, if it has one.
func (k sigvecKey) public() map[string]any {
	if k.def.kid == "" {
		return sigkeyCloneJWK(k.key.public)
	}
	return sigkeyCloneJWK(k.key.public, "kid", k.def.kid)
}

func sigvecSeed(id string) []byte {
	sum := sha256.Sum256([]byte(sigvecSeedPrefix + id))
	return sum[:]
}

// sigvecKeys derives every vector key. Ed25519 and ML-DSA-44 seeds, and the
// P-256 and P-384 private scalars, are hashes of the key id; the RSA keys are
// the suite's fixture test keys.
func sigvecKeys(k SigkeyFixture) (map[string]sigvecKey, []SigvecKey, error) {
	keys := map[string]sigvecKey{}
	published := []SigvecKey{}
	for _, def := range sigvecKeyDefs {
		var out sigvecKey
		out.def = def
		label := sigvecSeedPrefix + def.id
		switch def.alg {
		case "Ed25519":
			seed := sigvecSeed(def.id)
			out.key = sigkeyEd25519(hex.EncodeToString(seed))
			out.signer = ed25519.NewKeyFromSeed(seed)
			out.published = SigvecKey{SeedHex: hex.EncodeToString(seed), Derivation: fmt.Sprintf("seed = SHA-256(%q)", label)}
			out.published.PrivateJWK = sigkeyCloneJWK(out.key.public, "d", sigkeyB64.EncodeToString(seed))
		case "ML-DSA-44":
			seed := sigvecSeed(def.id)
			key, err := sigkeyMLDSA44(hex.EncodeToString(seed))
			if err != nil {
				return nil, nil, err
			}
			out.key = key
			out.published = SigvecKey{SeedHex: hex.EncodeToString(seed), Derivation: fmt.Sprintf("FIPS 204 seed xi = SHA-256(%q)", label)}
		case "ES256", "ES384":
			curve, scalar := ecdh.P256(), sha256.Sum256([]byte(label))
			raw := scalar[:]
			if def.alg == "ES384" {
				sum := sha512.Sum384([]byte(label))
				curve, raw = ecdh.P384(), sum[:]
			}
			exchange, err := curve.NewPrivateKey(raw)
			if err != nil {
				return nil, nil, err
			}
			der, err := x509.MarshalPKCS8PrivateKey(exchange)
			if err != nil {
				return nil, nil, err
			}
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, nil, err
			}
			private := parsed.(*ecdsa.PrivateKey)
			if out.key, err = sigkeyECDSA(def.alg, private); err != nil {
				return nil, nil, err
			}
			out.signer = private
			hash := "SHA-256"
			if def.alg == "ES384" {
				hash = "SHA-384"
			}
			out.published = SigvecKey{PKCS8: base64.StdEncoding.EncodeToString(der), Derivation: fmt.Sprintf("private scalar d = %s(%q)", hash, label)}
			out.published.PrivateJWK = sigkeyCloneJWK(out.key.public, "d", sigkeyB64.EncodeToString(raw))
		case "RS256", "PS256":
			entry := k.Keys[def.fixture]
			der, err := base64.StdEncoding.DecodeString(entry.PKCS8)
			if err != nil {
				return nil, nil, err
			}
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, nil, err
			}
			private := parsed.(*rsa.PrivateKey)
			out.key = sigkeyRSA(def.alg, private)
			out.signer = private
			b := func(n *big.Int) string { return sigkeyB64.EncodeToString(n.Bytes()) }
			out.published = SigvecKey{PKCS8: entry.PKCS8, Derivation: "the aauth-conformance fixture's " + def.fixture + " test key (fixture.json extensions.sigkey.keys)"}
			out.published.PrivateJWK = sigkeyCloneJWK(out.key.public, "d", b(private.D), "p", b(private.Primes[0]), "q", b(private.Primes[1]),
				"dp", b(private.Precomputed.Dp), "dq", b(private.Precomputed.Dq), "qi", b(private.Precomputed.Qinv))
		default:
			return nil, nil, fmt.Errorf("no derivation for %s", def.alg)
		}
		out.published.ID, out.published.Alg, out.published.PublicJWK = def.id, def.alg, out.public()
		if out.published.PrivateJWK != nil && def.kid != "" {
			out.published.PrivateJWK["kid"] = def.kid
		}
		keys[def.id] = out
		published = append(published, out.published)
	}
	return keys, published, nil
}

// sigvecCertificates is the x509 trust: an Ed25519 root, one end-entity
// certificate per x509 vector key, and the root's current, empty CRL. Ed25519
// signatures are deterministic, so the DER bytes are reproducible.
type sigvecCertificates struct {
	root   []byte
	crl    []byte
	leaves map[string][]byte
}

func sigvecMakeCertificates(keys map[string]sigvecKey) (sigvecCertificates, error) {
	out := sigvecCertificates{leaves: map[string][]byte{}}
	now := time.Unix(sigvecNow, 0).UTC()
	ca := keys["ca-ed25519"]
	caPrivate := ca.signer.(ed25519.PrivateKey)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Signature-Key Test Vectors Root"},
		NotBefore:             now.Add(-30 * 24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	root, err := x509.CreateCertificate(nil, rootTemplate, rootTemplate, caPrivate.Public(), caPrivate)
	if err != nil {
		return out, err
	}
	parsedRoot, err := x509.ParseCertificate(root)
	if err != nil {
		return out, err
	}
	out.root = root
	for serial, id := range []string{"x509-ed25519", "x509-es256"} {
		leaf := keys[id]
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(serial + 2)),
			Subject:               pkix.Name{CommonName: "signer.example"},
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		var public any
		switch s := leaf.signer.(type) {
		case ed25519.PrivateKey:
			public = s.Public()
		case *ecdsa.PrivateKey:
			public = &s.PublicKey
		}
		der, err := x509.CreateCertificate(nil, template, parsedRoot, public, caPrivate)
		if err != nil {
			return out, err
		}
		out.leaves[id] = der
	}
	crl, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}, parsedRoot, caPrivate)
	if err != nil {
		return out, err
	}
	out.crl = crl
	return out, nil
}

func sigvecPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// sigvecX5U is the certificate URL of an x509 vector key.
func sigvecX5U(id string) string { return "https://certs.example/" + id + ".pem" }

func sigvecJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func sigvecDocument(url string, v any) SigvecDocument {
	return SigvecDocument{URL: url, ContentType: "application/json", Body: sigvecJSON(v)}
}

// sigvecDefaultDocuments is every document the verifier can fetch unless a
// vector replaces one: the Agent Provider's and the signer's metadata and
// JWKS, the direct JWKS and the x509 chains.
func sigvecDefaultDocuments(keys map[string]sigvecKey, certs sigvecCertificates) []SigvecDocument {
	jwks := func(ids ...string) map[string]any {
		set := []any{}
		for _, id := range ids {
			set = append(set, keys[id].public())
		}
		return map[string]any{"keys": set}
	}
	return []SigvecDocument{
		sigvecDocument(sigvecAP+"/.well-known/aauth-agent.json", map[string]any{"issuer": sigvecAP, "jwks_uri": sigvecAP + "/.well-known/jwks.json"}),
		sigvecDocument(sigvecAP+"/.well-known/jwks.json", jwks("ap-ed25519")),
		sigvecDocument(sigvecSigner+"/.well-known/"+sigvecSignerDWK, map[string]any{"issuer": sigvecSigner, "jwks_uri": sigvecSigner + "/.well-known/jwks.json"}),
		sigvecDocument(sigvecSigner+"/.well-known/jwks.json", jwks("signer-ed25519", "signer-es256")),
		sigvecDocument(sigvecJWKSURL, jwks("signer-ed25519", "signer-es256")),
		{URL: sigvecX5U("x509-ed25519"), ContentType: "application/pem-certificate-chain", Body: sigvecPEM(certs.leaves["x509-ed25519"])},
		{URL: sigvecX5U("x509-es256"), ContentType: "application/pem-certificate-chain", Body: sigvecPEM(certs.leaves["x509-es256"])},
	}
}
