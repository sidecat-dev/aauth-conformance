package conformance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// sigkeyKey is one independent harness key: its public JWK (with alg, without
// kid) and JOSE-style signing and verification of a raw message, as RFC 9421
// Section 3.3.7 uses for HTTP Message Signatures and RFC 7518 for JWS.
type sigkeyKey struct {
	alg    string
	public map[string]any
	sign   func(message []byte) ([]byte, error)
	verify func(message, signature []byte) bool
}

var sigkeyB64 = base64.RawURLEncoding

func sigkeyEd25519(seed string) sigkeyKey {
	private := seedKey(seed)
	public := private.Public().(ed25519.PublicKey)
	return sigkeyKey{
		alg:    "Ed25519",
		public: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": sigkeyB64.EncodeToString(public), "alg": "Ed25519"},
		sign:   func(message []byte) ([]byte, error) { return ed25519.Sign(private, message), nil },
		verify: func(message, signature []byte) bool { return ed25519.Verify(public, message, signature) },
	}
}

// sigkeyFixtureKey returns the ES256, ES384, RS256 or PS256 fixture key.
func sigkeyFixtureKey(k SigkeyFixture, alg string) (sigkeyKey, error) {
	entry, ok := k.Keys[alg]
	if !ok {
		return sigkeyKey{}, fmt.Errorf("no fixture key for %s", alg)
	}
	der, err := base64.StdEncoding.DecodeString(entry.PKCS8)
	if err != nil {
		return sigkeyKey{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return sigkeyKey{}, err
	}
	switch alg {
	case "ES256", "ES384":
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return sigkeyKey{}, fmt.Errorf("%s fixture key is not ECDSA", alg)
		}
		return sigkeyECDSA(alg, key)
	case "RS256", "PS256":
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return sigkeyKey{}, fmt.Errorf("%s fixture key is not RSA", alg)
		}
		return sigkeyRSA(alg, key), nil
	}
	return sigkeyKey{}, fmt.Errorf("unsupported fixture algorithm %s", alg)
}

func sigkeyECDSA(alg string, key *ecdsa.PrivateKey) (sigkeyKey, error) {
	size, hash, crv := 32, crypto.SHA256, "P-256"
	if alg == "ES384" {
		size, hash, crv = 48, crypto.SHA384, "P-384"
	}
	exchange, err := key.PublicKey.ECDH()
	if err != nil {
		return sigkeyKey{}, err
	}
	point := exchange.Bytes()
	if len(point) != 1+2*size || point[0] != 4 {
		return sigkeyKey{}, fmt.Errorf("%s fixture key is not on %s", alg, crv)
	}
	digest := func(message []byte) []byte {
		h := hash.New()
		h.Write(message)
		return h.Sum(nil)
	}
	return sigkeyKey{
		alg:    alg,
		public: map[string]any{"kty": "EC", "crv": crv, "x": sigkeyB64.EncodeToString(point[1 : 1+size]), "y": sigkeyB64.EncodeToString(point[1+size:]), "alg": alg},
		sign: func(message []byte) ([]byte, error) {
			r, s, err := ecdsa.Sign(rand.Reader, key, digest(message))
			if err != nil {
				return nil, err
			}
			out := make([]byte, 2*size)
			r.FillBytes(out[:size])
			s.FillBytes(out[size:])
			return out, nil
		},
		verify: func(message, signature []byte) bool {
			if len(signature) != 2*size {
				return false
			}
			r, s := new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])
			return ecdsa.Verify(&key.PublicKey, digest(message), r, s)
		},
	}, nil
}

func sigkeyRSA(alg string, key *rsa.PrivateKey) sigkeyKey {
	digest := func(message []byte) []byte {
		sum := sha256.Sum256(message)
		return sum[:]
	}
	pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	return sigkeyKey{
		alg:    alg,
		public: map[string]any{"kty": "RSA", "n": sigkeyB64.EncodeToString(key.N.Bytes()), "e": sigkeyB64.EncodeToString(big.NewInt(int64(key.E)).Bytes()), "alg": alg},
		sign: func(message []byte) ([]byte, error) {
			if alg == "PS256" {
				return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest(message), pss)
			}
			return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest(message))
		},
		verify: func(message, signature []byte) bool {
			if alg == "PS256" {
				return rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest(message), signature, pss) == nil
			}
			return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest(message), signature) == nil
		},
	}
}

// sigkeySymmetric is an HS256 key: a shared secret that no Signature-Key
// scheme may convey (signature-key "Algorithm Determination").
func sigkeySymmetric() sigkeyKey {
	secret := sha512.Sum512_256([]byte("aauth-conformance symmetric fixture"))
	return sigkeyKey{
		alg:    "HS256",
		public: map[string]any{"kty": "oct", "k": sigkeyB64.EncodeToString(secret[:]), "alg": "HS256"},
		sign: func(message []byte) ([]byte, error) {
			mac := hmac.New(sha256.New, secret[:])
			mac.Write(message)
			return mac.Sum(nil), nil
		},
		verify: func(message, signature []byte) bool { return false },
	}
}

// sigkeyAlgKey returns the harness key for an algorithm: Ed25519 from seed,
// ML-DSA-44 from the post-quantum seed, the others from the fixture.
func sigkeyAlgKey(k SigkeyFixture, alg, ed25519Seed string) (sigkeyKey, error) {
	switch alg {
	case "Ed25519":
		return sigkeyEd25519(ed25519Seed), nil
	case "ML-DSA-44":
		return sigkeyMLDSA44(k.PQSeed)
	}
	return sigkeyFixtureKey(k, alg)
}

func sigkeyCloneJWK(key map[string]any, extra ...any) map[string]any {
	out := map[string]any{}
	for name, value := range key {
		out[name] = value
	}
	for i := 0; i+1 < len(extra); i += 2 {
		name := extra[i].(string)
		if extra[i+1] == nil {
			delete(out, name)
		} else {
			out[name] = extra[i+1]
		}
	}
	return out
}

// sigkeyJWS signs a compact JWS with the harness key, which need not match
// the header alg (refusal cases deliberately disagree).
func sigkeyJWS(header, claims map[string]any, key sigkeyKey) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := sigkeyB64.EncodeToString(h) + "." + sigkeyB64.EncodeToString(c)
	signature, err := key.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + sigkeyB64.EncodeToString(signature), nil
}

// sigkeyThumbprint is the RFC 7638 SHA-256 thumbprint over a public JWK's
// required members.
func sigkeyThumbprint(key map[string]any) string {
	var members []string
	switch key["kty"] {
	case "OKP":
		members = []string{"crv", "kty", "x"}
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	}
	ordered := "{"
	for i, name := range members {
		value, _ := json.Marshal(key[name])
		if i > 0 {
			ordered += ","
		}
		ordered += fmt.Sprintf("%q:%s", name, value)
	}
	sum := sha256.Sum256([]byte(ordered + "}"))
	return sigkeyB64.EncodeToString(sum[:])
}
