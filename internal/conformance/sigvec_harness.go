package conformance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dunglas/httpsfv"
)

// This file is the harness's own reading of the drafts: it builds signature
// bases, conveys and resolves keys and checks signatures with the Go standard
// library only. No AAuth library is used here.

// sigvecHeader looks up a header field by case-insensitive name.
func sigvecHeader(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// sigvecParams returns the label's Signature-Input inner list, serialized as
// RFC 9421 Section 2.3 requires for @signature-params, and its components.
func sigvecParams(signatureInput, label string) (string, []string, *httpsfv.Params, error) {
	dictionary, err := httpsfv.UnmarshalDictionary([]string{signatureInput})
	if err != nil {
		return "", nil, nil, fmt.Errorf("Signature-Input: %w", err)
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return "", nil, nil, fmt.Errorf("Signature-Input has no %s", label)
	}
	list, ok := member.(httpsfv.InnerList)
	if !ok {
		return "", nil, nil, fmt.Errorf("Signature-Input %s is not an inner list", label)
	}
	components := []string{}
	for _, item := range list.Items {
		name, ok := item.Value.(string)
		if !ok || (item.Params != nil && len(item.Params.Names()) > 0) {
			return "", nil, nil, fmt.Errorf("component identifiers must be plain strings")
		}
		components = append(components, name)
	}
	serialized, err := httpsfv.Marshal(list)
	return serialized, components, list.Params, err
}

// SigvecBase builds the RFC 9421 signature base for one label of a received
// request: the derived components @method, @authority, @path and @query and
// plain header fields, then @signature-params.
func SigvecBase(received SigvecRequest, label string) (string, error) {
	signatureInput, ok := sigvecHeader(received.Headers, "Signature-Input")
	if !ok {
		return "", fmt.Errorf("no Signature-Input")
	}
	params, components, _, err := sigvecParams(signatureInput, label)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(received.URL)
	if err != nil {
		return "", err
	}
	lines := []string{}
	for _, component := range components {
		var value string
		switch component {
		case "@method":
			value = strings.ToUpper(received.Method)
		case "@authority":
			value = strings.ToLower(target.Host)
			if target.Port() == "443" {
				value = strings.ToLower(target.Hostname())
			}
		case "@path":
			value = target.EscapedPath()
			if value == "" {
				value = "/"
			}
		case "@query":
			value = "?" + target.RawQuery
		default:
			if strings.HasPrefix(component, "@") {
				return "", fmt.Errorf("derived component %s is outside this harness", component)
			}
			field, ok := sigvecHeader(received.Headers, component)
			if !ok {
				return "", fmt.Errorf("covered field %s is absent", component)
			}
			value = strings.Trim(field, " \t")
		}
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	return strings.Join(append(lines, `"@signature-params": `+params), "\n"), nil
}

// sigvecSignatureBytes returns the label's signature bytes.
func sigvecSignatureBytes(received SigvecRequest, label string) ([]byte, error) {
	value, ok := sigvecHeader(received.Headers, "Signature")
	if !ok {
		return nil, fmt.Errorf("no Signature")
	}
	dictionary, err := httpsfv.UnmarshalDictionary([]string{value})
	if err != nil {
		return nil, err
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return nil, fmt.Errorf("Signature has no %s", label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("Signature %s is not an item", label)
	}
	bytes, ok := item.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("Signature %s is not a byte sequence", label)
	}
	return bytes, nil
}

// sigvecMember returns the selected Signature-Key member: its scheme token
// and its parameters by name.
func sigvecMember(received SigvecRequest, label string) (string, map[string]any, error) {
	value, ok := sigvecHeader(received.Headers, "Signature-Key")
	if !ok {
		return "", nil, fmt.Errorf("no Signature-Key")
	}
	dictionary, err := httpsfv.UnmarshalDictionary([]string{value})
	if err != nil {
		return "", nil, err
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return "", nil, fmt.Errorf("Signature-Key has no %s", label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return "", nil, fmt.Errorf("Signature-Key %s is not an item", label)
	}
	scheme, ok := item.Value.(httpsfv.Token)
	if !ok {
		return "", nil, fmt.Errorf("Signature-Key %s scheme is not a token", label)
	}
	params := map[string]any{}
	if item.Params != nil {
		for _, name := range item.Params.Names() {
			params[name], _ = item.Params.Get(name)
		}
	}
	return string(scheme), params, nil
}

// sigvecJWTParts decodes a compact JWT's header and payload without
// verifying it.
func sigvecJWTParts(compact string) (map[string]any, map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("JWT is not compact")
	}
	decode := func(s string) (map[string]any, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var v map[string]any
		return v, json.Unmarshal(b, &v)
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payload, err := decode(parts[1])
	return header, payload, err
}

// sigvecDocumentJSON finds and decodes one environment document.
func sigvecDocumentJSON(env SigvecEnvironment, target string) (map[string]any, error) {
	for _, d := range env.Documents {
		if d.URL == target {
			var v map[string]any
			return v, json.Unmarshal([]byte(d.Body), &v)
		}
	}
	return nil, fmt.Errorf("no document at %s", target)
}

func sigvecSelect(set map[string]any, kid string) (map[string]any, error) {
	keys, _ := set["keys"].([]any)
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && m["kid"] == kid {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no key %q", kid)
}

// sigvecDiscovered follows {issuer}/.well-known/{dwk} to its JWKS and selects kid.
func sigvecDiscovered(env SigvecEnvironment, issuer, dwk, kid string) (map[string]any, []string, error) {
	metadataURL := issuer + "/.well-known/" + dwk
	metadata, err := sigvecDocumentJSON(env, metadataURL)
	if err != nil {
		return nil, nil, err
	}
	if metadata["issuer"] != issuer {
		return nil, []string{metadataURL}, fmt.Errorf("metadata issuer is not %s", issuer)
	}
	jwksURI, _ := metadata["jwks_uri"].(string)
	set, err := sigvecDocumentJSON(env, jwksURI)
	if err != nil {
		return nil, []string{metadataURL}, err
	}
	key, err := sigvecSelect(set, kid)
	return key, []string{metadataURL, jwksURI}, err
}

// SigvecConveyedKey resolves the public key the selected member conveys or
// references, and the documents resolution read.
func SigvecConveyedKey(env SigvecEnvironment, received SigvecRequest, label string) (map[string]any, []string, error) {
	scheme, params, err := sigvecMember(received, label)
	if err != nil {
		return nil, nil, err
	}
	text := func(name string) string { s, _ := params[name].(string); return s }
	switch scheme {
	case "hwk":
		key := map[string]any{}
		for name, value := range params {
			key[name] = value
		}
		return key, nil, nil
	case "jwt", "jkt-jwt":
		header, payload, err := sigvecJWTParts(text("jwt"))
		if err != nil {
			return nil, nil, err
		}
		cnf, _ := payload["cnf"].(map[string]any)
		key, _ := cnf["jwk"].(map[string]any)
		if key == nil {
			return nil, nil, fmt.Errorf("JWT has no cnf.jwk")
		}
		var resolves []string
		if scheme == "jwt" {
			iss, _ := payload["iss"].(string)
			dwk, _ := payload["dwk"].(string)
			kid, _ := header["kid"].(string)
			_, resolves, _ = sigvecDiscovered(env, iss, dwk, kid)
		}
		return key, resolves, nil
	case "jwks_uri":
		return sigvecDiscovered(env, text("id"), text("dwk"), text("kid"))
	case "jwks":
		set, err := sigvecDocumentJSON(env, text("url"))
		if err != nil {
			return nil, nil, err
		}
		key, err := sigvecSelect(set, text("kid"))
		return key, []string{text("url")}, err
	case "self-jwt":
		header, payload, err := sigvecJWTParts(text("jwt"))
		if err != nil {
			return nil, nil, err
		}
		iss, _ := payload["iss"].(string)
		dwk, _ := payload["dwk"].(string)
		kid, _ := header["kid"].(string)
		return sigvecDiscovered(env, iss, dwk, kid)
	case "x509":
		x5u := text("x5u")
		for _, d := range env.Documents {
			if d.URL != x5u {
				continue
			}
			block, _ := pem.Decode([]byte(d.Body))
			if block == nil {
				return nil, nil, fmt.Errorf("x5u is not PEM")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			key, err := sigvecCertificateJWK(certificate)
			return key, []string{x5u}, err
		}
		return nil, nil, fmt.Errorf("no document at %s", x5u)
	}
	return nil, nil, fmt.Errorf("the harness resolves no key for scheme %s", scheme)
}

func sigvecCertificateJWK(certificate *x509.Certificate) (map[string]any, error) {
	switch public := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": sigkeyB64.EncodeToString(public), "alg": "Ed25519"}, nil
	case *ecdsa.PublicKey:
		if public.Curve != elliptic.P256() {
			return nil, fmt.Errorf("certificate key is not P-256")
		}
		point, err := public.ECDH()
		if err != nil {
			return nil, err
		}
		b := point.Bytes()
		return map[string]any{"kty": "EC", "crv": "P-256", "x": sigkeyB64.EncodeToString(b[1:33]), "y": sigkeyB64.EncodeToString(b[33:]), "alg": "ES256"}, nil
	}
	return nil, fmt.Errorf("certificate key type is outside this harness")
}

// SigvecVerifyJWK verifies a JOSE-style signature over message with a public
// JWK, by its alg: Ed25519, ES256, ES384, RS256 or PS256 (RFC 9421 Section
// 3.3.7). It answers false for any other alg or an unusable key.
func SigvecVerifyJWK(key map[string]any, message, signature []byte) bool {
	text := func(name string) []byte {
		s, _ := key[name].(string)
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return b
	}
	switch alg, _ := key["alg"].(string); alg {
	case "Ed25519":
		x := text("x")
		return key["kty"] == "OKP" && key["crv"] == "Ed25519" && len(x) == ed25519.PublicKeySize && ed25519.Verify(x, message, signature)
	case "ES256", "ES384":
		curve, size, crv := elliptic.P256(), 32, "P-256"
		var digest []byte
		if alg == "ES384" {
			curve, size, crv = elliptic.P384(), 48, "P-384"
			sum := sha512.Sum384(message)
			digest = sum[:]
		} else {
			sum := sha256.Sum256(message)
			digest = sum[:]
		}
		x, y := text("x"), text("y")
		if key["kty"] != "EC" || key["crv"] != crv || len(x) != size || len(y) != size || len(signature) != 2*size {
			return false
		}
		public := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		return ecdsa.Verify(public, digest, new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:]))
	case "RS256", "PS256":
		n, e := text("n"), text("e")
		if key["kty"] != "RSA" || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return false
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		sum := sha256.Sum256(message)
		if alg == "PS256" {
			return rsa.VerifyPSS(public, crypto.SHA256, sum[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
		}
		return rsa.VerifyPKCS1v15(public, crypto.SHA256, sum[:], signature) == nil
	}
	return false
}

// sigvecExpectedMember is the Signature-Key member value (without label) the
// drafts give for a part, in the order of the drafts' examples.
func (b *sigvecBuild) expectedMember(p sigvecPart) string {
	if p.Member != "" {
		return p.Member
	}
	quote := func(s string) string { return fmt.Sprintf("%q", s) }
	switch p.Scheme {
	case "hwk":
		return hwkMember(b.keys[p.Key].key.public)
	case "jwt", "jkt-jwt":
		member := p.Scheme + ";jwt=" + quote(p.JWT)
		if p.Cache {
			member += ";cache"
		}
		return member
	case "self-jwt":
		return "self-jwt;jwt=" + quote(p.JWT)
	case "jwks_uri":
		return "jwks_uri;id=" + quote(p.ID) + ";dwk=" + quote(p.DWK) + ";kid=" + quote(p.Kid)
	case "jwks":
		return "jwks;url=" + quote(p.URL) + ";kid=" + quote(p.Kid)
	case "x509":
		sum := sha256.Sum256(p.Cert)
		return "x509;x5u=" + quote(p.X5U) + ";x5t=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	case "cached":
		return "cached;cid=" + quote(p.CID)
	}
	return ""
}

// sigvecRequiredComponents is the covered set a signer must produce: the
// AAuth base set, @query with a query, and content-digest and content-type
// with content (protocol "Covered Components").
func sigvecRequiredComponents(pre SigvecRequest) []string {
	required := []string{"@method", "@authority", "@path"}
	if target, err := url.Parse(pre.URL); err == nil && target.RawQuery != "" {
		required = append(required, "@query")
	}
	if pre.Body != "" {
		required = append(required, "content-digest")
		if _, ok := sigvecHeader(pre.Headers, "Content-Type"); ok {
			required = append(required, "content-type")
		}
	}
	return append(required, "signature-key")
}

func sigvecContentDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// harnessSign signs a case with independent code: used only for the cases
// no conforming signer produces.
func (b *sigvecBuild) harnessSign(pre SigvecRequest, parts []sigvecPart, covered []string, created int64, nonce string) (map[string]string, error) {
	signed := map[string]string{}
	members := []string{}
	for _, p := range parts {
		members = append(members, p.Label+"="+b.expectedMember(p))
	}
	signed["Signature-Key"] = strings.Join(members, ", ")
	if pre.Body != "" {
		signed["Content-Digest"] = sigvecContentDigest(pre.Body)
	}
	if covered == nil {
		covered = sigvecRequiredComponents(pre)
	}
	params := fmt.Sprintf("(%s);created=%d", sigkeyQuoted(covered), created)
	if nonce != "" {
		params += fmt.Sprintf(";nonce=%q", nonce)
	}
	inputs, signatures := []string{}, []string{}
	for _, p := range parts {
		inputs = append(inputs, p.Label+"="+params)
	}
	signed["Signature-Input"] = strings.Join(inputs, ", ")
	received := SigvecRequest{Method: pre.Method, URL: pre.URL, Body: pre.Body, Headers: map[string]string{}}
	for k, v := range pre.Headers {
		received.Headers[k] = v
	}
	for k, v := range signed {
		received.Headers[k] = v
	}
	for _, p := range parts {
		base, err := SigvecBase(received, p.Label)
		if err != nil {
			return nil, err
		}
		key := sigkeySymmetric()
		if p.Key != "" {
			key = b.keys[p.Key].key
		}
		signature, err := key.sign([]byte(base))
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, p.Label+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	}
	signed["Signature"] = strings.Join(signatures, ", ")
	return signed, nil
}

// checkLibraryOutput checks one library's signed request against the drafts
// with independent code. It returns a note when the bytes differ from the
// drafts' example serialization but the structured value is the same.
func (b *sigvecBuild) checkLibraryOutput(pre SigvecRequest, parts []sigvecPart, created int64, nonce string, signed map[string]string) (string, error) {
	received := SigvecRequest{Method: pre.Method, URL: pre.URL, Body: pre.Body, Headers: map[string]string{}}
	for k, v := range pre.Headers {
		received.Headers[k] = v
	}
	for k, v := range signed {
		received.Headers[k] = v
	}
	note := ""
	expected := []string{}
	for _, p := range parts {
		expected = append(expected, p.Label+"="+b.expectedMember(p))
	}
	if got := signed["Signature-Key"]; got != strings.Join(expected, ", ") {
		want, _ := httpsfv.UnmarshalDictionary([]string{strings.Join(expected, ", ")})
		have, err := httpsfv.UnmarshalDictionary([]string{got})
		if err != nil || want == nil || !slices.Equal(want.Names(), have.Names()) {
			return "", fmt.Errorf("Signature-Key %q, expected %q", got, strings.Join(expected, ", "))
		}
		for _, p := range parts {
			ws, wp, _ := sigvecMember(SigvecRequest{Headers: map[string]string{"Signature-Key": strings.Join(expected, ", ")}}, p.Label)
			hs, hp, _ := sigvecMember(received, p.Label)
			if ws != hs || !jsonEqual(wp, hp) {
				return "", fmt.Errorf("Signature-Key member %s is %q, expected %q", p.Label, got, strings.Join(expected, ", "))
			}
		}
		note = "Signature-Key parameters are serialized in a different order from the drafts' examples"
	}
	if pre.Body != "" && signed["Content-Digest"] != sigvecContentDigest(pre.Body) {
		return "", fmt.Errorf("Content-Digest %q, expected %q", signed["Content-Digest"], sigvecContentDigest(pre.Body))
	}
	required := sigvecRequiredComponents(pre)
	for _, p := range parts {
		_, components, params, err := sigvecParams(signed["Signature-Input"], p.Label)
		if err != nil {
			return "", err
		}
		for _, r := range required {
			if !slices.Contains(components, r) {
				return "", fmt.Errorf("label %s does not cover %s", p.Label, r)
			}
		}
		if len(components) != len(required) {
			return "", fmt.Errorf("label %s covers %v, expected exactly %v", p.Label, components, required)
		}
		names := params.Names()
		want := []string{"created"}
		if nonce != "" {
			want = append(want, "nonce")
		}
		if !slices.Equal(names, want) {
			return "", fmt.Errorf("label %s has parameters %v, expected %v", p.Label, names, want)
		}
		if c, _ := params.Get("created"); c != created {
			return "", fmt.Errorf("label %s created %v, expected %d", p.Label, c, created)
		}
		if n, _ := params.Get("nonce"); nonce != "" && n != nonce {
			return "", fmt.Errorf("label %s nonce %v, expected %q", p.Label, n, nonce)
		}
		base, err := SigvecBase(received, p.Label)
		if err != nil {
			return "", err
		}
		signature, err := sigvecSignatureBytes(received, p.Label)
		if err != nil {
			return "", err
		}
		if !b.keys[p.Key].key.verify([]byte(base), signature) {
			return "", fmt.Errorf("label %s signature does not verify under %s over the harness's signature base", p.Label, p.Key)
		}
	}
	return note, nil
}

// sigvecCanonicalHeaders maps a launcher's header names to canonical form.
func sigvecCanonicalHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}
