package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// sigvecBuild holds the derived keys, certificates and documents, and the
// assertions to reuse when re-checking a published file.
type sigvecBuild struct {
	keys      map[string]sigvecKey
	certs     sigvecCertificates
	published []SigvecKey
	defaults  []SigvecDocument
	reuse     map[string]string // case id -> published compact JWT
	current   string
}

func newSigvecBuild(f Fixture) (*sigvecBuild, error) {
	k, err := sigkeyFixture(f)
	if err != nil {
		return nil, err
	}
	keys, published, err := sigvecKeys(k)
	if err != nil {
		return nil, err
	}
	certs, err := sigvecMakeCertificates(keys)
	if err != nil {
		return nil, err
	}
	return &sigvecBuild{keys: keys, certs: certs, published: published, defaults: sigvecDefaultDocuments(keys, certs), reuse: map[string]string{}}, nil
}

// SigvecSignJob asks a library to sign one request.
type SigvecSignJob struct {
	Op         string           `json:"op"`
	Created    int64            `json:"created"`
	Nonce      string           `json:"nonce,omitempty"`
	Request    SigvecRequest    `json:"request"`
	Signatures []SigvecSignPart `json:"signatures"`
}

// SigvecSignPart is one labeled signature: the private key and the
// Signature-Key member parameters the library is to present.
type SigvecSignPart struct {
	Label       string `json:"label"`
	Alg         string `json:"alg"`
	Kid         string `json:"kid,omitempty"`
	SeedHex     string `json:"seed_hex,omitempty"`
	PKCS8       string `json:"pkcs8_base64,omitempty"`
	Scheme      string `json:"scheme"`
	JWT         string `json:"jwt,omitempty"`
	Cache       bool   `json:"cache,omitempty"`
	ID          string `json:"id,omitempty"`
	DWK         string `json:"dwk,omitempty"`
	URL         string `json:"url,omitempty"`
	X5U         string `json:"x5u,omitempty"`
	Certificate string `json:"certificate_der_base64,omitempty"`
	X5T         string `json:"x5t_base64,omitempty"`
	CID         string `json:"cid,omitempty"`
}

// SigvecSigner signs a job with one library. A refusal is reported as an
// error; ok is false when the library has no API for the job.
type SigvecSigner func(ctx context.Context, job SigvecSignJob) (headers map[string]string, offered bool, err error)

// SigvecFinding is one disagreement or refusal seen while generating.
type SigvecFinding struct {
	Vector  string `json:"vector"`
	Library string `json:"library"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
}

// SigvecGeneration is the result of one generation run.
type SigvecGeneration struct {
	File     SigvecFile
	Findings []SigvecFinding
	// Agreement lists, per vector, which libraries produced identical bytes.
	Agreement []SigvecAgreement
}
type SigvecAgreement struct {
	Case       string   `json:"case"`
	Category   int      `json:"category"`
	Signed     []string `json:"signed"`
	Refused    []string `json:"refused,omitempty"`
	Identical  bool     `json:"identical"`
	SameBase   bool     `json:"same_base"`
	Published  []string `json:"published"`
	Difference string   `json:"difference,omitempty"`
}

func (b *sigvecBuild) signJob(c sigvecCase, pre SigvecRequest, parts []sigvecPart, created int64) SigvecSignJob {
	job := SigvecSignJob{Op: "sign", Created: created, Nonce: c.Nonce, Request: pre}
	for _, p := range parts {
		k := b.keys[p.Key]
		part := SigvecSignPart{Label: p.Label, Alg: k.def.alg, Kid: k.def.kid, SeedHex: k.published.SeedHex, PKCS8: k.published.PKCS8, Scheme: p.Scheme, JWT: p.JWT, Cache: p.Cache, ID: p.ID, DWK: p.DWK, URL: p.URL, X5U: p.X5U, CID: p.CID}
		if p.Scheme == "jwks_uri" || p.Scheme == "jwks" {
			part.Kid = p.Kid
		}
		if len(p.Cert) > 0 {
			part.Certificate = base64.StdEncoding.EncodeToString(p.Cert)
			digest := sha256.Sum256(p.Cert)
			part.X5T = base64.StdEncoding.EncodeToString(digest[:])
		}
		job.Signatures = append(job.Signatures, part)
	}
	return job
}

func sigvecDeterministic(alg string) bool {
	return slices.Contains([]string{"Ed25519", "RS256", "HS256", "ML-DSA-44"}, alg)
}

// sigvecConsistent reports whether a public JWK is well formed for its alg,
// so that a failed verification says the signature is wrong, not the key.
func sigvecConsistent(key map[string]any) bool {
	switch key["alg"] {
	case "Ed25519":
		return key["kty"] == "OKP" && key["crv"] == "Ed25519"
	case "ES256":
		return key["kty"] == "EC" && key["crv"] == "P-256"
	case "ES384":
		return key["kty"] == "EC" && key["crv"] == "P-384"
	case "RS256", "PS256":
		return key["kty"] == "RSA"
	}
	return false
}

func sigvecShort(library string) string { return strings.TrimPrefix(library, "aauth-") }

// sigvecSignedFields returns the header fields signing added or changed.
func sigvecSignedFields(pre SigvecRequest, headers map[string]string) map[string]string {
	signed := map[string]string{}
	for name, value := range sigvecCanonicalHeaders(headers) {
		if before, ok := sigvecHeader(pre.Headers, name); ok && before == value {
			continue
		}
		if slices.Contains([]string{"Host", "Content-Length"}, name) {
			continue
		}
		signed[name] = value
	}
	return signed
}

func sigvecMutate(mutation string, signed map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range signed {
		out[k] = v
	}
	switch mutation {
	case "":
	case "tamper-signature":
		value := out["Signature"]
		prefix := sigvecLabel + "=:"
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, prefix), ":"))
		if !strings.HasPrefix(value, prefix) || err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("cannot tamper %q", value)
		}
		raw[len(raw)/2] ^= 0x01
		out["Signature"] = prefix + base64.StdEncoding.EncodeToString(raw) + ":"
	case "rename-label":
		for _, name := range []string{"Signature-Input", "Signature"} {
			if !strings.HasPrefix(out[name], "sig1=") {
				return nil, fmt.Errorf("%s is not labelled sig1", name)
			}
			out[name] = sigvecLabel + strings.TrimPrefix(out[name], "sig1")
		}
	default:
		return nil, fmt.Errorf("unknown mutation %s", mutation)
	}
	return out, nil
}

// Generate builds every vector. Each case is signed by every library it
// names; the harness checks each output against the drafts and the libraries
// against each other. A deterministic case whose libraries agree byte for
// byte is published once; otherwise each library's output is published.
func (b *sigvecBuild) generate(ctx context.Context, signers map[string]SigvecSigner) (SigvecGeneration, error) {
	gen := SigvecGeneration{}
	vectors := []SigvecVector{}
	for _, c := range sigvecCases() {
		b.current = c.ID
		parts, err := c.Parts(b)
		if err != nil {
			return gen, fmt.Errorf("%s: %w", c.ID, err)
		}
		method := c.Method
		if method == "" {
			method = "GET"
		}
		target := sigvecResource
		if c.Query != "" {
			target += "?" + c.Query
		}
		pre := SigvecRequest{Method: method, URL: target, Body: c.Body}
		if c.ContentType != "" {
			pre.Headers = map[string]string{"Content-Type": c.ContentType}
		}
		created := int64(sigvecNow) + c.CreatedOffset
		category := c.Category
		if category == 0 {
			category = 2
			if sigvecDeterministic(c.Alg) {
				category = 3
			}
		}
		type output struct {
			library string
			signed  map[string]string
			note    string
		}
		outputs := []output{}
		agreement := SigvecAgreement{Case: c.ID, Category: category}
		if len(c.Signers) == 0 {
			signed, err := b.harnessSign(pre, parts, c.Covered, created, c.Nonce)
			if err != nil {
				return gen, fmt.Errorf("%s: harness: %w", c.ID, err)
			}
			outputs = append(outputs, output{library: "harness", signed: signed, note: "Signed by the harness: " + c.HarnessReason + "."})
		}
		for _, library := range c.Signers {
			sign, ok := signers[library]
			if !ok {
				continue
			}
			headers, offered, err := sign(ctx, b.signJob(c, pre, parts, created))
			if !offered || err != nil {
				reason := "no API for this job"
				if err != nil {
					reason = err.Error()
				}
				agreement.Refused = append(agreement.Refused, library+": "+reason)
				gen.Findings = append(gen.Findings, SigvecFinding{Vector: c.ID, Library: library, Kind: "not-signed", Detail: reason})
				continue
			}
			signed := sigvecSignedFields(pre, headers)
			note, err := b.checkLibraryOutput(pre, parts, created, c.Nonce, signed)
			if err != nil {
				gen.Findings = append(gen.Findings, SigvecFinding{Vector: c.ID, Library: library, Kind: "harness-check", Detail: err.Error()})
				continue
			}
			if note != "" {
				gen.Findings = append(gen.Findings, SigvecFinding{Vector: c.ID, Library: library, Kind: "serialization", Detail: note})
			}
			agreement.Signed = append(agreement.Signed, library)
			outputs = append(outputs, output{library: library, signed: signed, note: note})
		}
		if len(outputs) == 0 && c.Expect.Outcome != "verify" && len(c.Signers) > 0 {
			// A conforming signer may refuse to produce a request it knows
			// is invalid; the harness then signs the negative itself.
			signed, err := b.harnessSign(pre, parts, c.Covered, created, c.Nonce)
			if err != nil {
				return gen, fmt.Errorf("%s: harness: %w", c.ID, err)
			}
			c.HarnessReason = "every library refused to sign it (" + strings.Join(agreement.Refused, "; ") + ")"
			outputs = append(outputs, output{library: "harness", signed: signed})
		}
		if len(outputs) == 0 {
			gen.Findings = append(gen.Findings, SigvecFinding{Vector: c.ID, Kind: "unpublished", Detail: "no signer produced a checked output"})
			gen.Agreement = append(gen.Agreement, agreement)
			continue
		}
		// Compare the libraries: the base always, the signature too when
		// the algorithm is deterministic.
		agreement.Identical, agreement.SameBase = len(outputs) > 1, len(outputs) > 1
		for _, o := range outputs[1:] {
			for _, name := range []string{"Signature-Input", "Signature-Key", "Content-Digest"} {
				if o.signed[name] != outputs[0].signed[name] {
					agreement.SameBase, agreement.Identical = false, false
					agreement.Difference = fmt.Sprintf("%s differs: %s %q, %s %q", name, outputs[0].library, outputs[0].signed[name], o.library, o.signed[name])
				}
			}
			if o.signed["Signature"] != outputs[0].signed["Signature"] {
				agreement.Identical = false
				if sigvecDeterministic(c.Alg) && agreement.SameBase {
					agreement.Difference = fmt.Sprintf("deterministic %s signature differs: %s %q, %s %q", c.Alg, outputs[0].library, outputs[0].signed["Signature"], o.library, o.signed["Signature"])
				}
			}
		}
		if len(outputs) > 1 && sigvecDeterministic(c.Alg) && !agreement.Identical {
			gen.Findings = append(gen.Findings, SigvecFinding{Vector: c.ID, Kind: "disagreement", Detail: agreement.Difference})
		}
		publish := outputs
		reproduced := map[string][]string{}
		if c.Mutation != "" || c.Expect.Outcome != "verify" || agreement.Identical {
			publish = outputs[:1]
			if agreement.Identical {
				for _, o := range outputs[1:] {
					reproduced[outputs[0].library] = append(reproduced[outputs[0].library], o.library)
				}
			}
		}
		for _, o := range publish {
			id := c.ID
			if len(publish) > 1 {
				id += "." + sigvecShort(o.library)
			}
			agreement.Published = append(agreement.Published, id)
			v, err := b.vector(c, id, category, pre, parts, o.library, o.signed, reproduced[o.library], o.note, agreement.Refused)
			if err != nil {
				return gen, fmt.Errorf("%s: %w", id, err)
			}
			vectors = append(vectors, v)
		}
		gen.Agreement = append(gen.Agreement, agreement)
	}
	gen.File = b.file(vectors)
	return gen, nil
}

func (b *sigvecBuild) file(vectors []SigvecVector) SigvecFile {
	return SigvecFile{
		Version: 1,
		Title:   "HTTP Signature Keys (draft-hardt-httpbis-signature-key) test vectors",
		Description: []string{
			"Deterministic test vectors for every Signature-Key scheme and algorithm that aauth-rust and aauth-go both implement, with negative vectors for the draft's MUST-reject rules.",
			"Every vector publishes the request, the signature base verbatim, the header fields signing added, the keys with their private material, the documents the verifier resolves against, and the result the pinned drafts fix.",
			"Category 1 is key handling, 2 verify-only (randomized signatures: verify, never recompute and compare), 3 reproduce-the-bytes (deterministic signatures), as dickhardt/signature-key issue 25 defines them.",
			"Evaluate each vector at its now, with the verifier configuration below. vectors/signature-key/README.md describes every member and how to reproduce the set.",
		},
		Drafts: []SigvecDraft{
			{Name: "draft-hardt-httpbis-signature-key", Commit: "69f5ba2647be848feed043fb6d8b0790e43cd0b6", SHA256: "b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d", URL: "https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md"},
			{Name: "draft-hardt-oauth-aauth-protocol", Commit: "70d67375deb0bb002af7da0711fc58f6e8926e7e", SHA256: "99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0", URL: "https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md"},
		},
		Verifier: SigvecVerifier{
			Resource: sigvecResource, AgentProvider: sigvecAP, SelfJWTTyp: sigvecSelfJWTTyp, Label: sigvecLabel, WindowSeconds: sigvecWindow,
			Schemes:    []string{"hwk", "jwt", "jkt-jwt", "jwks_uri", "jwks", "self-jwt", "x509", "cached"},
			Algorithms: []string{"Ed25519", "ES256", "ES384", "RS256", "PS256"},
		},
		Keys:      b.published,
		Documents: b.defaults,
		X509:      SigvecX509{TrustAnchors: []string{base64.StdEncoding.EncodeToString(b.certs.root)}, CRLs: []string{base64.StdEncoding.EncodeToString(b.certs.crl)}},
		Vectors:   vectors,
	}
}

func (b *sigvecBuild) vector(c sigvecCase, id string, category int, pre SigvecRequest, parts []sigvecPart, library string, signed map[string]string, reproduced []string, note string, refused []string) (SigvecVector, error) {
	signed, err := sigvecMutate(c.Mutation, signed)
	if err != nil {
		return SigvecVector{}, err
	}
	v := SigvecVector{ID: id, Title: c.Title, Category: category, Scheme: parts[0].Scheme, Alg: c.Alg, Now: sigvecNow, Request: pre, Signed: signed, SigningKey: parts[0].Key, Expect: c.Expect, Optional: c.Optional}
	if v.SigningKey == "" {
		v.SigningKey = "symmetric-hs256"
	}
	if c.Documents != nil {
		v.Documents = c.Documents(b)
	}
	for _, p := range parts {
		if p.JWT != "" {
			header, payload, err := sigvecJWTParts(p.JWT)
			if err != nil {
				return v, err
			}
			by := "ap-ed25519"
			switch p.Scheme {
			case "self-jwt":
				by = p.Key
			case "jkt-jwt":
				for _, k := range b.keys {
					if jsonEqual(k.key.public, header["jwk"]) {
						by = k.def.id
					}
				}
			}
			v.Assertion = &SigvecAssertion{Compact: p.JWT, Header: header, Payload: payload, SignedBy: by}
			break
		}
	}
	file := b.file(nil)
	env := SigvecEnvironmentFor(file, v)
	received := SigvecReceived(v)
	if len(parts) > 1 {
		// A multi-signature vector: one base per label, each verified under
		// the key its own member conveys.
		v.Scheme, v.SigningKey = "", ""
		for _, p := range parts {
			s, err := sigvecSignatureFor(env, received, p.Label)
			if err != nil {
				return v, fmt.Errorf("label %s: %w", p.Label, err)
			}
			s.Scheme, s.Alg, s.SigningKey = p.Scheme, b.keys[p.Key].def.alg, p.Key
			v.Signatures = append(v.Signatures, s)
		}
	}
	base, err := SigvecBase(received, sigvecLabel)
	if err == nil && len(parts) == 1 {
		sum := sha256.Sum256([]byte(base))
		v.SignatureBase, v.SignatureBaseSHA256, v.SignatureBaseLength = base, hex.EncodeToString(sum[:]), len(base)
		if key, resolves, err := SigvecConveyedKey(env, received, sigvecLabel); err == nil || len(resolves) > 0 {
			v.Resolves = resolves
			if err == nil {
				if signature, err := sigvecSignatureBytes(received, sigvecLabel); err == nil {
					if verifies := SigvecVerifyJWK(key, []byte(base), signature); verifies || sigvecConsistent(key) {
						v.SignatureVerifies = &verifies
					}
				}
			}
		}
	}
	notes := []string{}
	if note != "" {
		notes = append(notes, note)
	}
	if len(refused) > 0 {
		notes = append(notes, "Not signed by "+strings.Join(refused, "; ")+".")
	}
	v.Provenance = SigvecProvenance{SignedBy: library, ReproducedBy: reproduced, Mutation: c.Mutation, Note: strings.Join(notes, " ")}
	if v.Provenance.SignedBy == "harness" {
		v.Provenance.Note = "Signed by the harness: " + c.HarnessReason + "."
	}
	verifies := v.SignatureVerifies != nil && *v.SignatureVerifies
	if len(v.Signatures) > 0 {
		verifies = true
		for _, s := range v.Signatures {
			verifies = verifies && s.SignatureVerifies != nil && *s.SignatureVerifies
		}
	}
	if c.Expect.Outcome == "verify" && !verifies && c.Category != 1 {
		return v, fmt.Errorf("positive vector does not verify under the harness's own resolution")
	}
	return v, nil
}

// sigvecSignatureFor rebuilds one label's signature base, resolves the key
// its member conveys and checks the signature, with the harness's own code.
func sigvecSignatureFor(env SigvecEnvironment, received SigvecRequest, label string) (SigvecSignature, error) {
	base, err := SigvecBase(received, label)
	if err != nil {
		return SigvecSignature{}, err
	}
	sum := sha256.Sum256([]byte(base))
	s := SigvecSignature{Label: label, SignatureBase: base, SignatureBaseSHA256: hex.EncodeToString(sum[:]), SignatureBaseLength: len(base)}
	key, resolves, err := SigvecConveyedKey(env, received, label)
	s.Resolves = resolves
	if err != nil {
		return s, err
	}
	signature, err := sigvecSignatureBytes(received, label)
	if err != nil {
		return s, err
	}
	verifies := SigvecVerifyJWK(key, []byte(base), signature)
	s.SignatureVerifies = &verifies
	return s, nil
}

// SigvecLauncherSigner signs through a started launcher.
func SigvecLauncherSigner(ready Ready, timeout time.Duration) SigvecSigner {
	return func(ctx context.Context, job SigvecSignJob) (map[string]string, bool, error) {
		body, err := json.Marshal(job)
		if err != nil {
			return nil, false, err
		}
		request, err := http.NewRequest(http.MethodPost, sigvecEndpoint, bytes.NewReader(body))
		if err != nil {
			return nil, false, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := Exchange(ctx, request, ready.URL, timeout)
		if err != nil {
			return nil, false, err
		}
		var answer struct {
			Headers    map[string]string `json:"headers"`
			NotOffered string            `json:"not_offered"`
			Error      string            `json:"error"`
		}
		json.Unmarshal(response.Body, &answer)
		switch response.Status {
		case http.StatusOK:
			return answer.Headers, true, nil
		case http.StatusNotImplemented:
			return nil, false, fmt.Errorf("not offered: %s", answer.NotOffered)
		}
		return nil, true, fmt.Errorf("refused (HTTP %d): %s", response.Status, answer.Error)
	}
}

// GenerateSigvecVectors starts each target's launcher and generates the set.
func GenerateSigvecVectors(ctx context.Context, f Fixture, targets Targets, o Options) (SigvecGeneration, error) {
	b, err := newSigvecBuild(f)
	if err != nil {
		return SigvecGeneration{}, err
	}
	return b.generateWith(ctx, f, targets, o)
}

// CheckSigvecVectors re-signs a published file's vectors with each target,
// reusing its assertions, and reports every difference from the file.
func CheckSigvecVectors(ctx context.Context, f Fixture, targets Targets, o Options, published SigvecFile) (SigvecGeneration, []string, error) {
	b, err := newSigvecBuild(f)
	if err != nil {
		return SigvecGeneration{}, nil, err
	}
	for _, v := range published.Vectors {
		if v.Assertion != nil {
			b.reuse[strings.SplitN(v.ID, ".", 2)[0]] = v.Assertion.Compact
		}
	}
	gen, err := b.generateWith(ctx, f, targets, o)
	if err != nil {
		return gen, nil, err
	}
	return gen, SigvecCompare(published, gen.File), nil
}

// SigvecCompare lists the differences between a published file and a fresh
// generation. A randomized signature (category 2, or an ES256-signed
// assertion) is expected to differ and is not reported.
func SigvecCompare(published, fresh SigvecFile) []string {
	differences := []string{}
	index := map[string]SigvecVector{}
	for _, v := range fresh.Vectors {
		index[v.ID] = v
	}
	for _, p := range published.Vectors {
		f, ok := index[p.ID]
		if !ok {
			differences = append(differences, p.ID+": not regenerated")
			continue
		}
		if p.Category != 2 && p.Signed["Signature"] != f.Signed["Signature"] {
			differences = append(differences, p.ID+": Signature differs")
		}
		for _, name := range []string{"Signature-Input", "Signature-Key", "Content-Digest"} {
			if p.Signed[name] != f.Signed[name] {
				differences = append(differences, p.ID+": "+name+" differs")
			}
		}
		if p.SignatureBase != f.SignatureBase {
			differences = append(differences, p.ID+": signature base differs")
		}
		if len(p.Signatures) != len(f.Signatures) {
			differences = append(differences, p.ID+": number of signatures differs")
		} else {
			for i := range p.Signatures {
				if p.Signatures[i].Label != f.Signatures[i].Label || p.Signatures[i].SignatureBase != f.Signatures[i].SignatureBase {
					differences = append(differences, p.ID+": signature base of label "+p.Signatures[i].Label+" differs")
				}
			}
		}
		delete(index, p.ID)
	}
	for id := range index {
		differences = append(differences, id+": not in the published file")
	}
	sort.Strings(differences)
	return differences
}

func (b *sigvecBuild) generateWith(ctx context.Context, f Fixture, targets Targets, o Options) (SigvecGeneration, error) {
	ap, stopAP, err := startAP(f)
	if err != nil {
		return SigvecGeneration{}, err
	}
	defer stopAP()
	signers := map[string]SigvecSigner{}
	libraries := []SigvecLibrary{}
	for _, target := range targets.Implementations {
		if target.Unavailable != "" {
			continue
		}
		config := Bootstrap{Version: 1, Role: SigvecRole, Now: f.Now, Issuer: f.Issuer, Resource: sigvecEndpoint, APTransport: ap}
		ready, stop, err := startAdapter(ctx, target, config, o)
		if err != nil {
			return SigvecGeneration{}, fmt.Errorf("%s: %w", target.ID, err)
		}
		defer stop()
		signers[target.ID] = SigvecLauncherSigner(ready, o.Timeout)
		libraries = append(libraries, SigvecLibrary{ID: target.ID, Revision: target.Revision})
	}
	gen, err := b.generate(ctx, signers)
	gen.File.Generated = SigvecGenerated{Libraries: libraries, Harness: "aauth-conformance internal/conformance (Go standard library only)"}
	return gen, err
}

// sigvecAssertions are a vector scenario's assertions.
func sigvecAssertions(v SigvecVector, clause string) []Assertion {
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	switch v.Expect.Outcome {
	case "verify":
		if len(v.Signatures) > 0 {
			assertions := []Assertion{{ID: "verified", Clause: clause, Kind: "status", Equals: raw(200)}}
			for _, s := range v.Signatures {
				assertions = append(assertions, Assertion{ID: "scheme-" + s.Label, Clause: clause, Kind: "json-path", Member: "labels." + s.Label, Equals: raw(s.Scheme)})
			}
			return assertions
		}
		return []Assertion{
			{ID: "verified", Clause: clause, Kind: "status", Equals: raw(200)},
			{ID: "scheme", Clause: clause, Kind: "json-member", Member: "scheme", Equals: raw(v.Scheme)},
		}
	case "verify-or-reject":
		return []Assertion{{ID: "defined-result", Clause: clause, Kind: "sigkey-pq", Equals: raw(v.Expect.Error)}}
	}
	assertions := []Assertion{{ID: "refused", Clause: clause, Kind: "status", Equals: raw(401)}}
	if v.Expect.Error == "" {
		return append(assertions, Assertion{ID: "error-present", Clause: clause, Kind: "sfv-token-present", Header: "Signature-Error", Member: "error", Equals: raw(true)})
	}
	return append(assertions, Assertion{ID: "error", Clause: clause, Kind: "sfv-token", Header: "Signature-Error", Member: "error", Equals: raw(v.Expect.Error)})
}

// sigvecClause is the clause of a published vector, from its case.
func sigvecClause(id string) string {
	base := strings.SplitN(id, ".", 2)[0]
	for _, c := range sigvecCases() {
		if c.ID == base {
			return c.Clause
		}
	}
	return ""
}

// WriteSigvec writes the vector file, its scenarios (numbered from 500) and
// the human-readable appendix into the suite at root.
func WriteSigvec(root string, file SigvecFile) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err = os.MkdirAll(filepath.Join(root, filepath.Dir(SigvecFilePath)), 0755); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, SigvecFilePath), data, 0644); err != nil {
		return err
	}
	old, _ := filepath.Glob(filepath.Join(root, "scenarios", "5[0-9][0-9]-sigvec-*.json"))
	for _, name := range old {
		os.Remove(name)
	}
	sum := sha256.Sum256(data)
	for i, v := range file.Vectors {
		input, _ := json.Marshal(SigvecInput{Source: VectorSource{File: SigvecFilePath, SHA256: hex.EncodeToString(sum[:]), Index: i}, Vector: v, Environment: SigvecEnvironmentFor(file, v)})
		scenario := map[string]any{
			"version":         1,
			"id":              "sigvec." + v.ID,
			"title":           "Signature-Key vector " + v.ID + ": " + v.Title,
			"role_under_test": SigvecRole,
			"given":           "agent-identity",
			"input":           json.RawMessage(input),
			"assertions":      sigvecAssertions(v, sigvecClause(v.ID)),
		}
		out, err := json.MarshalIndent(scenario, "", "  ")
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%03d-sigvec-%s.json", 500+i, strings.ReplaceAll(v.ID, ".", "-"))
		if err = os.WriteFile(filepath.Join(root, "scenarios", name), append(out, '\n'), 0644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(root, "vectors/signature-key/APPENDIX.md"), []byte(SigvecAppendix(file)), 0644)
}

// sigvecFold wraps text at 68 columns with RFC 8792 Section 7 single
// backslash folding.
func sigvecFold(text string) string {
	const width = 68
	var out strings.Builder
	folded := false
	for _, line := range strings.Split(text, "\n") {
		for len(line) > width {
			cut := width - 1
			for cut > 0 && (line[cut-1] == ' ' || line[cut] == ' ') {
				cut--
			}
			if cut == 0 {
				cut = width - 1
			}
			out.WriteString(line[:cut] + "\\\n")
			line = line[cut:]
			folded = true
		}
		out.WriteString(line + "\n")
	}
	if !folded {
		return out.String()
	}
	return "NOTE: '\\' line wrapping per RFC 8792\n\n" + out.String()
}

// SigvecAppendix renders the vectors for reading, in the style of RFC 9421
// Appendix B, with long lines folded per RFC 8792.
func SigvecAppendix(file SigvecFile) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	categories := map[int]string{1: "key handling", 2: "verify-only", 3: "reproduce-the-bytes"}
	w("# Signature-Key test vectors\n\n")
	w("Generated from `signature-key-vectors.json`, which is authoritative; this file\n")
	w("folds long lines per RFC 8792. Every vector is evaluated at `now` = %d.\n\n", sigvecNow)
	w("## Keys\n\n")
	for _, k := range file.Keys {
		w("### %s (%s)\n\n%s.\n\n```\n%s\n```\n\n", k.ID, k.Alg, strings.ToUpper(k.Derivation[:1])+k.Derivation[1:], strings.TrimRight(sigvecFold(sigvecPretty(k.PrivateJWKOrPublic())), "\n"))
	}
	w("## Vectors\n\n")
	for _, v := range file.Vectors {
		w("### %s\n\n%s. Category %d (%s). Signed by %s", v.ID, v.Title, v.Category, categories[v.Category], v.Provenance.SignedBy)
		if len(v.Provenance.ReproducedBy) > 0 {
			w("; %s produced the same bytes", strings.Join(v.Provenance.ReproducedBy, " and "))
		}
		w(". Expected: %s", v.Expect.Outcome)
		if v.Expect.Error != "" {
			w(" with `%s`", v.Expect.Error)
		}
		w(" (%s).\n\n", v.Expect.Basis)
		if v.Optional != "" {
			w("Optional: %s\n\n", v.Optional)
		}
		received := SigvecReceived(v)
		target, _ := url.Parse(received.URL)
		var request strings.Builder
		fmt.Fprintf(&request, "%s %s HTTP/1.1\nHost: %s\n", received.Method, target.RequestURI(), target.Host)
		names := []string{}
		for name := range received.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&request, "%s: %s\n", name, received.Headers[name])
		}
		if received.Body != "" {
			fmt.Fprintf(&request, "\n%s\n", received.Body)
		}
		w("Request:\n\n```http\n%s```\n\n", sigvecFold(request.String()))
		if v.SignatureBase != "" {
			w("Signature base (%d bytes, SHA-256 %s):\n\n```\n%s```\n\n", v.SignatureBaseLength, v.SignatureBaseSHA256, sigvecFold(v.SignatureBase))
		}
		for _, s := range v.Signatures {
			w("Signature base for label `%s` (%s, %s, key %s; %d bytes, SHA-256 %s):\n\n```\n%s```\n\n", s.Label, s.Scheme, s.Alg, s.SigningKey, s.SignatureBaseLength, s.SignatureBaseSHA256, sigvecFold(s.SignatureBase))
		}
		if v.Assertion != nil {
			w("Assertion header and payload (signed by %s):\n\n```\n%s\n%s\n```\n\n", v.Assertion.SignedBy, sigvecPretty(v.Assertion.Header), sigvecPretty(v.Assertion.Payload))
		}
		for _, d := range v.Documents {
			w("Document at %s, replacing the default:\n\n```\n%s```\n\n", d.URL, sigvecFold(d.Body+"\n"))
		}
	}
	return b.String()
}

func sigvecPretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// PrivateJWKOrPublic is the JWK to print: private when the key has one.
func (k SigvecKey) PrivateJWKOrPublic() map[string]any {
	if k.PrivateJWK != nil {
		return k.PrivateJWK
	}
	out := sigkeyCloneJWK(k.PublicJWK)
	if k.SeedHex != "" {
		out["seed_hex"] = k.SeedHex
	}
	return out
}

// ReadSigvec reads the published vector file.
func ReadSigvec(root string) (SigvecFile, []byte, error) {
	data, err := os.ReadFile(filepath.Join(root, SigvecFilePath))
	if err != nil {
		return SigvecFile{}, nil, err
	}
	var file SigvecFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return file, data, decoder.Decode(&file)
}
