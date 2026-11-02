package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Signature-Key test vectors: aauth-go signs a vector's request with its
// native signer, and verifies a vector with its native Resource (further
// schemes enabled) or, for self-jwt, which no Resource accepts, with
// PreparedRequest.VerifySelfJWT. Documents are served from memory to the
// native HTTP key resolver, which fetches, parses and selects keys itself.
func init() {
	extensionLaunchers["vectors.signature-key"] = func(config bootstrap, _ signaturekey.StaticKeyResolver) error {
		endpoint, err := url.Parse(config.Resource)
		if err != nil {
			return err
		}
		return sigvecServe(endpoint.Path)
	}
}

type sigvecRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type sigvecSignPart struct {
	Label       string `json:"label"`
	Alg         string `json:"alg"`
	Kid         string `json:"kid"`
	SeedHex     string `json:"seed_hex"`
	PKCS8       string `json:"pkcs8_base64"`
	Scheme      string `json:"scheme"`
	JWT         string `json:"jwt"`
	Cache       bool   `json:"cache"`
	ID          string `json:"id"`
	DWK         string `json:"dwk"`
	URL         string `json:"url"`
	X5U         string `json:"x5u"`
	Certificate string `json:"certificate_der_base64"`
	CID         string `json:"cid"`
}

type sigvecDocument struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

type sigvecEnvironment struct {
	Verifier struct {
		Resource   string   `json:"resource"`
		SelfJWTTyp string   `json:"self_jwt_typ"`
		Label      string   `json:"label"`
		Algorithms []string `json:"algorithms"`
	} `json:"verifier"`
	Documents []sigvecDocument `json:"documents"`
	X509      struct {
		TrustAnchors []string `json:"trust_anchors_der_base64"`
		CRLs         []string `json:"crls_der_base64"`
	} `json:"x509"`
}

type sigvecJob struct {
	Op          string            `json:"op"`
	Created     int64             `json:"created"`
	Nonce       string            `json:"nonce"`
	Now         int64             `json:"now"`
	Request     sigvecRequest     `json:"request"`
	Signatures  []sigvecSignPart  `json:"signatures"`
	Environment sigvecEnvironment `json:"environment"`
}

type sigvecUnoffered string

func (reason sigvecUnoffered) Error() string { return string(reason) }

func sigvecServe(path string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path}); err != nil {
		return err
	}
	return (&http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job sigvecJob
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<22)).Decode(&job); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply := func(status int, value any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(value)
		}
		switch job.Op {
		case "sign":
			headers, err := sigvecSign(job)
			var unoffered sigvecUnoffered
			switch {
			case errors.As(err, &unoffered):
				reply(http.StatusNotImplemented, map[string]string{"not_offered": string(unoffered)})
			case err != nil:
				reply(http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			default:
				reply(http.StatusOK, map[string]any{"headers": headers})
			}
		case "verify":
			recorder, err := sigvecVerify(job)
			if err != nil {
				reply(http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
				return
			}
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			w.Write(recorder.Body.Bytes())
		default:
			reply(http.StatusBadRequest, map[string]string{"error": "unknown op " + job.Op})
		}
	})}).Serve(listener)
}

func sigvecBuildRequest(spec sigvecRequest) (*http.Request, error) {
	var body io.Reader
	if spec.Body != "" {
		body = strings.NewReader(spec.Body)
	}
	request, err := http.NewRequest(spec.Method, spec.URL, body)
	if err != nil {
		return nil, err
	}
	for name, value := range spec.Headers {
		request.Header.Set(name, value)
	}
	return request, nil
}

func sigvecSigningKey(part sigvecSignPart) (jose.SigningKey, error) {
	kid := part.Kid
	if kid == "" {
		kid = "vector-key"
	}
	if part.SeedHex != "" {
		seed, err := hex.DecodeString(part.SeedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return jose.SigningKey{}, fmt.Errorf("Ed25519 seed must be 32-byte hex")
		}
		return jose.NewEd25519SigningKey(kid, ed25519.NewKeyFromSeed(seed))
	}
	der, err := base64.StdEncoding.DecodeString(part.PKCS8)
	if err != nil {
		return jose.SigningKey{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return jose.SigningKey{}, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return jose.SigningKey{}, fmt.Errorf("vector key is not a signer")
	}
	return jose.NewSigningKeyForAlgorithm(kid, part.Alg, signer)
}

func sigvecCredential(part sigvecSignPart, key jose.SigningKey) (signaturekey.Credential, error) {
	switch part.Scheme {
	case "hwk":
		return signaturekey.NewHWKCredential(key.PublicJWK())
	case "jwt":
		credential, err := signaturekey.NewJWTCredential(part.JWT)
		if err == nil && part.Cache {
			credential, err = credential.WithCache()
		}
		return credential, err
	case "jwks_uri":
		return signaturekey.NewJWKSURICredential(part.ID, part.DWK, part.Kid)
	case "jwks":
		return signaturekey.NewJWKSCredential(part.URL, part.Kid)
	case "self-jwt":
		return signaturekey.NewSelfJWTCredential(part.JWT)
	case "jkt-jwt":
		return signaturekey.NewJKTJWTCredential(part.JWT)
	case "x509":
		der, err := base64.StdEncoding.DecodeString(part.Certificate)
		if err != nil {
			return signaturekey.Credential{}, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return signaturekey.Credential{}, err
		}
		return signaturekey.NewX509Credential(part.X5U, certificate)
	case "cached":
		return signaturekey.Credential{}, sigvecUnoffered("aauth-go presents only a cache identifier a verifier issued: NewCachedCredential takes a CacheGrant")
	}
	return signaturekey.Credential{}, sigvecUnoffered("aauth-go offers no " + part.Scheme + " signer")
}

// sigvecSign signs the job's request with SignRequests at the job's created
// time and returns every header field of the signed request.
func sigvecSign(job sigvecJob) (map[string]string, error) {
	request, err := sigvecBuildRequest(job.Request)
	if err != nil {
		return nil, err
	}
	signatures := []signaturekey.RequestSignature{}
	for _, part := range job.Signatures {
		key, err := sigvecSigningKey(part)
		if err != nil {
			return nil, err
		}
		credential, err := sigvecCredential(part, key)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signaturekey.RequestSignature{Label: part.Label, Key: key, Credential: credential})
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(job.Created, 0).UTC() })
	if err = signaturekey.SignRequests(request, signatures, clock, signaturekey.SignOptions{Nonce: job.Nonce}); err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for name, values := range request.Header {
		headers[name] = strings.Join(values, ", ")
	}
	return headers, nil
}

// sigvecDocuments serves the environment's documents from memory to the
// native resolver; any other destination is refused.
func sigvecDocuments(documents []sigvecDocument) (*http.Client, func(context.Context, string) error) {
	byURL := map[string]sigvecDocument{}
	origins := map[string]bool{}
	for _, d := range documents {
		byURL[d.URL] = d
		if u, err := url.Parse(d.URL); err == nil {
			origins[u.Scheme+"://"+u.Host] = true
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("vector documents never redirect")
	}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		document, ok := byURL[r.URL.String()]
		recorder := httptest.NewRecorder()
		if !ok {
			recorder.WriteHeader(http.StatusNotFound)
		} else {
			recorder.Header().Set("Content-Type", document.ContentType)
			recorder.Header().Set("Cache-Control", "max-age=300")
			recorder.Header().Set("Content-Length", fmt.Sprint(len(document.Body)))
			recorder.WriteString(document.Body)
		}
		response := recorder.Result()
		response.ContentLength = int64(recorder.Body.Len())
		response.Request = r
		return response, nil
	})}
	admit := func(_ context.Context, endpoint string) error {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || !origins[u.Scheme+"://"+u.Host] {
			return fmt.Errorf("endpoint %s is not admitted", endpoint)
		}
		return nil
	}
	return client, admit
}

func sigvecFailure(recorder *httptest.ResponseRecorder, err error) {
	failure := signaturekey.NormalizeError(err, signaturekey.ErrorInvalidSignature)
	value, formatErr := signaturekey.FormatError(*failure)
	if formatErr == nil {
		recorder.Header().Set("Signature-Error", value)
	}
	recorder.Header().Set("Content-Type", "text/plain")
	recorder.WriteHeader(http.StatusUnauthorized)
	recorder.WriteString(err.Error())
}

func sigvecVerify(job sigvecJob) (*httptest.ResponseRecorder, error) {
	request, err := sigvecBuildRequest(job.Request)
	if err != nil {
		return nil, err
	}
	env := job.Environment
	target, err := url.Parse(env.Verifier.Resource)
	if err != nil {
		return nil, err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(job.Now, 0).UTC() })
	client, admit := sigvecDocuments(env.Documents)
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{Client: client, Clock: clock, Admit: admit, TransportEnforcesEgress: true})
	if err != nil {
		return nil, err
	}
	recorder := httptest.NewRecorder()
	echo := func(w http.ResponseWriter, value map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(value)
	}
	// No aauth-go Resource accepts self-jwt; its own verifier is called.
	if credential, err := signaturekey.ParseCredentialForLabel(request.Header.Values("Signature-Key"), env.Verifier.Label); err == nil && credential.Scheme() == signaturekey.SchemeSelfJWT {
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT}, SignatureLabel: env.Verifier.Label,
		})
		if err == nil {
			_, _, err = prepared.VerifySelfJWT(context.Background(), resolver, env.Verifier.SelfJWTTyp)
		}
		if err != nil {
			sigvecFailure(recorder, err)
			return recorder, nil
		}
		echo(recorder, map[string]string{"scheme": "self-jwt"})
		return recorder, nil
	}
	decode := func(values []string) ([][]byte, error) {
		out := [][]byte{}
		for _, v := range values {
			der, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			out = append(out, der)
		}
		return out, nil
	}
	anchors, err := decode(env.X509.TrustAnchors)
	if err != nil {
		return nil, err
	}
	lists, err := decode(env.X509.CRLs)
	if err != nil {
		return nil, err
	}
	cacheKey := make([]byte, 32)
	cache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: cacheKey})
	if err != nil {
		return nil, err
	}
	sut, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer:      target.Scheme + "://" + target.Host,
		KeyResolver: resolver,
		Clock:       clock,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified principal", 500)
				return
			}
			echo(w, map[string]string{"scheme": "jwt", "sub": principal.Agent})
		}),
		FurtherSchemes: &resource.FurtherSchemesConfig{
			Schemes:    []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJKTJWT, signaturekey.SchemeJWKSURI, signaturekey.SchemeJWKS, signaturekey.SchemeX509, signaturekey.SchemeCached},
			Algorithms: env.Verifier.Algorithms,
			JWKS:       resolver,
			Cache:      cache,
			// The host fetches x5u itself (the package never does): here
			// from the vector's documents, with the vector's trust.
			X509: func(_ context.Context, certificateURL string) (signaturekey.X509VerifyOptions, error) {
				options := signaturekey.X509VerifyOptions{}
				for _, d := range env.Documents {
					if d.URL == certificateURL {
						options.ChainPEM = []byte(d.Body)
					}
				}
				if options.ChainPEM == nil {
					return options, fmt.Errorf("no certificate chain at %s", certificateURL)
				}
				for _, der := range anchors {
					root, err := x509.ParseCertificate(der)
					if err != nil {
						return options, err
					}
					options.Roots = append(options.Roots, root)
				}
				for _, der := range lists {
					list, err := x509.ParseRevocationList(der)
					if err != nil {
						return options, err
					}
					options.RevocationLists = append(options.RevocationLists, list)
				}
				return options, nil
			},
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				signer, ok := resource.SignerFromContext(r.Context())
				if !ok {
					http.Error(w, "missing verified signer", 500)
					return
				}
				echo(w, map[string]string{"scheme": string(signer.Scheme), "signer": signer.Signer, "alg": signer.PublicKey.Alg})
			}),
		},
	})
	if err != nil {
		return nil, err
	}
	sut.Handler().ServeHTTP(recorder, request)
	return recorder, nil
}
