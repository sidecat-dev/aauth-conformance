package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Signature-Key roles: a native Resource that also accepts the schemes AAuth
// does not use, and the native request signer. Discovery runs in the native
// HTTP key resolver; the host transport only routes each logical HTTPS origin
// to its loopback fixture, so documents are fetched, parsed and selected by
// aauth-go.
func init() {
	extensionLaunchers["sigkey.verifier"] = runSigkeyVerifier
	extensionLaunchers["sigkey.signer"] = runSigkeySigner
}

type sigkeyExtension struct {
	Verifier   string            `json:"verifier"`
	SelfJWTTyp string            `json:"self_jwt_typ"`
	Algorithms []string          `json:"algorithms"`
	Documents  map[string]string `json:"documents"`
}

// sigkeyHostClient routes each fixture origin to its loopback transport,
// preserving the logical Host, and refuses any other destination.
func sigkeyHostClient(documents map[string]string) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("fixture discovery never redirects")
	}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		physical, ok := documents["https://"+r.URL.Host]
		if !ok || r.URL.Scheme != "https" {
			return nil, fmt.Errorf("no fixture transport for %s", r.URL.Redacted())
		}
		target, err := url.Parse(physical)
		if err != nil {
			return nil, err
		}
		return transport.RoundTrip(mapPhysicalRequest(r, target))
	})}
}

func runSigkeyVerifier(config bootstrap, _ signaturekey.StaticKeyResolver) error {
	var ext sigkeyExtension
	if err := json.Unmarshal(config.Extension, &ext); err != nil {
		return err
	}
	target, err := url.Parse(ext.Verifier)
	if err != nil {
		return err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: sigkeyHostClient(ext.Documents),
		Clock:  clock,
		// Egress admission is host policy: admit only the fixture origins.
		Admit: func(_ context.Context, endpoint string) error {
			u, err := url.Parse(endpoint)
			if err != nil {
				return err
			}
			if _, ok := ext.Documents["https://"+u.Host]; !ok || u.Scheme != "https" {
				return fmt.Errorf("endpoint %s is not admitted", endpoint)
			}
			return nil
		},
		TransportEnforcesEgress: true,
	})
	if err != nil {
		return err
	}
	echo := func(w http.ResponseWriter, value map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(value)
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
			Schemes:    []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJKTJWT, signaturekey.SchemeJWKSURI, signaturekey.SchemeJWKS},
			Algorithms: ext.Algorithms,
			JWKS:       resolver,
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
		return err
	}
	return sigkeyServe(target.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != target.Path {
			http.NotFound(w, r)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		sut.Handler().ServeHTTP(w, r)
	}))
}

func sigkeyServe(path string, handler http.Handler) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path}); err != nil {
		return err
	}
	return (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

type sigkeyJob struct {
	Scheme      string `json:"scheme"`
	Alg         string `json:"alg"`
	Kid         string `json:"kid"`
	Seed        string `json:"seed_hex"`
	PKCS8       string `json:"pkcs8_hex"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
	JWT         string `json:"jwt"`
	ID          string `json:"id"`
	DWK         string `json:"dwk"`
	JWKSURL     string `json:"jwks_url"`
	Transport   string `json:"transport"`
}

// sigkeySigningKey loads the public fixture test key the job names.
func sigkeySigningKey(job sigkeyJob) (jose.SigningKey, error) {
	if job.Seed != "" {
		seed, err := hex.DecodeString(job.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return jose.SigningKey{}, fmt.Errorf("Ed25519 seed must be 32-byte hex")
		}
		return jose.NewEd25519SigningKey(job.Kid, ed25519.NewKeyFromSeed(seed))
	}
	der, err := hex.DecodeString(job.PKCS8)
	if err != nil {
		return jose.SigningKey{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return jose.SigningKey{}, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return jose.SigningKey{}, fmt.Errorf("fixture key is not a signer")
	}
	return jose.NewSigningKeyForAlgorithm(job.Kid, job.Alg, signer)
}

func runSigkeySigner(config bootstrap, _ signaturekey.StaticKeyResolver) error {
	control, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	return sigkeyServe(control.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job sigkeyJob
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&job); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		physical, err := url.Parse(job.Transport)
		if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
			http.Error(w, "loopback transport required", 400)
			return
		}
		key, err := sigkeySigningKey(job)
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), job.Method, job.URL, bytes.NewReader([]byte(job.Body)))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if job.ContentType != "" {
			request.Header.Set("Content-Type", job.ContentType)
		}
		switch job.Scheme {
		case "hwk":
			err = signaturekey.SignHWKRequest(request, key, clock)
		case "jwt":
			err = signaturekey.SignJWTRequest(request, key, job.JWT, clock)
		case "jwks_uri":
			err = signaturekey.SignJWKSURIRequest(request, key, job.ID, job.DWK, clock)
		case "jwks":
			var credential signaturekey.Credential
			if credential, err = signaturekey.NewJWKSCredential(job.JWKSURL, job.Kid); err == nil {
				err = signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{})
			}
		case "self-jwt":
			err = signaturekey.SignSelfJWTRequest(request, key, job.JWT, clock)
		case "jkt-jwt":
			var credential signaturekey.Credential
			if credential, err = signaturekey.NewJKTJWTCredential(job.JWT); err == nil {
				err = signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{})
			}
		default:
			err = fmt.Errorf("aauth-go offers no %s signer", job.Scheme)
		}
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(mapPhysicalRequest(request, physical))
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"status": response.StatusCode})
	}))
}
