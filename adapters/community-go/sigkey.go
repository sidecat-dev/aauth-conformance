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

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
)

// The community module verifies agent requests (jwt) with VerifyAndExtractAgent
// and server requests (jwks_uri) with VerifyServerRequest; it offers no
// Resource-side hwk, jwks, self-jwt or jkt-jwt verifier. This launcher routes a
// jwks_uri member to the server verifier and every other request to the agent
// verifier, which refuses other schemes itself. Discovery runs in the module's
// JWKSResolver over a host transport that only maps fixture origins to loopback.
func init() {
	launchers["sigkey.verifier"] = communitySigkeyVerifier
	launchers["sigkey.signer"] = communitySigkeySigner
}

type communitySigkeyExtension struct {
	Verifier  string            `json:"verifier"`
	Signer    string            `json:"signer"`
	Documents map[string]string `json:"documents"`
}

func communityHostClient(documents map[string]string) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("fixture discovery never redirects")
	}, Transport: communityRoundTrip(func(r *http.Request) (*http.Response, error) {
		physical, ok := documents["https://"+r.URL.Host]
		if !ok || r.URL.Scheme != "https" {
			return nil, fmt.Errorf("no fixture transport for %s", r.URL.Redacted())
		}
		target, err := url.Parse(physical)
		if err != nil {
			return nil, err
		}
		mapped := r.Clone(r.Context())
		mapped.Host = r.URL.Host
		mapped.URL.Scheme, mapped.URL.Host = target.Scheme, target.Host
		return transport.RoundTrip(mapped)
	})}
}

type communityRoundTrip func(*http.Request) (*http.Response, error)

func (f communityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func communityServe(path string, handler http.Handler) error {
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

func communitySigkeyVerifier(config bootstrap) error {
	var ext communitySigkeyExtension
	if err := json.Unmarshal(config.Extension, &ext); err != nil {
		return err
	}
	target, err := url.Parse(ext.Verifier)
	if err != nil {
		return err
	}
	resolver := aauth.NewJWKSResolver(communityHostClient(ext.Documents))
	signature := aauth.RequestVerifyOptions{Now: func() time.Time { return time.Unix(config.Now, 0).UTC() }, Authority: target.Host}
	echo := func(w http.ResponseWriter, value map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(value)
	}
	return communityServe(target.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != target.Path {
			http.NotFound(w, r)
			return
		}
		r.URL.Scheme, r.URL.Host = "https", r.Host
		if member, err := aauth.ParseSignatureKeyMember(r, aauth.DefaultSignatureLabel); err == nil && member.Scheme == aauth.SchemeJWKSURI {
			caller, err := aauth.VerifyServerRequest(r.Context(), r, aauth.VerifyServerOptions{
				Resolver:    resolver,
				TrustSigner: func(id, _ string) bool { return id == ext.Signer },
				Signature:   signature,
			})
			if err != nil {
				aauth.WriteSignatureFailure(w, err)
				return
			}
			echo(w, map[string]string{"scheme": "jwks_uri", "signer": caller.ID})
			return
		}
		claims, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: resolver, RequireProviderClaims: true, Signature: signature})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		echo(w, map[string]string{"scheme": "jwt", "sub": claims.Subject})
	}))
}

type communitySigkeyJob struct {
	Scheme      string `json:"scheme"`
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
	Transport   string `json:"transport"`
}

func communitySigner(job communitySigkeyJob) (crypto.Signer, error) {
	if job.Seed != "" {
		seed, err := hex.DecodeString(job.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("Ed25519 seed must be 32-byte hex")
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	der, err := hex.DecodeString(job.PKCS8)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("fixture key is not a signer")
	}
	return signer, nil
}

// communitySigkeySigner signs with the module's own signers. They read the
// wall clock: the module takes no clock, so created is not the fixture time.
func communitySigkeySigner(config bootstrap) error {
	control, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	return communityServe(control.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job communitySigkeyJob
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&job); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		physical, err := url.Parse(job.Transport)
		if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
			http.Error(w, "loopback transport required", 400)
			return
		}
		signer, err := communitySigner(job)
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		request, err := http.NewRequestWithContext(context.Background(), job.Method, job.URL, bytes.NewReader([]byte(job.Body)))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if job.ContentType != "" {
			request.Header.Set("Content-Type", job.ContentType)
		}
		switch job.Scheme {
		case "hwk":
			err = agentprovider.SignHWK(request, signer)
		case "jwt":
			aauth.AttachSignatureKey(request, job.JWT)
			err = aauth.SignRequest(request, signer, "")
		case "jwks_uri":
			err = aauth.ServerSigner{Issuer: job.ID, DWK: job.DWK, Kid: job.Kid, Key: signer}.SignRequest(request)
		case "jkt-jwt":
			err = agentprovider.SignJKTJWT(request, job.JWT, signer)
		default:
			err = fmt.Errorf("the community module offers no %s signer", job.Scheme)
		}
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		mapped := request.Clone(request.Context())
		mapped.Host = request.URL.Host
		mapped.URL.Scheme, mapped.URL.Host = physical.Scheme, physical.Host
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(mapped)
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
