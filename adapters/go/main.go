// This launcher supplies host configuration; AAuth signing/verification is the SUT's.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type bootstrap struct {
	PersonServer    string   `json:"person_server"`
	PersonSeed      string   `json:"person_seed_hex"`
	PersonKid       string   `json:"person_kid"`
	PersonSubject   string   `json:"person_subject"`
	PersonLifetime  int64    `json:"person_lifetime"`
	AuthLifetime    int64    `json:"auth_lifetime"`
	PermittedScopes []string `json:"permitted_scopes"`
	ResourceKid     string   `json:"resource_kid"`
	ResourceJWK     jose.JWK `json:"resource_jwk"`
	Version         int      `json:"version"`
	Now             int64    `json:"now"`
	Issuer          string   `json:"issuer"`
	Resource        string   `json:"resource"`
	APTransport     string   `json:"ap_transport"`
	Role            string   `json:"role"`
	AgentSeed       string   `json:"agent_seed_hex"`
	Subject         string   `json:"subject"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
func run() error {
	var config bootstrap
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		return err
	}
	if config.Version != 1 {
		return fmt.Errorf("bootstrap version must be 1")
	}
	origin, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("unexpected AP redirect") }}
	fetch := func(path string, v any) error {
		r, err := client.Get(config.APTransport + path)
		if err != nil {
			return err
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("AP HTTP %d", r.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			return err
		}
		if len(b) > 65536 {
			return fmt.Errorf("AP document too large")
		}
		return json.Unmarshal(b, v)
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if err = fetch("/.well-known/aauth-agent.json", &metadata); err != nil {
		return err
	}
	if metadata.Issuer != config.Issuer || metadata.JWKS != config.Issuer+"/.well-known/jwks.json" {
		return fmt.Errorf("AP metadata differs from fixture")
	}
	var jwks struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err = fetch("/.well-known/jwks.json", &jwks); err != nil {
		return err
	}
	keys := signaturekey.StaticKeyResolver{}
	for _, key := range jwks.Keys {
		keys[signaturekey.StaticKeyReference{Issuer: config.Issuer, DiscoveryDocument: "aauth-agent.json", KeyID: key.Kid}] = key
	}
	if config.Role == "person-server.direct" {
		return runPersonServer(config, keys)
	}
	if config.Role == "agent.signing" {
		return runAgent(config, keys)
	}
	sut, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: origin.Scheme + "://" + origin.Host, KeyResolver: keys, Clock: aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }),
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified principal", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": principal.Agent})
		}),
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != origin.Path {
			http.NotFound(w, r)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		sut.Handler().ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + origin.Path}); err != nil {
		return err
	}
	return (&http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func runAgent(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	seed, err := hex.DecodeString(config.AgentSeed)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("Agent seed must be 32-byte hex")
	}
	key, err := jose.NewEd25519SigningKey("fixture-agent", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			Method    string            `json:"method"`
			URL       string            `json:"url"`
			Headers   map[string]string `json:"headers"`
			Token     string            `json:"token"`
			Transport string            `json:"transport"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&job); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		physical, err := url.Parse(job.Transport)
		if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
			http.Error(w, "loopback transport required", 400)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), job.Method, job.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for name, value := range job.Headers {
			request.Header.Set(name, value)
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client, err := agent.New(r.Context(), agent.Config{Identifier: config.Subject, SigningKey: key, AgentToken: job.Token, KeyResolver: keys, Clock: aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }), HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(signed *http.Request) (*http.Response, error) {
			mapped := mapPhysicalRequest(signed, physical)
			return transport.RoundTrip(mapped)
		})}})
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		response, err := client.CallAsAgentWithComponents(r.Context(), request, nil)
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		defer response.Body.Close()
		if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 65537)); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"status": response.StatusCode})
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + "/control"}); err != nil {
		return err
	}
	return (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

// Substitute only the socket destination. Preserve explicit SUT Host output.
func mapPhysicalRequest(signed *http.Request, physical *url.URL) *http.Request {
	mapped := signed.Clone(signed.Context())
	target := *signed.URL
	target.Scheme = physical.Scheme
	target.Host = physical.Host
	if mapped.Host == "" {
		mapped.Host = signed.URL.Host
	}
	mapped.URL = &target
	return mapped
}
func runPersonServer(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	seed, err := hex.DecodeString(config.PersonSeed)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("Person Server seed must be 32-byte hex")
	}
	key, err := jose.NewEd25519SigningKey(config.PersonKid, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	origin, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	resourceIssuer := origin.Scheme + "://" + origin.Host
	keys[signaturekey.StaticKeyReference{Issuer: resourceIssuer, DiscoveryDocument: "aauth-resource.json", KeyID: config.ResourceKid}] = config.ResourceJWK
	keys[signaturekey.StaticKeyReference{Issuer: config.PersonServer, DiscoveryDocument: "aauth-person.json", KeyID: config.PersonKid}] = key.PublicJWK()
	var sequence atomic.Uint64
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: config.PersonServer, SigningKey: key, KeyResolver: keys,
		Clock:  aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }),
		NewID:  func() string { return fmt.Sprintf("fixture-%d", sequence.Add(1)) },
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(_ context.Context, input personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: config.PersonSubject, Lifetime: time.Duration(config.PersonLifetime) * time.Second}, nil
		},
		Authorize: func(_ context.Context, input personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			for _, scope := range input.Scopes {
				allowed := false
				for _, permitted := range config.PermittedScopes {
					if scope == permitted {
						allowed = true
					}
				}
				if !allowed {
					return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
				}
			}
			return personserver.AuthorizationDecision{Scopes: append([]string(nil), input.Scopes...), Lifetime: time.Duration(config.AuthLifetime) * time.Second}, nil
		},
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Incoming Host is signature evidence. Reconstruct only the HTTPS scheme;
		// never replace an incoming authority with the configured Person Server.
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		sut.Handler().ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + "/person"}); err != nil {
		return err
	}
	return (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
