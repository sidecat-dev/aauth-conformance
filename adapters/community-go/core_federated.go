package main

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/personserver"
)

// coreFederatedConfig adds the four-party members to the Person Server bootstrap.
type coreFederatedConfig struct {
	corePersonConfig
	AccessServer        string `json:"access_server"`
	AccessSeed          string `json:"access_seed_hex"`
	AccessKid           string `json:"access_kid"`
	ResourceSeed        string `json:"resource_seed_hex"`
	FederationTransport string `json:"federation_transport"`
}

// Four-party authorization runs the module's personserver.Server, its
// accessserver.Server and a ResourceGuard on one listener, routed by the
// received Host. Each keeps its own identity and key.
func init() { launchers["authorization.federated"] = coreFederated }

func coreFederated(config bootstrap) error {
	var c coreFederatedConfig
	if err := json.Unmarshal(config.Raw, &c); err != nil {
		return err
	}
	bundle, err := coreFederatedBundle(config, c)
	if err != nil {
		return err
	}
	target, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	return coreServe(target.Path, bundle)
}

// coreFederatedBundle builds the three native roles and returns their
// Host router. The PS reaches the AS's token endpoint only through the
// runner's relay at federation_transport.
func coreFederatedBundle(config bootstrap, c coreFederatedConfig) (http.Handler, error) {
	psKey, err := coreSigner(c.PersonSeed)
	if err != nil {
		return nil, err
	}
	asKey, err := coreSigner(c.AccessSeed)
	if err != nil {
		return nil, err
	}
	resourceKey, err := coreSigner(c.ResourceSeed)
	if err != nil {
		return nil, err
	}
	agents, err := coreAgentProviderKeys(config)
	if err != nil {
		return nil, err
	}
	resourceID := coreOrigin(config.Resource)
	named := func(key crypto.Signer, kid string) (aauth.JWKS, error) {
		jwk, err := aauth.NewJWK(key.Public())
		jwk.Kid = kid
		return aauth.JWKS{Keys: []aauth.JWK{jwk}}, err
	}
	psJWKS, err := named(psKey, c.PersonKid)
	if err != nil {
		return nil, err
	}
	asJWKS, err := named(asKey, c.AccessKid)
	if err != nil {
		return nil, err
	}
	resourceJWKS, err := named(resourceKey, c.ResourceKid)
	if err != nil {
		return nil, err
	}
	servers := aauth.StaticResolver{c.PersonServer: psJWKS, c.AccessServer: asJWKS, resourceID: resourceJWKS}
	clock := coreClock(config)
	access, err := accessserver.New(accessserver.Config{
		Issuer: c.AccessServer, Key: asKey, KeyID: c.AccessKid,
		Store: accessserver.NewMemoryStore(),
		Authorizer: accessserver.AuthorizerFunc(func(_ context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			for _, scope := range strings.Fields(r.Resource.Scope) {
				if !slices.Contains(c.PermittedScopes, scope) {
					return accessserver.Decision{Outcome: accessserver.Denied, Code: "access_denied", Reason: "scope outside the fixture policy"}, nil
				}
			}
			return accessserver.Decision{Outcome: accessserver.Allowed, TTL: time.Duration(c.AuthLifetime) * time.Second}, nil
		}),
		Resources:      func(resource string) bool { return resource == resourceID },
		TrustPS:        func(_ context.Context, ps string) bool { return ps == c.PersonServer },
		Paths:          accessserver.Paths{Token: "/token"},
		ServerResolver: servers, TokenResolver: servers, AgentResolver: agents,
		AuthTokenTTL: time.Duration(c.AuthLifetime) * time.Second,
		Now:          clock,
	})
	if err != nil {
		return nil, err
	}
	physical, err := url.Parse(c.FederationTransport)
	if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
		return nil, fmt.Errorf("federation transport must be loopback HTTP")
	}
	asURL, err := url.Parse(c.AccessServer)
	if err != nil {
		return nil, err
	}
	relay := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	federationClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("unexpected AS redirect") },
		Transport: coreRoundTrip(func(signed *http.Request) (*http.Response, error) {
			if !strings.EqualFold(signed.URL.Host, asURL.Host) || signed.URL.Scheme != "https" {
				return nil, fmt.Errorf("unexpected federation destination %s", signed.URL.Host)
			}
			// The AS's own metadata document is served by the native AS on
			// this listener; signed token requests go through the relay.
			if signed.Method == http.MethodGet && signed.URL.Path == "/.well-known/"+aauth.WellKnownAccess {
				recorder := httptest.NewRecorder()
				access.ServeHTTP(recorder, signed)
				return recorder.Result(), nil
			}
			return relay.RoundTrip(coreMapPhysical(signed, physical))
		})}
	people, err := personserver.New(personserver.Config{
		Issuer: c.PersonServer, Key: psKey, KeyID: c.PersonKid,
		SubjectKey:     []byte("conformance fixture subject derivation key, public"),
		Store:          personserver.NewMemoryStore(),
		Decider:        corePersonPolicy(c.corePersonConfig),
		Federator:      accessserver.NewClient(aauth.ServerSigner{Issuer: c.PersonServer, DWK: aauth.WellKnownPerson, Kid: c.PersonKid, Key: psKey}, federationClient),
		AgentResolver:  agents,
		TokenResolver:  servers,
		ServerResolver: servers,
		Paths:          personserver.Paths{PersonToken: "/person", AuthToken: "/token"},
		PersonTokenTTL: time.Duration(c.PersonLifetime) * time.Second,
		AuthTokenTTL:   time.Duration(c.AuthLifetime) * time.Second,
		Now:            clock,
	})
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(config.Resource)
	if err != nil {
		return nil, err
	}
	guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
		Resource: resourceID, Key: resourceKey, KeyID: c.ResourceKid, Audience: c.AccessServer,
		Verify:        aauth.TokenVerifyOptions{Resolver: servers, Signature: aauth.RequestVerifyOptions{Now: clock}},
		AgentResolver: agents,
		TrustIssuer:   aauth.TrustIssuers(c.PersonServer),
	})
	if err != nil {
		return nil, err
	}
	scope := strings.Join(c.PermittedScopes, " ")
	resource := guard.Require(aauth.Access{Level: aauth.AccessAuth, Scope: scope}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := aauth.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "missing verified caller", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": caller.Subject})
	}))
	routes := map[string]http.Handler{
		strings.ToLower(coreHost(c.PersonServer)): people,
		strings.ToLower(asURL.Host):               access,
		strings.ToLower(target.Host):              coreLogical(resource, target.Path),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := routes[strings.ToLower(r.Host)]
		if !ok {
			http.Error(w, "unknown logical host", 421)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		handler.ServeHTTP(w, r)
	}), nil
}

type coreRoundTrip func(*http.Request) (*http.Response, error)

func (f coreRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// coreHost is the host of a server identifier.
func coreHost(identifier string) string {
	u, err := url.Parse(identifier)
	if err != nil {
		return ""
	}
	return u.Host
}
