// Selected only by build-adapters -role authorization.subagent.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() { runSubagentServers = runSubagentBundle }

// runSubagentBundle hosts native PS, AS and Resource roles for parent-mediated
// sub-agent scenarios. Direct scenarios use a three-party PS; the others
// federate with deferred AS approval and payment. The host control changes
// only the AS policy stage, the clock shared by all roles and the PS binding
// state; the native roles verify, issue, poll and refuse.
func runSubagentBundle(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	for _, provider := range config.AdditionalAgentProviders {
		if err := admitAgentProvider(provider, keys); err != nil {
			return err
		}
	}
	newKey := func(seedHex, kid string) (jose.SigningKey, error) {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return jose.SigningKey{}, fmt.Errorf("role signing seed must be 32-byte hex")
		}
		return jose.NewEd25519SigningKey(kid, ed25519.NewKeyFromSeed(seed))
	}
	psKey, err := newKey(config.PersonSeed, config.PersonKid)
	if err != nil {
		return err
	}
	asKey, err := newKey(config.AccessSeed, config.AccessKid)
	if err != nil {
		return err
	}
	resourceKey, err := newKey(config.ResourceSeed, config.ResourceKid)
	if err != nil {
		return err
	}
	resourceURL, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	resourceID := resourceURL.Scheme + "://" + resourceURL.Host
	keys[signaturekey.StaticKeyReference{Issuer: resourceID, DiscoveryDocument: "aauth-resource.json", KeyID: config.ResourceKid}] = resourceKey.PublicJWK()
	keys[signaturekey.StaticKeyReference{Issuer: config.PersonServer, DiscoveryDocument: "aauth-person.json", KeyID: config.PersonKid}] = psKey.PublicJWK()
	keys[signaturekey.StaticKeyReference{Issuer: config.AccessServer, DiscoveryDocument: "aauth-access.json", KeyID: config.AccessKid}] = asKey.PublicJWK()
	var offset atomic.Int64
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now+offset.Load(), 0).UTC() })
	var ids atomic.Uint64
	nextID := func() string { return fmt.Sprintf("subagent-%d", ids.Add(1)) }
	permitted := func(scopes []string) bool {
		for _, scope := range scopes {
			allowed := false
			for _, permitted := range config.PermittedScopes {
				allowed = allowed || scope == permitted
			}
			if !allowed {
				return false
			}
		}
		return true
	}
	var stage atomic.Int32
	access, err := accessserver.New(accessserver.Config{
		Issuer: config.AccessServer, SigningKey: asKey, KeyResolver: keys, Clock: clock, NewID: nextID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != config.PersonServer {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Second},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if !permitted(request.Scopes) {
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			}
			switch stage.Load() {
			case -1:
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			case 0:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{Payment: &accessserver.PaymentChallenge{Authenticate: `Payment id="fixture-bill", method="example"`}}}, nil
			case 1:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
			default:
				return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: time.Duration(config.AuthLifetime) * time.Second}, nil
			}
		},
	})
	if err != nil {
		return err
	}
	physical, err := url.Parse(config.FederationTransport)
	if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
		return fmt.Errorf("federation transport must be loopback HTTP")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(signed *http.Request) (*http.Response, error) {
		if signed.URL.Scheme+"://"+signed.URL.Host != config.AccessServer {
			return nil, fmt.Errorf("unexpected federation destination")
		}
		return transport.RoundTrip(mapPhysicalRequest(signed, physical))
	})}
	bindPerson := func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
		return personserver.Person{Subject: config.PersonSubject, Lifetime: time.Duration(config.PersonLifetime) * time.Second}, nil
	}
	bindings := testutil.NewAgentBindingRevocationStore()
	var people *personserver.Server
	if config.PersonDirect {
		people, err = personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: config.PersonServer, SigningKey: psKey, KeyResolver: keys, Clock: clock, NewID: nextID,
			Tokens: testutil.NewMissionStore(), BindPerson: bindPerson,
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				if !permitted(request.Scopes) {
					return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
				}
				return personserver.AuthorizationDecision{Scopes: append([]string(nil), request.Scopes...), Lifetime: time.Duration(config.AuthLifetime) * time.Second}, nil
			},
			AgentBindingRevocations: bindings,
		})
	} else {
		people, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
			Issuer: config.PersonServer, SigningKey: psKey, KeyResolver: keys, Clock: clock, NewID: nextID,
			Tokens: testutil.NewMissionStore(), HTTPClient: client,
			AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
				if issuer != config.AccessServer {
					return "", fmt.Errorf("unconfigured Access Server")
				}
				return issuer + "/token", nil
			},
			BindPerson:              bindPerson,
			Consent:                 func(context.Context, personserver.AuthorizationRequest) error { return nil },
			Deferred:                &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 30 * time.Second},
			AgentBindingRevocations: bindings,
		})
	}
	if err != nil {
		return err
	}
	protected, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: config.AccessServer, SigningKey: resourceKey, KeyResolver: keys,
		Clock: clock, NewID: nextID, ScopeDescriptions: map[string]string{"read": "Read fixture identity"},
		RequiredScopes: func(*http.Request) []string { return []string{"read"} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != config.PersonServer || identity.Subject != config.PersonSubject {
				return fmt.Errorf("unrecognized fixture person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "native Resource did not supply verified principal", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": principal.Subject})
		}),
	})
	if err != nil {
		return err
	}
	// The host controls policy, fixture time and binding state. AS and PS
	// polls, credential issuance and refusals stay with the native roles.
	control := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var command struct {
			Stage         int32  `json:"stage"`
			Reference     string `json:"reference"`
			NowOffset     *int64 `json:"now_offset"`
			Revoke        bool   `json:"revoke"`
			ParentIssuer  string `json:"parent_issuer"`
			ParentSubject string `json:"parent_subject"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&command) != nil || command.Stage < -1 || command.Stage > 2 ||
			command.NowOffset != nil && (*command.NowOffset < 0 || *command.NowOffset > 3600) {
			http.Error(w, "invalid host control", http.StatusBadRequest)
			return
		}
		if command.Revoke {
			if err := people.RevokeAgentBinding(r.Context(), personserver.AgentBinding{
				AgentProvider: command.ParentIssuer, Agent: command.ParentSubject,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if command.NowOffset != nil {
			offset.Store(*command.NowOffset)
		}
		stage.Store(command.Stage)
		if command.Reference != "" {
			if err := people.AdvanceFederation(r.Context(), command.Reference); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handlers := map[string]http.Handler{
		config.PersonServer: people.Handler(), config.AccessServer: access.Handler(), resourceID: protected.Handler(),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme, r.URL.Host = "https", r.Host
		if "https://"+r.Host == config.PersonServer && r.URL.Path == "/__fixture/subagent" {
			control.ServeHTTP(w, r)
			return
		}
		handler := handlers["https://"+r.Host]
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"version": 1, "url": "http://" + listener.Addr().String() + resourceURL.Path,
	}); err != nil {
		return err
	}
	return (&http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

// admitAgentProvider trusts an additional fixture Agent Provider through its
// own loopback transport. Its metadata must name the declared issuer; the
// native Person and Access Servers still decide whether its tokens qualify.
func admitAgentProvider(provider agentProviderTrust, keys signaturekey.StaticKeyResolver) error {
	physical, err := url.Parse(provider.Transport)
	if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
		return fmt.Errorf("additional Agent Provider transport must be loopback HTTP")
	}
	if err := aauth.ValidateServerIdentifier(provider.Issuer); err != nil {
		return fmt.Errorf("additional Agent Provider issuer: %w", err)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("unexpected AP redirect") }}
	fetch := func(path string, v any) error {
		response, err := client.Get(provider.Transport + path)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("additional AP HTTP %d", response.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			return err
		}
		if len(body) > 65536 {
			return errors.New("additional AP document too large")
		}
		return json.Unmarshal(body, v)
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if err := fetch("/.well-known/aauth-agent.json", &metadata); err != nil {
		return err
	}
	if metadata.Issuer != provider.Issuer || metadata.JWKS != provider.Issuer+"/.well-known/jwks.json" {
		return errors.New("additional AP metadata differs from its declared issuer")
	}
	var jwks struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := fetch("/.well-known/jwks.json", &jwks); err != nil {
		return err
	}
	for _, key := range jwks.Keys {
		keys[signaturekey.StaticKeyReference{Issuer: provider.Issuer, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.Kid}] = key
	}
	return nil
}
