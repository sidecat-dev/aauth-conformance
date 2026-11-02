// aauth-go-deployment serves aauth-go's native Resource, Person Servers and
// Access Server over HTTPS, as a deployment the conformance suite's remote
// mode can test. Each role has its own name and a key generated at start; it
// discovers every other party's keys over HTTPS from the parties it trusts.
// Policy follows the suite's test profile: one directed person, the read
// scope only, 60-second Person and 180-second Auth tokens.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
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

// config is the deployment: its names, what it trusts and how it connects.
type config struct {
	Listen  string            `json:"listen"`
	Cert    string            `json:"cert"`
	Key     string            `json:"key"`
	CA      string            `json:"ca"`
	Resolve map[string]string `json:"resolve"`
	// Names of this deployment's roles.
	IdentityResource  string `json:"identity_resource"`
	DirectPerson      string `json:"direct_person_server"`
	FederatedResource string `json:"federated_resource"`
	FederatedPerson   string `json:"federated_person_server"`
	AccessServer      string `json:"access_server"`
	// Parties outside this deployment that it trusts.
	AgentProviders []string `json:"agent_providers"`
	PersonServers  []string `json:"person_servers"`
	Resources      []string `json:"resources"`
}

const (
	subject        = "directed-person-1"
	personLifetime = 60 * time.Second
	authLifetime   = 180 * time.Second
)

func main() {
	path := flag.String("config", "deployment.json", "deployment configuration")
	flag.Parse()
	if err := run(*path); err != nil {
		log.Fatal(err)
	}
}

func run(path string) error {
	var c config
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	client, err := httpsClient(c)
	if err != nil {
		return err
	}
	trusted := append(slices.Clone(c.AgentProviders), c.PersonServers...)
	trusted = append(trusted, c.Resources...)
	trusted = append(trusted, c.DirectPerson, c.FederatedResource, c.FederatedPerson, c.AccessServer)
	keys, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: aauth.SystemClock{}, TransportEnforcesEgress: true,
		Admit: func(_ context.Context, endpoint string) error {
			for _, issuer := range trusted {
				if strings.HasPrefix(endpoint, issuer+"/") {
					return nil
				}
			}
			return fmt.Errorf("not a trusted party: %s", endpoint)
		},
	})
	if err != nil {
		return err
	}
	handlers, err := roles(c, keys, client)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return err
	}
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := handlers["https://"+r.Host]
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		// The native handlers read the request's logical HTTPS URL.
		r.URL.Scheme, r.URL.Host = "https", r.Host
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: c.Listen, Handler: router, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}}
	log.Printf("aauth-go deployment listening on %s", c.Listen)
	return server.ListenAndServeTLS("", "")
}

// roles builds each native role and returns its handler by issuer.
func roles(c config, keys signaturekey.KeyResolver, client *http.Client) (map[string]http.Handler, error) {
	clock := aauth.SystemClock{}
	var ids atomic.Uint64
	newID := func() string { return fmt.Sprintf("go-%d-%d", time.Now().Unix(), ids.Add(1)) }
	key := func(kid string) jose.SigningKey {
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		signing, err := jose.NewEd25519SigningKey(kid, private)
		if err != nil {
			log.Fatal(err)
		}
		return signing
	}
	bind := func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
		return personserver.Person{Subject: subject, Lifetime: personLifetime}, nil
	}
	readOnly := func(scopes []string) bool {
		return !slices.ContainsFunc(scopes, func(s string) bool { return s != "read" })
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := ""
		if agent, ok := resource.AgentPrincipalFromContext(r.Context()); ok {
			sub = agent.Agent
		} else if person, ok := resource.AuthPrincipalFromContext(r.Context()); ok {
			sub = person.Subject
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": sub})
	})
	people := append(slices.Clone(c.PersonServers), c.FederatedPerson)

	identity, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: c.IdentityResource, KeyResolver: keys, Clock: clock, Protected: echo,
	})
	if err != nil {
		return nil, err
	}
	direct, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: c.DirectPerson, SigningKey: key("go-direct-ps"), KeyResolver: keys, Clock: clock, NewID: newID,
		Tokens: testutil.NewMissionStore(), BindPerson: bind,
		Authorize: func(_ context.Context, r personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if !readOnly(r.Scopes) {
				return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
			}
			return personserver.AuthorizationDecision{Scopes: slices.Clone(r.Scopes), Lifetime: authLifetime}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	access, err := accessserver.New(accessserver.Config{
		Issuer: c.AccessServer, SigningKey: key("go-as"), KeyResolver: keys, Clock: clock, NewID: newID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if !slices.Contains(people, issuer) {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Authorize: func(_ context.Context, r accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if !readOnly(r.Scopes) {
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			}
			return accessserver.Decision{Scopes: slices.Clone(r.Scopes), Lifetime: authLifetime}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	federatedPerson, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: c.FederatedPerson, SigningKey: key("go-federated-ps"), KeyResolver: keys, Clock: clock, NewID: newID,
		HTTPClient: client, Tokens: testutil.NewMissionStore(), BindPerson: bind,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != c.AccessServer {
				return "", fmt.Errorf("no federation with %s", issuer)
			}
			return issuer + "/token", nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
	})
	if err != nil {
		return nil, err
	}
	federated, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: c.FederatedResource, AccessServer: c.AccessServer, SigningKey: key("go-resource"),
		KeyResolver: keys, Clock: clock, NewID: newID,
		ScopeDescriptions: map[string]string{"read": "Read the caller's identity"},
		RequiredScopes:    func(*http.Request) []string { return []string{"read"} },
		ResolvePerson: func(_ context.Context, person resource.PersonIdentity, _ resource.PersonContext) error {
			if !slices.Contains(people, person.Issuer) || person.Subject != subject {
				return fmt.Errorf("unknown person")
			}
			return nil
		},
		Protected: echo,
	})
	if err != nil {
		return nil, err
	}
	return map[string]http.Handler{
		c.IdentityResource: identity.Handler(), c.DirectPerson: direct.Handler(),
		c.AccessServer: access.Handler(), c.FederatedPerson: federatedPerson.Handler(),
		c.FederatedResource: federated.Handler(),
	}, nil
}

// httpsClient trusts the configured roots and connects each configured
// host:port to its fixed address, like curl --resolve.
func httpsClient(c config) (*http.Client, error) {
	pem, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", c.CA)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			fixed, ok := c.Resolve[address]
			if !ok {
				return nil, fmt.Errorf("no route to %s", address)
			}
			return dialer.DialContext(ctx, network, fixed)
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
