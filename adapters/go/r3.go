// R3 launchers: a native Resource with class R3, and a native three-party
// Person Server issuing R3 Auth tokens. Trust and policy are fixed host
// configuration; every R3 decision and response is the SUT's.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() {
	extensionLaunchers["r3.resource"] = runR3Resource
	extensionLaunchers["r3.issuer"] = runR3Issuer
}

type r3Extension struct {
	Topology        string   `json:"topology"`
	ResourceSeed    string   `json:"resource_seed_hex"`
	ResourceKid     string   `json:"resource_kid"`
	ResourceJWK     jose.JWK `json:"resource_jwk"`
	PersonServer    string   `json:"person_server"`
	PersonSeed      string   `json:"person_seed_hex"`
	PersonKid       string   `json:"person_kid"`
	PersonJWK       jose.JWK `json:"person_jwk"`
	PersonSubject   string   `json:"person_subject"`
	PersonLifetime  int64    `json:"person_lifetime"`
	AuthLifetime    int64    `json:"auth_lifetime"`
	PermittedScopes []string `json:"permitted_scopes"`
	AccessServer    string   `json:"access_server"`
	AccessKid       string   `json:"access_kid"`
	AccessJWK       jose.JWK `json:"access_jwk"`
	OtherServer     string   `json:"other_server"`
	OtherKid        string   `json:"other_kid"`
	OtherJWK        jose.JWK `json:"other_jwk"`
	Vocabulary      string   `json:"vocabulary"`
	Tools           []string `json:"tools"`
	Grantable       []string `json:"grantable"`
	R3Transport     string   `json:"r3_transport"`
}

func r3Config(config bootstrap) (r3Extension, string, error) {
	var extension r3Extension
	if err := json.Unmarshal(config.Extension, &extension); err != nil {
		return extension, "", err
	}
	origin, err := url.Parse(config.Resource)
	if err != nil {
		return extension, "", err
	}
	return extension, origin.Scheme + "://" + origin.Host, nil
}

func r3SigningKey(seedHex, kid string) (jose.SigningKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return jose.SigningKey{}, fmt.Errorf("role signing seed must be 32-byte hex")
	}
	return jose.NewEd25519SigningKey(kid, ed25519.NewKeyFromSeed(seed))
}

func r3Trust(keys signaturekey.StaticKeyResolver, issuer, document, kid string, jwk jose.JWK) {
	jwk.Kid = kid
	keys[signaturekey.StaticKeyReference{Issuer: issuer, DiscoveryDocument: document, KeyID: kid}] = jwk
}

// r3Tool reads the tool name from one MCP operation's canonical JSON.
func r3Tool(operation r3.Operation) string {
	var value struct {
		Tool string `json:"tool"`
	}
	json.Unmarshal(operation.JSON(), &value)
	return value.Tool
}

func r3Serve(config bootstrap, handler http.Handler) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	path, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path.Path}); err != nil {
		return err
	}
	logical := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Received Host is signature evidence; only the HTTPS scheme is restored.
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		handler.ServeHTTP(w, r)
	})
	return (&http.Server{Handler: logical, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

func runR3Resource(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	extension, resourceID, err := r3Config(config)
	if err != nil {
		return err
	}
	resourceKey, err := r3SigningKey(extension.ResourceSeed, extension.ResourceKid)
	if err != nil {
		return err
	}
	// The Resource's own historical keys, the PS and AS it trusts, and one
	// further trusted server that no document entitles.
	keys[signaturekey.StaticKeyReference{Issuer: resourceID, DiscoveryDocument: "aauth-resource.json", KeyID: extension.ResourceKid}] = resourceKey.PublicJWK()
	r3Trust(keys, extension.PersonServer, "aauth-person.json", extension.PersonKid, extension.PersonJWK)
	r3Trust(keys, extension.AccessServer, "aauth-access.json", extension.AccessKid, extension.AccessJWK)
	r3Trust(keys, extension.OtherServer, "aauth-access.json", extension.OtherKid, extension.OtherJWK)
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return err
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return err
	}
	tools := []map[string]any{}
	for _, tool := range extension.Tools {
		tools = append(tools, map[string]any{"name": tool, "inputSchema": map[string]any{"type": "object"}})
	}
	toolsJSON, _ := json.Marshal(map[string]any{"tools": tools})
	definition, err := mcp.ParseDefinition(resourceID+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage(toolsJSON)))
	if err != nil {
		return err
	}
	display, err := r3.NewDisplay("Use fixture records", "Records may be exported", "Record contents", "Exported copies cannot be recalled")
	if err != nil {
		return err
	}
	operations := map[string]r3.Operation{}
	for _, tool := range extension.Tools {
		named, err := mcp.NewOperation(tool)
		if err != nil {
			return err
		}
		if operations[tool], err = named.ToR3(); err != nil {
			return err
		}
	}
	r3Settings := &resource.R3Config{
		Registry: registry, Definitions: definitions,
		Vocabularies: []resource.R3VocabularyConfig{{
			Definition: definition,
			DisplayForOperations: func(context.Context, r3.OperationSet, *string) (*r3.Display, error) {
				return &display, nil
			},
		}},
		Documents: testutil.NewR3DocumentStore(),
		HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
			operation, ok := operations[strings.TrimPrefix(request.URL.Path, "/op/")]
			return operation, ok && strings.HasPrefix(request.URL.Path, "/op/"), nil
		}},
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	var ids atomic.Uint64
	nextID := func() string { return fmt.Sprintf("r3-%d", ids.Add(1)) }
	descriptions := map[string]string{}
	for _, scope := range extension.PermittedScopes {
		descriptions[scope] = "Fixture scope " + scope
	}
	resolvePerson := func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
		if identity.Issuer != extension.PersonServer || identity.Subject != extension.PersonSubject {
			return fmt.Errorf("unrecognized fixture person")
		}
		return nil
	}
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "native Resource did not supply a verified principal", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"operation": strings.TrimPrefix(r.URL.Path, "/op/"), "sub": principal.Subject})
	})
	var sut *resource.Server
	if extension.Topology == "three-party" {
		sut, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keys, Clock: clock, NewID: nextID,
			ScopeDescriptions: descriptions, RequiredScopes: func(*http.Request) []string { return nil },
			ResolvePerson: resolvePerson, Protected: protected, R3: r3Settings,
		})
	} else {
		sut, err = resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: resourceID, AccessServer: extension.AccessServer, SigningKey: resourceKey, KeyResolver: keys,
			Clock: clock, NewID: nextID, ScopeDescriptions: descriptions,
			RequiredScopes: func(*http.Request) []string { return nil },
			ResolvePerson:  resolvePerson, Protected: protected, R3: r3Settings,
		})
	}
	if err != nil {
		return err
	}
	return r3Serve(config, sut.Handler())
}

func runR3Issuer(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	extension, resourceID, err := r3Config(config)
	if err != nil {
		return err
	}
	personKey, err := r3SigningKey(extension.PersonSeed, extension.PersonKid)
	if err != nil {
		return err
	}
	r3Trust(keys, resourceID, "aauth-resource.json", extension.ResourceKid, extension.ResourceJWK)
	keys[signaturekey.StaticKeyReference{Issuer: extension.PersonServer, DiscoveryDocument: "aauth-person.json", KeyID: extension.PersonKid}] = personKey.PublicJWK()
	physical, err := url.Parse(extension.R3Transport)
	if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
		return fmt.Errorf("R3 transport must be loopback HTTP")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	// The PS's own signed fetch leaves unchanged; only the socket moves to the
	// harness Resource. No TLS or discovery-admission claim is made here.
	client := &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(signed *http.Request) (*http.Response, error) {
		if signed.URL.Scheme+"://"+signed.URL.Host != resourceID {
			return nil, fmt.Errorf("unexpected R3 fetch destination")
		}
		return transport.RoundTrip(mapPhysicalRequest(signed, physical))
	})}
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return err
	}
	permitted := func(scopes []string) bool {
		for _, scope := range scopes {
			if !slices.Contains(extension.PermittedScopes, scope) {
				return false
			}
		}
		return true
	}
	lifetime := time.Duration(extension.AuthLifetime) * time.Second
	var sequence atomic.Uint64
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: extension.PersonServer, SigningKey: personKey, KeyResolver: keys,
		Clock:  aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }),
		NewID:  func() string { return fmt.Sprintf("r3-ps-%d", sequence.Add(1)) },
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: extension.PersonSubject, Lifetime: time.Duration(extension.PersonLifetime) * time.Second}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if !permitted(request.Scopes) {
				return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
			}
			return personserver.AuthorizationDecision{Scopes: append([]string(nil), request.Scopes...), Lifetime: lifetime}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: client,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return fmt.Errorf("R3 document endpoint is not admitted")
				}
				return nil
			},
			// Fixed host consent: the requested permitted scopes, and every
			// document operation the fixture lists as grantable.
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				if !permitted(request.Scopes) {
					return personserver.DirectR3Decision{}, personserver.ErrAccessDenied
				}
				var chosen []r3.Operation
				for _, operation := range document.OperationSet().Operations() {
					if slices.Contains(extension.Grantable, r3Tool(operation)) {
						chosen = append(chosen, operation)
					}
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), chosen...)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				grant, err := r3.NewGrant(granted, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: lifetime, Grant: grant}, nil
			},
			Issuances: testutil.NewR3IssuanceStore(),
		},
	})
	if err != nil {
		return err
	}
	return r3Serve(config, sut.Handler())
}
