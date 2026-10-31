package main

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// corePersonConfig is the Person Server part of the bootstrap.
type corePersonConfig struct {
	PersonServer    string         `json:"person_server"`
	PersonSeed      string         `json:"person_seed_hex"`
	PersonKid       string         `json:"person_kid"`
	PersonSubject   string         `json:"person_subject"`
	PersonLifetime  int64          `json:"person_lifetime"`
	AuthLifetime    int64          `json:"auth_lifetime"`
	PermittedScopes []string       `json:"permitted_scopes"`
	ResourceKid     string         `json:"resource_kid"`
	ResourceJWK     map[string]any `json:"resource_jwk"`
}

// The Person Server role runs the module's personserver.Server at /person
// and /token. Host policy binds every agent to the fixture person and
// grants only permitted scopes; the module verifies requests and tokens,
// derives subjects and issues tokens.
func init() { launchers["person-server.direct"] = corePersonServer }

func corePersonServer(config bootstrap) error {
	var p corePersonConfig
	if err := json.Unmarshal(config.Raw, &p); err != nil {
		return err
	}
	key, err := coreSigner(p.PersonSeed)
	if err != nil {
		return err
	}
	agents, err := coreAgentProviderKeys(config)
	if err != nil {
		return err
	}
	resource, err := coreResourceJWK(p.ResourceJWK, p.ResourceKid)
	if err != nil {
		return err
	}
	self, err := aauth.NewJWK(key.Public())
	if err != nil {
		return err
	}
	self.Kid = p.PersonKid
	tokens := aauth.StaticResolver{coreOrigin(config.Resource): {Keys: []aauth.JWK{resource}}, p.PersonServer: {Keys: []aauth.JWK{self}}}
	server, err := personserver.New(personserver.Config{
		Issuer: p.PersonServer, Key: key, KeyID: p.PersonKid,
		SubjectKey:     []byte("conformance fixture subject derivation key, public"),
		Store:          personserver.NewMemoryStore(),
		Decider:        corePersonPolicy(p),
		AgentResolver:  agents,
		TokenResolver:  tokens,
		ServerResolver: tokens,
		Paths:          personserver.Paths{PersonToken: "/person", AuthToken: "/token"},
		PersonTokenTTL: time.Duration(p.PersonLifetime) * time.Second,
		AuthTokenTTL:   time.Duration(p.AuthLifetime) * time.Second,
		Now:            coreClock(config),
	})
	if err != nil {
		return err
	}
	return coreServe("/person", coreLogical(server, ""))
}

// corePersonPolicy binds the agent to the configured person and grants an
// auth token only for permitted scopes, refusing others with the module's
// own denial.
func corePersonPolicy(p corePersonConfig) personserver.Decider {
	return personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
		// In four-party access the Access Server decides the scope; the
		// person consents to federation.
		if r.Kind == personserver.KindAuthToken && r.AccessServer == "" {
			for _, scope := range strings.Fields(r.Scope) {
				if !slices.Contains(p.PermittedScopes, scope) {
					return corePolicyDenial, nil
				}
			}
		}
		return personserver.Allow(personserver.Grant{Person: p.PersonSubject}), nil
	})
}

// corePolicyDenial is the host's refusal of a scope outside the fixture
// policy; the fixture's host contract names its code access_denied.
var corePolicyDenial = personserver.Decision{Outcome: personserver.Denied, Code: "access_denied", Reason: "scope outside the fixture policy"}

// coreResourceJWK decodes the fixture Resource's public JWK into the
// module's type and names it by the fixture kid.
func coreResourceJWK(raw map[string]any, kid string) (aauth.JWK, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return aauth.JWK{}, err
	}
	var jwk aauth.JWK
	if err := json.Unmarshal(b, &jwk); err != nil {
		return aauth.JWK{}, err
	}
	jwk.Kid = kid
	return jwk, nil
}

// coreOrigin is the server identifier of an HTTPS URL.
func coreOrigin(raw string) string {
	if i := strings.Index(raw[len("https://"):], "/"); strings.HasPrefix(raw, "https://") && i >= 0 {
		return raw[:len("https://")+i]
	}
	return raw
}

var _ http.Handler = (*personserver.Server)(nil)
