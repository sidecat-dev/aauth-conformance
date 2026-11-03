// Package conformance runs wire assertions against Resource implementations.
package conformance

import (
	"encoding/json"
	"net/http"
)

type Fixture struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Now     int64  `json:"now"`
	Issuer  string `json:"issuer"`
	Origin  string `json:"origin"`
	Path    string `json:"path"`
	// PersonPath is a second Resource endpoint, one that requires the
	// person's identity (protocol, Person Token Required).
	PersonPath string         `json:"person_path,omitempty"`
	Kid        string         `json:"kid"`
	Subject    string         `json:"subject"`
	APSeed     string         `json:"ap_seed_hex"`
	AgentSeed  string         `json:"agent_seed_hex"`
	Person     *PersonFixture `json:"person_server,omitempty"`
	Access     *AccessFixture `json:"access_server,omitempty"`
	// Extensions holds identities for extension roles, keyed by role family.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
	// Skew is how many seconds a server's issued-at time may differ from Now.
	// Launchers share the fixed clock, so it is zero; remote mode sets it
	// because a deployed server reads its own clock.
	Skew int64 `json:"-"`
	// Enrolled is an agent token a bootstrap provider signed for this run.
	// Remote mode sets it when the deployment names a provider. Launchers
	// leave it nil and mint tokens with the fixture key.
	Enrolled *EnrolledAgent `json:"-"`
}

// issuedNow reports whether a server-chosen issued-at time is Now, within Skew.
func (f Fixture) issuedNow(t float64) bool {
	return t >= float64(f.Now-f.Skew) && t <= float64(f.Now+f.Skew)
}

// signedExpiry reports whether a response's expires_in agrees with the
// signed expiry, counted from the server's issue time.
func (f Fixture) signedExpiry(claims map[string]any, expiresIn int64) bool {
	exp, ok := claims["exp"].(float64)
	return ok && f.issuedNow(exp-float64(expiresIn))
}

type TokenSpec struct {
	IATOffset int64 `json:"iat_offset"`
	EXPOffset int64 `json:"exp_offset"`
	// PS names the fixture Person Server in the Agent token's ps claim.
	PS bool `json:"ps,omitempty"`
}
type RequestSpec struct {
	Headers       map[string]string `json:"headers,omitempty"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Proof         string            `json:"proof"`
	CreatedOffset int64             `json:"created_offset"`
	Covered       []string          `json:"covered"`
	Tamper        bool              `json:"tamper_signature"`
	// Endpoint "person" selects the fixture's person_path, the endpoint
	// that requires a Person token; empty selects the fixture path.
	Endpoint string `json:"endpoint,omitempty"`
	// ResourceMetadataUnpublished makes the person flow's Resource publish
	// no /.well-known/aauth-resource.json, as Core lets a Resource do
	// (Resource Metadata); a fetch of it is answered 404. Absent, the
	// Resource publishes its issuer. Only an Agent scenario at the person
	// endpoint sets it.
	ResourceMetadataUnpublished bool `json:"resource_metadata_unpublished,omitempty"`
}
type Scenario struct {
	Subagent  *SubagentSpec  `json:"subagent,omitempty"`
	Deferred  *DeferredSpec  `json:"deferred,omitempty"`
	Version   int            `json:"version"`
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Role      string         `json:"role_under_test"`
	Given     string         `json:"given"`
	Token     TokenSpec      `json:"token"`
	Request   RequestSpec    `json:"request"`
	Person    *PersonSpec    `json:"person,omitempty"`
	Federated *FederatedSpec `json:"federated,omitempty"`
	// Input carries an extension role's scenario inputs; the role decodes it.
	Input      json.RawMessage `json:"input,omitempty"`
	Assertions []Assertion     `json:"assertions"`
}
type Assertion struct {
	Stage  string          `json:"stage,omitempty"`
	ID     string          `json:"id"`
	Clause string          `json:"clause"`
	Kind   string          `json:"kind"`
	Header string          `json:"header,omitempty"`
	Member string          `json:"member,omitempty"`
	Equals json.RawMessage `json:"equals"`
}
type Source struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}
type Clause struct {
	Role    string `json:"role,omitempty"`
	ID      string `json:"id"`
	Source  string `json:"source"`
	Section string `json:"section"`
	Anchor  string `json:"anchor"`
	Scope   string `json:"scope"`
}
type Catalog struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
	Clauses []Clause `json:"clauses"`
}
type Suite struct {
	Fixture   Fixture
	Catalog   Catalog
	Scenarios []Scenario
	Digest    string
}
type Target struct {
	// Remote names the deployed servers a remote-mode run tested, by party.
	Remote      map[string]string `json:"remote,omitempty"`
	Unavailable string            `json:"unavailable,omitempty"`
	ID          string            `json:"id"`
	Revision    string            `json:"revision"`
	Command     []string          `json:"command"`
	Claims      []string          `json:"claims"`
}
type Targets struct {
	Role            string   `json:"role,omitempty"`
	Version         int      `json:"version"`
	Implementations []Target `json:"implementations"`
}
type AgentProviderTrust struct {
	Issuer    string `json:"issuer"`
	Transport string `json:"transport"`
}
type Bootstrap struct {
	AdditionalAgentProviders []AgentProviderTrust `json:"additional_agent_providers,omitempty"`
	PersonDirect             bool                 `json:"person_direct,omitempty"`
	AccessServer             string               `json:"access_server,omitempty"`
	AccessSeed               string               `json:"access_seed_hex,omitempty"`
	AccessKid                string               `json:"access_kid,omitempty"`
	ResourceSeed             string               `json:"resource_seed_hex,omitempty"`
	FederationTransport      string               `json:"federation_transport,omitempty"`
	PersonServer             string               `json:"person_server,omitempty"`
	PersonSeed               string               `json:"person_seed_hex,omitempty"`
	PersonKid                string               `json:"person_kid,omitempty"`
	PersonSubject            string               `json:"person_subject,omitempty"`
	PersonLifetime           int64                `json:"person_lifetime,omitempty"`
	AuthLifetime             int64                `json:"auth_lifetime,omitempty"`
	PermittedScopes          []string             `json:"permitted_scopes,omitempty"`
	ResourceKid              string               `json:"resource_kid,omitempty"`
	ResourceJWK              map[string]any       `json:"resource_jwk,omitempty"`
	// PersonJWK is the public key of the fixture Person Server, kid
	// PersonKid, for a role that verifies Person tokens it does not issue.
	PersonJWK map[string]any `json:"person_jwk,omitempty"`
	// PersonResource is the Resource endpoint that requires a Person token.
	PersonResource string `json:"person_resource,omitempty"`
	Role           string `json:"role,omitempty"`
	AgentSeed      string `json:"agent_seed_hex,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Version        int    `json:"version"`
	Now            int64  `json:"now"`
	Issuer         string `json:"issuer"`
	Resource       string `json:"resource"`
	APTransport    string `json:"ap_transport"`
	// Extension carries an extension role's launcher configuration.
	Extension json.RawMessage `json:"extension,omitempty"`
}
type Ready struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
}
type Response struct {
	Status  int         `json:"status"`
	Header  http.Header `json:"headers"`
	Trailer http.Header `json:"trailers,omitempty"`
	Body    []byte      `json:"body_base64"`
}
type Result struct {
	Assertion string          `json:"assertion"`
	Clause    string          `json:"clause"`
	State     string          `json:"state"`
	Expected  json.RawMessage `json:"expected"`
	Actual    any             `json:"actual,omitempty"`
	Detail    string          `json:"detail,omitempty"`
}
