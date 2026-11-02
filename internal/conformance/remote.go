package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// Deployment names the servers an implementer runs, per suite role. Remote
// mode plays every other party itself over HTTPS: the Agent, the Agent
// Provider, and the Resource or Person Server a role does not name.
type Deployment struct {
	Version  int                   `json:"version"`
	ID       string                `json:"id"`
	Revision string                `json:"revision"`
	Roles    map[string]RemoteRole `json:"roles"`
}

// RemoteRole names one suite role's deployed servers. Resource is the URL of
// a protected resource; the servers are named by their issuer identifiers.
type RemoteRole struct {
	Resource          string `json:"resource,omitempty"`
	PersonServer      string `json:"person_server,omitempty"`
	AccessServer      string `json:"access_server,omitempty"`
	AgentProvider     string `json:"agent_provider,omitempty"`
	SupervisionServer string `json:"supervision_server,omitempty"`
	// Agent is the agent identifier a deployed Agent Provider serves for the
	// suite's Agent, which holds the fixture's agent key.
	Agent string `json:"agent,omitempty"`
	// Control is the HTTPS URL under which the deployment serves the host
	// controls launchers serve (ADAPTERS.md), such as /__fixture/fire. It is
	// a test hook, not protocol; scenarios that need one are not exercised
	// without it.
	Control string `json:"control,omitempty"`
	// Claims narrows the graded clauses. Empty claims the role's protocol
	// and test-profile clauses, as build-adapters does for a launcher.
	Claims []string `json:"claims,omitempty"`
}

// RemoteOptions bound one remote run. Skew is how far, in seconds, a
// server's issued-at time may be from the suite's clock.
type RemoteOptions struct {
	Timeout time.Duration
	Skew    int64
}

// remoteDriver runs one suite role against deployed servers.
type remoteDriver struct {
	// requires lists the servers the role cannot run without.
	requires []string
	// discover names, per named server, the metadata document the role
	// reads from it and whether it verifies that server's signatures.
	discover map[string]remoteDocument
	// parties lists suite-played parties, beyond the fixture's Agent
	// Provider, Resource and Person Server, a deployment discovers.
	parties func(Fixture) []harnessParty
	// gap says why a scenario cannot be exercised remotely, or "".
	gap func(Scenario, RemoteRole) string
	// unobserved lists stages a remote run cannot see, and why.
	unobserved func(Scenario) ([]string, string)
	// fixture rebases the suite fixture for one case. Without it the
	// Resource, Person Server and Access Server the deployment names
	// replace the fixture's (RemoteRole.fixture).
	fixture func(base Fixture, s Scenario, r *RemoteRun) Fixture
	// run executes one case; the context carries the RemoteRun.
	run func(context.Context, Fixture, Scenario, Target, Options) Case
}

// remoteDocument is a metadata document remote mode fetches from a named
// server. With Keys the role verifies the server's signatures, so the
// document must name a jwks_uri with a usable key; without, keys are read
// when the document names a jwks_uri.
type remoteDocument struct {
	Name string
	Keys bool
}

const (
	partyResource    = "resource"
	partyPerson      = "person_server"
	partyAccess      = "access_server"
	partyProvider    = "agent_provider"
	partySupervision = "supervision_server"
	partyAgent       = "agent"
	partyControl     = "control"
)

var remoteDrivers = map[string]remoteDriver{}

// registerRemote adds a role's remote driver; role files call it from init.
func registerRemote(role string, d remoteDriver) {
	if _, exists := remoteDrivers[role]; exists || d.run == nil {
		panic("invalid or duplicate remote driver " + role)
	}
	remoteDrivers[role] = d
}

func init() {
	registerRemote(ResourceRole, remoteDriver{
		requires: []string{partyResource},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			return runResourceCase(ctx, f, s, t, "", o, nil)
		},
	})
	registerRemote(PersonServerRole, remoteDriver{
		requires: []string{partyPerson},
		discover: map[string]remoteDocument{partyPerson: {"aauth-person.json", true}},
		gap: func(s Scenario, _ RemoteRole) string {
			if s.Person.Mutation == "expired-presented" {
				return "re-signs the Person Server's own token, which needs its private key"
			}
			return ""
		},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			return runPersonCase(ctx, f, s, t, "", o, nil)
		},
	})
	registerRemote(FederatedRole, remoteDriver{
		requires: []string{partyResource, partyAccess},
		discover: map[string]remoteDocument{partyResource: {"aauth-resource.json", true}, partyPerson: {"aauth-person.json", true}, partyAccess: {"aauth-access.json", true}},
		gap:      federatedGap,
		unobserved: func(s Scenario) ([]string, string) {
			if s.Federated.HarnessPS {
				return nil, ""
			}
			return []string{"handoff", "access"}, "the Person Server's request to the Access Server is not observable remotely"
		},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			return runFederatedCase(ctx, f, s, t, "", o, nil, nil)
		},
	})
}

func federatedGap(s Scenario, r RemoteRole) string {
	m := s.Federated.Mutation
	switch {
	case s.Federated.Budget != "":
		return "uses the launcher's fixed budget paths and X-Fixture cost headers"
	case s.Federated.HarnessPS && (strings.HasPrefix(m, "as-resource-") || m == "as-denial"):
		return "re-signs the Resource's challenge, which needs the Resource's private key"
	case s.Federated.HarnessPS:
		return ""
	case m != "none" && m != "short-agent":
		return "injects a fault between the Person Server and the Access Server"
	case r.PersonServer == "":
		return "the deployment names no person_server for this role"
	}
	return ""
}

// RemoteRoles lists the suite roles remote mode can run.
func RemoteRoles() []string {
	roles := []string{}
	for _, role := range Roles() {
		if _, ok := remoteDrivers[role]; ok {
			roles = append(roles, role)
		}
	}
	return roles
}

// ValidateDeployment checks a deployment file against the suite.
func ValidateDeployment(d Deployment, s Suite) error {
	if d.Version != 1 || d.ID == "" || d.Revision == "" || len(d.Roles) == 0 {
		return fmt.Errorf("deployment needs version 1, id, revision and at least one role")
	}
	harness := map[string]bool{}
	for _, name := range HarnessNames(s.Fixture) {
		harness[name] = true
	}
	for role, r := range d.Roles {
		driver, ok := remoteDrivers[role]
		if !ok {
			return fmt.Errorf("remote mode cannot run %q; it runs %s", role, strings.Join(RemoteRoles(), ", "))
		}
		servers := r.servers()
		for _, party := range driver.requires {
			if servers[party] == "" {
				return fmt.Errorf("%s needs %s", role, party)
			}
		}
		for party, value := range servers {
			identifier := value
			switch party {
			case partyResource:
				identifier = resourceIdentifier(value)
				if !resourceURL(value) {
					return fmt.Errorf("%s resource %q must be an HTTPS URL with a path and no port, query or fragment", role, value)
				}
			case partyControl:
				identifier = resourceIdentifier(value)
				if !endpointURL(value) {
					return fmt.Errorf("%s control %q must be an HTTPS URL with no query or fragment", role, value)
				}
			case partyAgent:
				if !agentIdentifier(value) {
					return fmt.Errorf("%s agent %q must be an agent identifier, aauth:local@domain", role, value)
				}
				continue
			}
			if u, err := url.Parse(identifier); err != nil || harness[u.Hostname()] {
				return fmt.Errorf("%s %s %q must not use a name the suite serves", role, party, value)
			}
			if party != partyControl && !serverIdentifier(identifier) {
				return fmt.Errorf("%s %s %q must be an HTTPS server identifier", role, party, value)
			}
		}
		known := Claims(s, role)
		known = append(known, RecommendedClaims(s, role)...)
		for _, claim := range r.Claims {
			if !slices.Contains(known, claim) {
				return fmt.Errorf("%s does not have clause %q", role, claim)
			}
		}
	}
	return nil
}

// servers lists what the role names, by party: its servers, and the agent
// and control when it names them.
func (r RemoteRole) servers() map[string]string {
	servers := map[string]string{}
	for party, value := range map[string]string{partyResource: r.Resource, partyPerson: r.PersonServer, partyAccess: r.AccessServer,
		partyProvider: r.AgentProvider, partySupervision: r.SupervisionServer, partyAgent: r.Agent, partyControl: r.Control} {
		if value != "" {
			servers[party] = value
		}
	}
	return servers
}

// agentIdentifier applies the protocol's agent identifier shape: aauth:,
// a local part, @ and a lowercase domain.
func agentIdentifier(value string) bool {
	local, domain, ok := strings.Cut(strings.TrimPrefix(value, "aauth:"), "@")
	return ok && strings.HasPrefix(value, "aauth:") && local != "" && domain != "" && domain == strings.ToLower(domain) && !strings.ContainsAny(value, " /?#")
}

// serverIdentifier applies the protocol's Server Identifiers rules.
func serverIdentifier(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Port() == "" && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && value == strings.ToLower(value)
}

func resourceURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && strings.HasPrefix(u.Path, "/") && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func resourceIdentifier(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// RunRemote runs every role the deployment names and returns one report per
// role, in the suite's role order. Exchanges use the context's Network.
func RunRemote(ctx context.Context, s Suite, d Deployment, options RemoteOptions) ([]Report, error) {
	if err := ValidateDeployment(d, s); err != nil {
		return nil, err
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	roles := []string{}
	for role := range d.Roles {
		roles = append(roles, role)
	}
	order := Roles()
	sort.Slice(roles, func(i, j int) bool { return slices.Index(order, roles[i]) < slices.Index(order, roles[j]) })
	reports := []Report{}
	for _, role := range roles {
		selected, err := s.ForRole(role)
		if err != nil {
			return nil, err
		}
		reports = append(reports, runRemoteRole(ctx, selected, role, d, options))
	}
	return reports, nil
}

// RemoteRun is what a remote driver knows about the deployment during one
// role's run: the role as named, each discovered server and the harness that
// serves the suite's parties. Its context carries it to the driver.
type RemoteRun struct {
	Role    RemoteRole
	Servers map[string]RemoteServer
	Harness *Harness
	Skew    int64
}

// RemoteServer is one deployed server as discovered: its metadata document
// and the signing keys its JWKS publishes.
type RemoteServer struct {
	Issuer   string
	Metadata map[string]any
	Keys     keySet
}

// Endpoint returns a string member of the server's metadata.
func (s RemoteServer) Endpoint(member string) string {
	value, _ := s.Metadata[member].(string)
	return value
}

// ControlURL returns the URL of a host-control path under the deployment's
// control, or "" when it names none.
func (r *RemoteRun) ControlURL(path string) string {
	if r.Role.Control == "" {
		return ""
	}
	return strings.TrimSuffix(r.Role.Control, "/") + path
}

// controlGap is the reason a scenario that needs host controls is not
// exercised when the deployment names no control.
func controlGap(r RemoteRole, paths ...string) string {
	if r.Control != "" || len(paths) == 0 {
		return ""
	}
	return "needs the host control " + strings.Join(paths, " and ") + ", and the deployment names no control"
}

type remoteKey struct{}

func withRemote(ctx context.Context, r *RemoteRun) context.Context {
	return context.WithValue(ctx, remoteKey{}, r)
}

// remoteFrom returns the remote run a driver's case belongs to, or nil for
// a launcher run.
func remoteFrom(ctx context.Context) *RemoteRun {
	r, _ := ctx.Value(remoteKey{}).(*RemoteRun)
	return r
}

func runRemoteRole(ctx context.Context, s Suite, role string, d Deployment, options RemoteOptions) Report {
	r, driver := d.Roles[role], remoteDrivers[role]
	claims := r.Claims
	if len(claims) == 0 {
		claims = Claims(s, role)
	}
	target := Target{ID: d.ID, Revision: d.Revision, Claims: claims, Remote: r.servers()}
	report := Report{Version: 1, Role: role, Transport: "remote", SuiteSHA256: s.Digest, Clock: time.Now().Unix(), Catalog: s.Catalog}
	run := Run{Target: target}
	servers, endpoints, discoveryError := discoverRemote(ctx, r, driver.discover, options.Timeout)
	if discoveryError != nil {
		run.Error = discoveryError.Error()
	}
	harness := harnessFrom(ctx)
	if harness == nil {
		harness = NewHarness(s.Fixture)
	}
	remote := &RemoteRun{Role: r, Servers: servers, Harness: harness, Skew: options.Skew}
	ctx = withRemote(ctx, remote)
	published := map[string]keySet{}
	for party, server := range servers {
		published[party] = server.Keys
	}
	for _, scenario := range s.Scenarios {
		reason := ""
		if driver.gap != nil {
			reason = driver.gap(scenario, r)
		}
		if reason != "" {
			run.Cases = append(run.Cases, unexercisedCase(scenario, target, reason))
			continue
		}
		if discoveryError != nil {
			run.Cases = append(run.Cases, failedCase(scenario, target, discoveryError))
			continue
		}
		var f Fixture
		if driver.fixture != nil {
			f = driver.fixture(s.Fixture, scenario, remote)
		} else {
			f = r.fixture(s.Fixture, scenario, published, endpoints, options.Skew)
		}
		c := driver.run(ctx, f, scenario, target, Options{Timeout: options.Timeout})
		if driver.unobserved != nil {
			stages, why := driver.unobserved(scenario)
			markUnobserved(&c, scenario, stages, why)
		}
		run.Cases = append(run.Cases, c)
	}
	report.Runs = []Run{run}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}

// personEndpoints are the endpoints a deployed Person Server's metadata
// advertises, where the suite's Agent sends its requests.
type personEndpoints struct {
	person, token string
}

// discoverRemote fetches the metadata and signing keys of each named server
// the role reads, and a Person Server's endpoints.
func discoverRemote(ctx context.Context, r RemoteRole, documents map[string]remoteDocument, timeout time.Duration) (map[string]RemoteServer, personEndpoints, error) {
	servers := map[string]RemoteServer{}
	endpoints := personEndpoints{}
	for party, value := range r.servers() {
		document, read := documents[party]
		if !read {
			continue
		}
		issuer := value
		if party == partyResource {
			issuer = resourceIdentifier(value)
		}
		keys, metadata, err := publishedKeys(ctx, issuer, document.Name, timeout, !document.Keys)
		if err != nil {
			return nil, endpoints, fmt.Errorf("discovering %s keys: %w", party, err)
		}
		servers[party] = RemoteServer{Issuer: issuer, Metadata: metadata, Keys: keys}
		if party == partyPerson && document.Name == "aauth-person.json" {
			endpoints.person, _ = metadata["person_token_endpoint"].(string)
			endpoints.token, _ = metadata["auth_token_endpoint"].(string)
			if !endpointURL(endpoints.person) || !endpointURL(endpoints.token) {
				return nil, endpoints, fmt.Errorf("%s/.well-known/%s: person_token_endpoint and auth_token_endpoint must be HTTPS URLs with no query or fragment", issuer, document.Name)
			}
		}
	}
	return servers, endpoints, nil
}

// endpointURL applies the metadata rule for endpoint values: the https
// scheme, and no query string or fragment.
func endpointURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(value, "#")
}

// fixture rebases the suite fixture onto the deployment for one scenario: the
// clock is now, and each named server replaces the fixture identity, keys
// and endpoints of its role. Parties the suite plays keep their fixture
// identities.
func (r RemoteRole) fixture(base Fixture, s Scenario, published map[string]keySet, endpoints personEndpoints, skew int64) Fixture {
	f := base
	f.Now, f.Skew = time.Now().Unix(), skew
	if base.Person != nil {
		person := *base.Person
		f.Person = &person
	}
	if base.Access != nil {
		access := *base.Access
		f.Access = &access
	}
	if r.Resource != "" {
		u, _ := url.Parse(r.Resource)
		f.Origin, f.Path = resourceIdentifier(r.Resource), u.EscapedPath()
		if f.Person != nil {
			f.Person.ResourcePublished = published[partyResource]
		}
	}
	harnessPS := s.Federated != nil && s.Federated.HarnessPS
	if r.PersonServer != "" && f.Person != nil && !harnessPS {
		f.Person.Issuer, f.Person.Published = r.PersonServer, published[partyPerson]
		f.Person.PersonEndpoint, f.Person.TokenEndpoint = endpoints.person, endpoints.token
	}
	if r.AccessServer != "" && f.Access != nil {
		f.Access.Issuer, f.Access.Published = r.AccessServer, published[partyAccess]
	}
	return f
}

func unexercisedCase(s Scenario, t Target, reason string) Case {
	c := Case{ID: s.ID}
	for _, a := range s.Assertions {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: reason}
		if !slices.Contains(t.Claims, a.Clause) {
			result.State, result.Detail = "not_claimed", ""
		}
		c.Results = append(c.Results, result)
	}
	return c
}

func failedCase(s Scenario, t Target, err error) Case {
	c := Case{ID: s.ID, Error: err.Error()}
	for _, a := range s.Assertions {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: err.Error()}
		if !slices.Contains(t.Claims, a.Clause) {
			result.State, result.Detail = "not_claimed", ""
		}
		c.Results = append(c.Results, result)
	}
	return c
}

// markUnobserved records claimed assertions on stages remote mode cannot see
// as not exercised, replacing the runner's missing-stage error.
func markUnobserved(c *Case, s Scenario, stages []string, reason string) {
	for i, a := range s.Assertions {
		if slices.Contains(stages, a.Stage) && c.Results[i].State != "not_claimed" {
			c.Results[i] = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: reason}
		}
	}
}

// rebaseExpected returns the scenario with each expected value that names a
// fixture identity the deployment replaced rewritten to the deployed one, so
// an assertion such as "issuer equals the Supervision Server" grades the
// server under test. Strings are replaced only when they match exactly.
func rebaseExpected(s Scenario, replace map[string]string) Scenario {
	var rewrite func(any) any
	rewrite = func(value any) any {
		switch v := value.(type) {
		case string:
			if deployed, ok := replace[v]; ok {
				return deployed
			}
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				out[i] = rewrite(item)
			}
			return out
		case map[string]any:
			out := map[string]any{}
			for name, item := range v {
				out[name] = rewrite(item)
			}
			return out
		}
		return value
	}
	s.Assertions = slices.Clone(s.Assertions)
	for i, a := range s.Assertions {
		var expected any
		if json.Unmarshal(a.Equals, &expected) != nil {
			continue
		}
		if b, err := json.Marshal(rewrite(expected)); err == nil && !bytes.Equal(b, a.Equals) {
			s.Assertions[i].Equals = b
		}
	}
	return s
}
