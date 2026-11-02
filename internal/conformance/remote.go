package conformance

import (
	"context"
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
	Resource     string `json:"resource,omitempty"`
	PersonServer string `json:"person_server,omitempty"`
	AccessServer string `json:"access_server,omitempty"`
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
	// gap says why a scenario cannot be exercised remotely, or "".
	gap func(Scenario, RemoteRole) string
	// unobserved lists stages a remote run cannot see, and why.
	unobserved func(Scenario) ([]string, string)
	run        func(context.Context, Fixture, Scenario, Target, Options) Case
}

const (
	partyResource = "resource"
	partyPerson   = "person_server"
	partyAccess   = "access_server"
)

var remoteDrivers = map[string]remoteDriver{
	ResourceRole: {
		requires: []string{partyResource},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			return runResourceCase(ctx, f, s, t, "", o, nil)
		},
	},
	PersonServerRole: {
		requires: []string{partyPerson},
		gap: func(s Scenario, _ RemoteRole) string {
			if s.Person.Mutation == "expired-presented" {
				return "re-signs the Person Server's own token, which needs its private key"
			}
			return ""
		},
		run: func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
			return runPersonCase(ctx, f, s, t, "", o, nil)
		},
	},
	FederatedRole: {
		requires: []string{partyResource, partyAccess},
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
	},
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
	for _, party := range harnessParties(s.Fixture) {
		harness[party.issuer] = true
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
			if party == partyResource {
				identifier = resourceIdentifier(value)
				if !resourceURL(value) {
					return fmt.Errorf("%s resource %q must be an HTTPS URL with a path and no port, query or fragment", role, value)
				}
			}
			if !serverIdentifier(identifier) || harness[identifier] {
				return fmt.Errorf("%s %s %q must be an HTTPS server identifier not used by the suite", role, party, value)
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

func (r RemoteRole) servers() map[string]string {
	servers := map[string]string{}
	for party, value := range map[string]string{partyResource: r.Resource, partyPerson: r.PersonServer, partyAccess: r.AccessServer} {
		if value != "" {
			servers[party] = value
		}
	}
	return servers
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

func runRemoteRole(ctx context.Context, s Suite, role string, d Deployment, options RemoteOptions) Report {
	r, driver := d.Roles[role], remoteDrivers[role]
	claims := r.Claims
	if len(claims) == 0 {
		claims = Claims(s, role)
	}
	target := Target{ID: d.ID, Revision: d.Revision, Claims: claims, Remote: r.servers()}
	report := Report{Version: 1, Role: role, Transport: "remote", SuiteSHA256: s.Digest, Clock: time.Now().Unix(), Catalog: s.Catalog}
	run := Run{Target: target}
	published, discoveryError := discoverRemote(ctx, r, options.Timeout)
	if discoveryError != nil {
		run.Error = discoveryError.Error()
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
		f := r.fixture(s.Fixture, scenario, published, options.Skew)
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

// discoverRemote fetches the signing keys each named server publishes.
func discoverRemote(ctx context.Context, r RemoteRole, timeout time.Duration) (map[string]keySet, error) {
	documents := map[string]string{partyPerson: "aauth-person.json", partyAccess: "aauth-access.json"}
	published := map[string]keySet{}
	for party, value := range r.servers() {
		issuer, document := value, documents[party]
		if party == partyResource {
			if r.AccessServer == "" {
				continue // An agent-identity Resource signs nothing the suite checks.
			}
			issuer, document = resourceIdentifier(value), "aauth-resource.json"
		}
		keys, err := publishedKeys(ctx, issuer, document, timeout)
		if err != nil {
			return nil, fmt.Errorf("discovering %s keys: %w", party, err)
		}
		published[party] = keys
	}
	return published, nil
}

// fixture rebases the suite fixture onto the deployment for one scenario: the
// clock is now, and each named server replaces the fixture identity and keys
// of its role. Parties the suite plays keep their fixture identities.
func (r RemoteRole) fixture(base Fixture, s Scenario, published map[string]keySet, skew int64) Fixture {
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
