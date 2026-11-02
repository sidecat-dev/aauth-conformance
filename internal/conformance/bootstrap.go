package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Bootstrap roles grade draft-hardt-aauth-bootstrap at the pinned commit. The
// draft is informational and uses no BCP 14 keywords (line 130), so each
// protocol clause is a core or Signature-Key requirement the draft applies;
// its own guidance is graded as recommended, and the routes and bodies the
// draft leaves to each AP (lines 371 and 410) are this suite's adapter
// contract.
const (
	// BootstrapProviderRole is a hosted Agent Provider: enrollment, two-key
	// and single-key refresh, and sub-agent issuance.
	BootstrapProviderRole = "bootstrap.agent-provider"
	// BootstrapAgentRole is the enrolling Agent: enrollment, refresh and a
	// parent's sub-agent request.
	BootstrapAgentRole = "bootstrap.agent"
	// BootstrapSelfHostedRole is a self-hosted domain that is its own AP for
	// several agents and their sub-agents.
	BootstrapSelfHostedRole = "bootstrap.self-hosted"
)

// BootstrapFixture is fixture.json extensions.bootstrap.
type BootstrapFixture struct {
	EnrollmentPath       string            `json:"enrollment_path"`
	RefreshPath          string            `json:"refresh_path"`
	SingleKeyRefreshPath string            `json:"single_key_refresh_path"`
	SubagentPath         string            `json:"subagent_path"`
	IssuePath            string            `json:"issue_path"`
	AgentLifetime        int64             `json:"agent_lifetime"`
	Seeds                map[string]string `json:"seeds_hex"`
	Discriminator        string            `json:"discriminator"`
	ForeignAP            EventsIdentity    `json:"foreign_ap"`
}

// bootstrapSeedNames are the fixture keys a scenario may name.
var bootstrapSeedNames = []string{"durable", "other_durable", "ephemeral", "second_ephemeral", "subagent"}

func (b BootstrapFixture) seed(name string) string {
	if name == "ap" {
		return ""
	}
	return b.Seeds[name]
}

func bootstrapFixture(f Fixture) (BootstrapFixture, error) {
	var b BootstrapFixture
	if err := DecodeExtension(f, "bootstrap", &b); err != nil {
		return b, err
	}
	paths := []string{b.EnrollmentPath, b.RefreshPath, b.SingleKeyRefreshPath, b.SubagentPath, b.IssuePath}
	for i, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\r\n") || slices.Contains(paths[:i], p) || strings.HasPrefix(p, "/.well-known/") {
			return b, fmt.Errorf("bootstrap fixture paths must be distinct origin-relative paths")
		}
	}
	if b.AgentLifetime <= 300 || b.AgentLifetime > 86400 || f.Person == nil {
		return b, fmt.Errorf("bootstrap fixture needs an agent lifetime above the refresh margin and a Person Server")
	}
	if len(b.Seeds) != len(bootstrapSeedNames) {
		return b, fmt.Errorf("bootstrap fixture names exactly the seeds %v", bootstrapSeedNames)
	}
	seen := map[string]bool{strings.ToLower(f.APSeed): true, strings.ToLower(f.AgentSeed): true}
	for _, name := range bootstrapSeedNames {
		seed := b.Seeds[name]
		if !validSeed(seed) || seen[seed] {
			return b, fmt.Errorf("bootstrap seed %q must be a distinct lowercase 32-byte hex seed", name)
		}
		seen[seed] = true
	}
	foreign, err := url.Parse(b.ForeignAP.Issuer)
	if err != nil || foreign.Scheme != "https" || foreign.Host == "" || foreign.Path != "" || b.ForeignAP.Issuer == f.Issuer || !validSeed(b.ForeignAP.Seed) || seen[b.ForeignAP.Seed] || b.ForeignAP.Kid == "" {
		return b, fmt.Errorf("bootstrap foreign_ap must be another HTTPS issuer with its own seed")
	}
	if b.Discriminator == "" || !agentLocalRE.MatchString(b.Discriminator) || strings.Contains(b.Discriminator, "+") {
		return b, fmt.Errorf("bootstrap discriminator must be a nonempty local-part segment without +")
	}
	return b, nil
}

// Scenario inputs.
type bootstrapProviderInput struct {
	Flow     string `json:"flow"`
	Mutation string `json:"mutation"`
}
type bootstrapAgentInput struct {
	Operations []string `json:"operations"`
	// Remaining gives, per renew operation, the seconds left before the
	// current agent token's exp at the clock the harness sets for it.
	Remaining []int64 `json:"remaining,omitempty"`
}
type bootstrapIssue struct {
	Agent         string `json:"agent,omitempty"`
	Key           string `json:"key"`
	Parent        int    `json:"parent,omitempty"`
	Discriminator string `json:"discriminator,omitempty"`
}
type bootstrapSelfInput struct {
	Issues   []bootstrapIssue `json:"issues"`
	Metadata bool             `json:"metadata,omitempty"`
}

var bootstrapProviderFlows = map[string][]string{
	"refresh":    {"none", "unenrolled", "jkt-iss", "jkt-typ", "jkt-signature", "jkt-expired", "proof-key"},
	"rotate":     {"none"},
	"installs":   {"none"},
	"single-key": {"none"},
	"subagent":   {"none", "no-discriminator", "nested", "foreign-parent", "expired-parent"},
}

// bootstrapProviderStages lists, in order, the requests a flow sends.
func bootstrapProviderStages(in bootstrapProviderInput) []string {
	switch {
	case in.Flow == "rotate":
		return []string{"enroll", "refresh", "refresh-2"}
	case in.Flow == "installs":
		return []string{"enroll", "refresh", "enroll-other", "refresh-other"}
	case in.Flow == "subagent" && in.Mutation == "nested":
		return []string{"enroll", "refresh", "subagent-1", "subagent"}
	case in.Flow == "subagent" && (in.Mutation == "foreign-parent" || in.Mutation == "expired-parent"):
		return []string{"subagent"}
	case in.Flow == "subagent":
		return []string{"enroll", "refresh", "subagent"}
	}
	return []string{"enroll", "refresh"}
}

// Token properties the bootstrap-token kind grades, by the kind of stage
// whose response carries the token.
var (
	bootstrapTopLevelProperties = []string{"signature", "claims", "identifier", "top-level", "key", "ps", "lifetime"}
	bootstrapSubagentProperties = []string{"signature", "claims", "identifier", "key", "subagent-identity", "subagent-claims"}
	bootstrapAgentProperties    = map[string][]string{
		"enroll":     {"hwk-proof", "body-coverage"},
		"refresh":    {"naming-jwt", "durable-anchor", "ephemeral-proof", "naming-jti", "fresh-ephemeral", "body-coverage"},
		"single-key": {"single-key-proof", "body-coverage"},
		"subagent":   {"parent-proof", "subagent-key", "durable-absent", "body-coverage"},
		"call":       {"refreshed-token"},
		"renew":      {"refresh-sent", "margin-refresh"},
	}
)

func init() {
	RegisterRole(BootstrapProviderRole, ExtensionRole{Kinds: []string{"bootstrap-token", "bootstrap-no-token"}, Validate: validateBootstrapProvider, Run: runBootstrapProvider})
	RegisterRole(BootstrapAgentRole, ExtensionRole{Kinds: []string{"bootstrap-request"}, Validate: validateBootstrapAgent, Run: runBootstrapAgent})
	RegisterRole(BootstrapSelfHostedRole, ExtensionRole{Kinds: []string{"bootstrap-token", "bootstrap-no-token", "bootstrap-jwks"}, Validate: validateBootstrapSelf, Run: runBootstrapSelf})
}

// bootstrapAssertions checks stages, booleans and properties: own maps each
// role kind to the properties allowed at a stage.
func bootstrapAssertions(s Scenario, stages []string, own map[string]func(stage string) []string) error {
	for _, a := range s.Assertions {
		if !slices.Contains(stages, a.Stage) {
			return fmt.Errorf("%s/%s: stage %q is not observed in this scenario", s.ID, a.ID, a.Stage)
		}
		allowed, ok := own[a.Kind]
		if !ok {
			continue
		}
		var b any
		json.Unmarshal(a.Equals, &b)
		if _, isBool := b.(bool); !isBool {
			return fmt.Errorf("%s/%s: %s needs a boolean", s.ID, a.ID, a.Kind)
		}
		if properties := allowed(a.Stage); properties == nil && a.Member != "" || properties != nil && !slices.Contains(properties, a.Member) {
			return fmt.Errorf("%s/%s: %s member %q is not graded at stage %s", s.ID, a.ID, a.Kind, a.Member, a.Stage)
		}
	}
	return nil
}

func tokenProperties(stage string) []string {
	if strings.HasPrefix(stage, "subagent") || stage == "issue-sub" {
		return bootstrapSubagentProperties
	}
	properties := slices.Clone(bootstrapTopLevelProperties)
	switch stage {
	case "refresh-2":
		properties = append(properties, "same-subject")
	case "refresh-other":
		properties = append(properties, "new-subject")
	}
	return properties
}

func validateBootstrapProvider(f Fixture, s Scenario) error {
	if _, err := bootstrapFixture(f); err != nil {
		return err
	}
	var in bootstrapProviderInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains(bootstrapProviderFlows[in.Flow], in.Mutation) {
		return fmt.Errorf("%s: unsupported bootstrap flow %q or mutation %q", s.ID, in.Flow, in.Mutation)
	}
	stages := bootstrapProviderStages(in)
	for _, a := range s.Assertions {
		if a.Kind == "bootstrap-token" && (a.Stage == "enroll" || a.Stage == "enroll-other") {
			return fmt.Errorf("%s/%s: enrollment returns no agent token", s.ID, a.ID)
		}
	}
	return bootstrapAssertions(s, stages, map[string]func(string) []string{
		"bootstrap-token":    tokenProperties,
		"bootstrap-no-token": func(string) []string { return nil },
	})
}

// bootstrapAgentStages names each operation's stage: the second refresh is
// refresh-2 and the second renew renew-2. A renew follows a two-key refresh,
// and only another renew may follow it, because it moves the harness clock.
func bootstrapAgentStages(in bootstrapAgentInput) ([]string, error) {
	stages := []string{}
	refreshed, renews := false, 0
	for i, op := range in.Operations {
		switch {
		case renews > 0 && op != "renew":
			return nil, fmt.Errorf("operation %d %q: only renew may follow a renew", i+1, op)
		case op == "enroll" && i == 0:
			stages = append(stages, "enroll")
		case op == "refresh" && i > 0:
			if refreshed {
				if slices.Contains(stages, "refresh-2") {
					return nil, fmt.Errorf("at most two refreshes")
				}
				stages = append(stages, "refresh-2")
			} else {
				stages = append(stages, "refresh")
			}
			refreshed = true
		case op == "single-key" && i > 0 && !slices.Contains(stages, op):
			stages = append(stages, op)
			refreshed = true
		case (op == "subagent" || op == "call") && refreshed && !slices.Contains(stages, op):
			stages = append(stages, op)
		case op == "renew" && slices.Contains(stages, "refresh") && renews < 2:
			renews++
			stages = append(stages, map[int]string{1: "renew", 2: "renew-2"}[renews])
		default:
			return nil, fmt.Errorf("operation %d %q: enroll first, refresh or single-key after it, subagent or call after a refresh, each once, and at most two renews last", i+1, op)
		}
	}
	if renews != len(in.Remaining) {
		return nil, fmt.Errorf("remaining needs one entry per renew")
	}
	return stages, nil
}

func agentStageOperation(stage string) string {
	return strings.TrimSuffix(stage, "-2")
}

func validateBootstrapAgent(f Fixture, s Scenario) error {
	b, err := bootstrapFixture(f)
	if err != nil {
		return err
	}
	var in bootstrapAgentInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	stages, err := bootstrapAgentStages(in)
	if err != nil {
		return fmt.Errorf("%s: %w", s.ID, err)
	}
	for _, left := range in.Remaining {
		if left <= 0 || left >= b.AgentLifetime {
			return fmt.Errorf("%s: each remaining is above 0 and below the agent lifetime", s.ID)
		}
	}
	for _, a := range s.Assertions {
		if a.Kind != "bootstrap-request" {
			return fmt.Errorf("%s/%s: the Agent role grades only bootstrap-request", s.ID, a.ID)
		}
	}
	return bootstrapAssertions(s, stages, map[string]func(string) []string{
		"bootstrap-request": func(stage string) []string { return bootstrapAgentProperties[agentStageOperation(stage)] },
	})
}

// bootstrapSelfStages names issue-1 … issue-N, then metadata and jwks.
func bootstrapSelfStages(in bootstrapSelfInput) []string {
	stages := []string{}
	for i := range in.Issues {
		stages = append(stages, fmt.Sprintf("issue-%d", i+1))
	}
	if in.Metadata {
		stages = append(stages, "metadata", "jwks")
	}
	return stages
}

func validateBootstrapSelf(f Fixture, s Scenario) error {
	if _, err := bootstrapFixture(f); err != nil {
		return err
	}
	var in bootstrapSelfInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if len(in.Issues) > 6 || len(in.Issues) == 0 && !in.Metadata {
		return fmt.Errorf("%s: one to six issues, or metadata", s.ID)
	}
	subagent := map[string]bool{}
	for i, issue := range in.Issues {
		stage := fmt.Sprintf("issue-%d", i+1)
		if issue.Key != "ap" && !slices.Contains(bootstrapSeedNames, issue.Key) {
			return fmt.Errorf("%s: %s names unknown key %q", s.ID, stage, issue.Key)
		}
		switch {
		case issue.Parent == 0 && issue.Agent != "" && issue.Discriminator == "" && agentLocalRE.MatchString(issue.Agent) && !strings.Contains(issue.Agent, "+"):
		case issue.Parent > 0 && issue.Parent <= i && issue.Agent == "" && issue.Discriminator != "" && agentLocalRE.MatchString(issue.Discriminator) && !strings.Contains(issue.Discriminator, "+"):
			subagent[stage] = true
		default:
			return fmt.Errorf("%s: %s is a top-level agent with a local name or a sub-agent of an earlier issue with a discriminator", s.ID, stage)
		}
	}
	return bootstrapAssertions(s, bootstrapSelfStages(in), map[string]func(string) []string{
		"bootstrap-token": func(stage string) []string {
			if subagent[stage] {
				return tokenProperties("issue-sub")
			}
			if strings.HasPrefix(stage, "issue-") {
				return append(tokenProperties(stage), "distinct-subject")
			}
			return []string{}
		},
		"bootstrap-no-token": func(stage string) []string {
			if strings.HasPrefix(stage, "issue-") {
				return nil
			}
			return []string{}
		},
		"bootstrap-jwks": func(stage string) []string {
			if stage == "jwks" {
				return []string{"ap-key", "agent-keys-absent"}
			}
			return []string{}
		},
	})
}

// bootstrapLauncher is the bootstrap extension every Bootstrap launcher reads.
type bootstrapLauncher struct {
	APSeed               string `json:"ap_seed_hex,omitempty"`
	APKid                string `json:"ap_kid,omitempty"`
	EnrollmentPath       string `json:"enrollment_path,omitempty"`
	RefreshPath          string `json:"refresh_path,omitempty"`
	SingleKeyRefreshPath string `json:"single_key_refresh_path,omitempty"`
	SubagentPath         string `json:"subagent_path,omitempty"`
	IssuePath            string `json:"issue_path,omitempty"`
	AgentLifetime        int64  `json:"agent_lifetime,omitempty"`
	PersonServer         string `json:"person_server,omitempty"`
}

// bootstrapCase is one scenario's harness. config is the launcher bootstrap;
// run drives the started launcher.
type bootstrapCase struct {
	config func() Bootstrap
	run    func(ctx context.Context, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error)
	close  func()
}

// runBootstrapRole starts a fresh launcher per scenario, as the Events roles
// do, and grades generic kinds against stage responses and role kinds from
// the case's own results. A scenario none of whose clauses a target claims
// is not run for it: an unclaimed case cannot pass, and running it would only
// exercise the launcher's refusal of an operation its library does not offer.
func runBootstrapRole(ctx context.Context, s Suite, targets Targets, o Options, report Report, prepare func(Fixture, BootstrapFixture, Scenario) (bootstrapCase, error)) Report {
	b, fixtureErr := bootstrapFixture(s.Fixture)
	for _, target := range targets.Implementations {
		result := Run{Target: target}
		for _, scenario := range s.Scenarios {
			c := Case{ID: scenario.ID}
			stages, own := map[string]*Response{}, map[string]Result{}
			execution := ""
			offered := target.Unavailable == "" && slices.ContainsFunc(scenario.Assertions, func(a Assertion) bool { return slices.Contains(target.Claims, a.Clause) })
			if offered {
				stages, c.Exchanges, own, execution = runBootstrapCase(ctx, s.Fixture, b, fixtureErr, scenario, target, o, prepare)
			}
			c.Error = execution
			for _, a := range scenario.Assertions {
				if !offered {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: sigkeyNotOffered(target)})
					continue
				}
				c.Results = append(c.Results, Grade(a, target.Claims, execution, stages[a.Stage], func(a Assertion) Result {
					if r := own[a.ID]; r.State != "" {
						return r
					}
					return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "no observation for this assertion"}
				}))
			}
			result.Cases = append(result.Cases, c)
		}
		report.Runs = append(report.Runs, result)
	}
	return report
}

func runBootstrapCase(ctx context.Context, f Fixture, b BootstrapFixture, fixtureErr error, scenario Scenario, target Target, o Options, prepare func(Fixture, BootstrapFixture, Scenario) (bootstrapCase, error)) (stages map[string]*Response, exchanges []PersonExchange, own map[string]Result, execution string) {
	stages, own = map[string]*Response{}, map[string]Result{}
	if fixtureErr != nil {
		return stages, nil, own, fixtureErr.Error()
	}
	harness, err := prepare(f, b, scenario)
	if err != nil {
		return stages, nil, own, err.Error()
	}
	if harness.close != nil {
		defer harness.close()
	}
	ready, stop, err := startAdapter(ctx, target, harness.config(), o)
	if err != nil {
		return stages, nil, own, err.Error()
	}
	defer stop()
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("bootstrap case panicked: %v", recovered)
			}
		}()
		stages, exchanges, own, err = harness.run(ctx, ready, o)
	}()
	if err != nil {
		execution = err.Error()
	}
	return stages, exchanges, own, execution
}

// agentLocalRE is the local part Agent Identifiers allows (core line 488).
var agentLocalRE = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,255}$`)

// splitAgentIdentifier returns the local and domain parts of aauth:local@domain.
func splitAgentIdentifier(id string) (string, string, bool) {
	rest, ok := strings.CutPrefix(id, "aauth:")
	if !ok {
		return "", "", false
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return "", "", false
	}
	local, domain := rest[:at], rest[at+1:]
	if !agentLocalRE.MatchString(local) || domain == "" || strings.ContainsAny(domain, "/:@?#") {
		return "", "", false
	}
	return local, domain, true
}

// tokenExpectation is what one issued agent token must carry.
type tokenExpectation struct {
	issuer string
	keys   keySet
	key    ed25519.PublicKey
	ps     string
	// parent holds the parent's verified claims for a sub-agent token.
	parent        map[string]any
	discriminator string
	// earlier holds subjects a distinct-subject check compares against.
	earlier []string
}

// tokenObservation is the independent reading of one issued agent token.
type tokenObservation struct {
	Token      string          `json:"token,omitempty"`
	Claims     map[string]any  `json:"claims,omitempty"`
	Properties map[string]bool `json:"properties"`
	Problems   []string        `json:"problems,omitempty"`
}

func (o tokenObservation) subject() string {
	sub, _ := o.Claims["sub"].(string)
	return sub
}

// observeAgentToken verifies an issued agent token's signature under the
// AP's keys and reads each property the bootstrap-token kind grades.
func observeAgentToken(f Fixture, compact string, e tokenExpectation) tokenObservation {
	o := tokenObservation{Token: compact, Properties: map[string]bool{}}
	head, claims, err := verifyJWTWith(compact, e.keys, "aa-agent+jwt")
	o.Claims = claims
	if claims == nil {
		o.Claims = unverifiedClaims(compact)
	}
	note := func(property string, ok bool, problem string) {
		o.Properties[property] = ok
		if !ok {
			o.Problems = append(o.Problems, property+": "+problem)
		}
	}
	note("signature", err == nil && head["alg"] == "Ed25519", "the JWT does not verify as aa-agent+jwt under the AP key its kid names")
	if claims == nil {
		claims = map[string]any{}
	}
	sub, _ := claims["sub"].(string)
	jti, _ := claims["jti"].(string)
	iat, iatOK := claims["iat"].(float64)
	exp, expOK := claims["exp"].(float64)
	note("claims", claims["iss"] == e.issuer && claims["dwk"] == "aauth-agent.json" && jti != "" && iatOK && f.issuedNow(iat) && expOK && exp > iat && exp > float64(f.Now),
		"iss, dwk, jti, iat at the fixture clock and exp after iat are required")
	issuer, _ := url.Parse(e.issuer)
	local, domain, valid := splitAgentIdentifier(sub)
	note("identifier", valid && issuer != nil && domain == issuer.Hostname() && (e.parent != nil || !strings.Contains(local, "+")),
		"sub must be aauth:local@domain with the AP's domain, and a top-level local part has no +")
	_, hasParent := claims["parent_agent"]
	note("top-level", !hasParent, "a top-level agent token carries no parent_agent")
	cnf, _ := claims["cnf"].(map[string]any)
	note("key", cnf != nil && bytes.Equal(confirmationPublicKey(cnf["jwk"]), e.key), "cnf.jwk must be the requested key with alg Ed25519")
	ps, hasPS := claims["ps"]
	note("ps", e.ps == "" && !hasPS || ps == e.ps, "ps must be the configured Person Server")
	note("lifetime", iatOK && expOK && exp-iat > 300 && exp-iat <= 86400, "lifetime above the five-minute refresh margin and at most 24 hours")
	if e.parent != nil {
		parentSub, _ := e.parent["sub"].(string)
		parentLocal, parentDomain, _ := splitAgentIdentifier(parentSub)
		discriminator, discriminated := strings.CutPrefix(local, parentLocal+"+")
		note("subagent-identity", claims["iss"] == e.parent["iss"] && claims["parent_agent"] == parentSub && valid && domain == parentDomain && discriminated && discriminator != "",
			"iss equals the parent's, parent_agent names the parent, and local is the parent's local, +, and a discriminator")
		parentExp, _ := e.parent["exp"].(float64)
		parentPS, parentHasPS := e.parent["ps"]
		note("subagent-claims", (parentHasPS && ps == parentPS || !parentHasPS && !hasPS) && expOK && exp <= parentExp && (e.discriminator == "" || discriminator == e.discriminator),
			"ps copied from the parent, exp not after the parent's, and the offered discriminator")
	}
	note("distinct-subject", sub != "" && !slices.Contains(e.earlier, sub), "each agent gets its own sub")
	return o
}

// gradeToken records the token properties a scenario asserts at a stage.
func gradeToken(s Scenario, stage string, o tokenObservation, detail string, own map[string]Result) {
	for _, a := range s.Assertions {
		if a.Stage != stage || a.Kind != "bootstrap-token" {
			continue
		}
		value, known := o.Properties[a.Member]
		reason := detail
		if reason == "" && !value {
			reason = strings.Join(o.Problems, "; ")
		}
		if !known && reason == "" {
			reason = "property not observed"
		}
		own[a.ID] = CompareResult(a, value, reason)
		own[a.ID] = withActual(own[a.ID], o.Claims)
	}
}

// issuedToken reads agent_token from a 200 JSON response.
func issuedToken(r *Response) (string, error) {
	if r == nil {
		return "", fmt.Errorf("no response")
	}
	if r.Status != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", r.Status, strings.TrimSpace(string(r.Body)))
	}
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return "", fmt.Errorf("response is not a JSON object: %v", err)
	}
	token, ok := body["agent_token"].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("response has no agent_token")
	}
	return token, nil
}

// noToken grades a refusal: a 4xx response that releases no agent token.
func noToken(r *Response) (bool, string) {
	if r == nil {
		return false, "no response"
	}
	if r.Status < 400 || r.Status > 499 {
		return false, fmt.Sprintf("status %d is not a 4xx refusal", r.Status)
	}
	var body map[string]any
	if json.Unmarshal(r.Body, &body) == nil {
		if _, present := body["agent_token"]; present {
			return false, "the refusal carries agent_token"
		}
	}
	return true, ""
}

func gradeNoToken(s Scenario, stage string, r *Response, own map[string]Result) {
	for _, a := range s.Assertions {
		if a.Stage == stage && a.Kind == "bootstrap-no-token" {
			ok, detail := noToken(r)
			own[a.ID] = CompareResult(a, ok, detail)
		}
	}
}

// mintJOSE signs a JWT with an explicit protected header.
func mintJOSE(seed string, header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(seedKey(seed), []byte(signed)))
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of an Ed25519 public key.
func jwkThumbprint(key ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func seedPublic(seed string) ed25519.PublicKey {
	return seedKey(seed).Public().(ed25519.PublicKey)
}

func hostOf(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
