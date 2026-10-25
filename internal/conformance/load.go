package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}
func ReadJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if e = Decode(b, v); e != nil {
		return fmt.Errorf("%s: %w", path, e)
	}
	return nil
}

func Load(dir string) (Suite, error) {
	var suite Suite
	files, err := filepath.Glob(filepath.Join(dir, "scenarios", "*.json"))
	if err != nil {
		return suite, err
	}
	if len(files) == 0 {
		return suite, fmt.Errorf("suite contains no scenarios")
	}
	files = append([]string{filepath.Join(dir, "fixture.json"), filepath.Join(dir, "clauses.json")}, files...)
	hash := sha256.New()
	for i, path := range files {
		b, e := os.ReadFile(path)
		if e != nil {
			return suite, e
		}
		rel, _ := filepath.Rel(dir, path)
		fmt.Fprintf(hash, "%s\x00%d\x00", filepath.ToSlash(rel), len(b))
		hash.Write(b)
		var target any
		switch i {
		case 0:
			target = &suite.Fixture
		case 1:
			target = &suite.Catalog
		default:
			suite.Scenarios = append(suite.Scenarios, Scenario{})
			target = &suite.Scenarios[len(suite.Scenarios)-1]
		}
		if e = Decode(b, target); e != nil {
			return suite, fmt.Errorf("%s: %w", path, e)
		}
	}
	suite.Digest = hex.EncodeToString(hash.Sum(nil))
	if err = suite.validate(); err != nil {
		return suite, err
	}
	return suite, nil
}
func (s Suite) validate() error {
	f := s.Fixture
	if f.Version != 1 || f.ID == "" || f.Now < 86400 || f.Now > (1<<33)-86401 || f.Kid == "" || f.Subject == "" {
		return fmt.Errorf("invalid fixture version/identity/clock")
	}
	for _, seed := range []string{f.APSeed, f.AgentSeed} {
		b, e := hex.DecodeString(seed)
		if e != nil || len(b) != 32 {
			return fmt.Errorf("fixture keys must be 32-byte hex seeds")
		}
	}
	for _, origin := range []string{f.Issuer, f.Origin} {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("fixture origins must be HTTPS server identifiers")
		}
	}
	if !strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "?#\r\n") {
		return fmt.Errorf("invalid fixture path")
	}
	if s.Catalog.Version != 1 || len(s.Catalog.Clauses) == 0 {
		return fmt.Errorf("invalid catalog")
	}
	sources := map[string]bool{}
	for _, source := range s.Catalog.Sources {
		commit, e := hex.DecodeString(source.Commit)
		digest, d := hex.DecodeString(source.SHA256)
		if source.ID == "" || sources[source.ID] || e != nil || len(commit) != 20 || d != nil || len(digest) != 32 || !strings.HasPrefix(source.URL, "https://") {
			return fmt.Errorf("invalid pinned source %q", source.ID)
		}
		sources[source.ID] = true
	}
	clauses := map[string]bool{}
	clauseRoles := map[string]string{}
	for _, c := range s.Catalog.Clauses {
		if c.ID == "" || clauses[c.ID] || !sources[c.Source] || c.Section == "" || c.Anchor == "" || !slices.Contains([]string{"protocol", "adapter-contract", "out-of-slice"}, c.Scope) {
			return fmt.Errorf("invalid/duplicate clause %q", c.ID)
		}
		clauses[c.ID] = true
		if clauseRole(c) != ResourceRole && clauseRole(c) != AgentRole && clauseRole(c) != PersonServerRole && clauseRole(c) != FederatedRole && clauseRole(c) != DeferredRole && clauseRole(c) != SubagentRole {
			return fmt.Errorf("unknown clause role")
		}
		clauseRoles[c.ID] = clauseRole(c)
	}
	ids := map[string]bool{}
	for _, scenario := range s.Scenarios {
		if scenario.Version != 1 || scenario.ID == "" || ids[scenario.ID] || !slices.Contains([]string{ResourceRole, AgentRole, PersonServerRole, FederatedRole, DeferredRole, SubagentRole}, scenario.Role) || scenario.Given != f.ID || len(scenario.Assertions) == 0 {
			return fmt.Errorf("invalid scenario %q", scenario.ID)
		}
		ids[scenario.ID] = true
		if scenario.Role == PersonServerRole {
			if f.Person == nil || scenario.Person == nil {
				return fmt.Errorf("Person Server fixture/spec required")
			}
			if err := validatePersonFixture(*f.Person); err != nil {
				return err
			}
			if !slices.Contains([]string{"none", "tampered-proof", "tampered-body", "wrong-aud", "wrong-jkt", "wrong-sub", "wrong-jti", "wrong-ps", "expired-resource", "expired-presented", "denied-scope", "short-parent"}, scenario.Person.Mutation) {
				return fmt.Errorf("unsupported Person Server mutation")
			}
		}
		if scenario.Role == SubagentRole {
			if err := validateSubagentScenario(f, scenario); err != nil {
				return err
			}
		} else if scenario.Subagent != nil {
			return fmt.Errorf("subagent input requires subagent role")
		}
		if scenario.Role == DeferredRole {
			if err := validateDeferredScenario(f, scenario); err != nil {
				return err
			}
		} else if scenario.Deferred != nil {
			return fmt.Errorf("deferred inputs require deferred role")
		}
		if scenario.Role == FederatedRole {
			if err := validateFederatedScenario(f, scenario); err != nil {
				return err
			}
		} else if scenario.Federated != nil {
			return fmt.Errorf("federated inputs require federated role")
		}
		req := scenario.Request
		if scenario.Role == PersonServerRole && (req.Method != "" || req.Path != "" || req.Proof != "" || req.CreatedOffset != 0 || req.Tamper || len(req.Covered) > 0 || len(req.Headers) > 0) {
			return fmt.Errorf("PS request profile is prescribed by person.mutation; request fields are unsupported")
		}
		if req.CreatedOffset < -86400 || req.CreatedOffset > 86400 || scenario.Token.IATOffset < -86400 || scenario.Token.IATOffset > 86400 || scenario.Token.EXPOffset < -86400 || scenario.Token.EXPOffset > 86400 {
			return fmt.Errorf("unsupported request profile in %s", scenario.ID)
		}
		if scenario.Role == ResourceRole && (req.Method != "GET" || req.Path != f.Path || !slices.Contains([]string{"unsigned", "jwt"}, req.Proof) || len(req.Headers) > 0) {
			return fmt.Errorf("invalid Resource request")
		}
		if scenario.Role == AgentRole {
			path, err := url.ParseRequestURI(req.Path)
			if err != nil || path.IsAbs() || !strings.HasPrefix(req.Path, "/") || !slices.Contains([]string{"GET", "POST"}, req.Method) || req.Proof != "sut" || req.CreatedOffset != 0 {
				return fmt.Errorf("invalid Agent request")
			}
			for key := range req.Headers {
				if !strings.EqualFold(key, "Authorization") {
					return fmt.Errorf("only Authorization is supported in Agent profile")
				}
			}
		}
		covered := map[string]bool{}
		for _, c := range req.Covered {
			if covered[c] || !slices.Contains([]string{"@method", "@authority", "@path", "signature-key"}, c) {
				return fmt.Errorf("unsupported/repeated component %s", c)
			}
			covered[c] = true
		}
		assertions := map[string]bool{}
		for _, a := range scenario.Assertions {
			if a.ID == "" || assertions[a.ID] || (!clauses[a.Clause] || clauseRoles[a.Clause] != scenario.Role) || !slices.Contains([]string{"status", "sfv-token", "sfv-strings", "sfv-string-set", "sfv-integer", "sfv-trailer-integer", "sfv-absent", "sfv-trailer-absent", "json-member", "problem-if-present", "wire-preserved", "wire-proof", "wire-token", "wire-created", "wire-covers", "ps-no-token", "ps-jwt", "ps-jwt-subject", "ps-jwt-signature", "ps-jwt-identity", "ps-jwt-key", "ps-jwt-lifetime", "ps-jwt-scope", "ps-jwt-no-authorization", "fed-challenge", "fed-ps-proof", "fed-forwarded", "fed-budget", "fed-consumed", "deferred-pending", "deferred-proof", "deferred-forwarded", "deferred-stable", "subagent-jwt", "subagent-proof", "subagent-forwarded", "subagent-refused", "subagent-pending", "subagent-no-token", "subagent-cancelled"}, a.Kind) || !json.Valid(a.Equals) {
				return fmt.Errorf("invalid assertion %s/%s (clause %q)", scenario.ID, a.ID, a.Clause)
			}
			if (scenario.Role == AgentRole) != strings.HasPrefix(a.Kind, "wire-") || strings.HasPrefix(a.Kind, "ps-") && scenario.Role != PersonServerRole && scenario.Role != FederatedRole && scenario.Role != DeferredRole || strings.HasPrefix(a.Kind, "fed-") && scenario.Role != FederatedRole || strings.HasPrefix(a.Kind, "subagent-") && scenario.Role != SubagentRole {
				return fmt.Errorf("assertion kind does not match role")
			}
			if scenario.Role == PersonServerRole {
				if !slices.Contains([]string{"person", "token"}, a.Stage) || !(strings.HasPrefix(a.Kind, "ps-jwt") || a.Kind == "ps-no-token" || slices.Contains([]string{"status", "sfv-token", "json-member"}, a.Kind)) {
					return fmt.Errorf("invalid Person Server assertion profile")
				}
				if strings.HasPrefix(a.Kind, "ps-jwt") || a.Kind == "ps-no-token" {
					var b any
					json.Unmarshal(a.Equals, &b)
					if _, ok := b.(bool); !ok {
						return fmt.Errorf("PS JWT assertion requires boolean")
					}
				}
			} else if scenario.Role == FederatedRole {
				if !validFederatedAssertion(a) ||
					scenario.Federated.HarnessPS && slices.Contains([]string{"person", "handoff", "token"}, a.Stage) {
					return fmt.Errorf("invalid federation assertion stage/kind")
				}
				if a.Kind != "fed-budget" && a.Kind != "fed-consumed" && (strings.HasPrefix(a.Kind, "fed-") || strings.HasPrefix(a.Kind, "ps-")) {
					var b any
					json.Unmarshal(a.Equals, &b)
					if _, ok := b.(bool); !ok {
						return fmt.Errorf("federation assertion requires boolean")
					}
				}
			} else if scenario.Role == DeferredRole {
				if !validDeferredAssertion(a) {
					return fmt.Errorf("invalid deferred assertion")
				}
			} else if scenario.Role == SubagentRole {
				if !validSubagentAssertion(a) {
					return fmt.Errorf("invalid subagent assertion")
				}
			} else if a.Stage != "" {
				return fmt.Errorf("stage only supported for Person Server")
			}
			assertions[a.ID] = true
			var value any
			json.Unmarshal(a.Equals, &value)
			if slices.Contains([]string{"wire-preserved", "wire-proof", "wire-token"}, a.Kind) {
				if _, ok := value.(bool); !ok {
					return fmt.Errorf("Agent boolean assertion required")
				}
			}
			if a.Kind == "wire-created" {
				if _, ok := value.(float64); !ok {
					return fmt.Errorf("Agent timestamp required")
				}
			}
			if a.Kind == "wire-covers" {
				values, ok := value.([]any)
				if !ok {
					return fmt.Errorf("coverage list required")
				}
				for _, v := range values {
					if _, ok := v.(string); !ok {
						return fmt.Errorf("coverage Strings required")
					}
				}
			}
			if a.Kind == "status" {
				n, ok := value.(float64)
				if !ok || n < 100 || n > 599 || n != float64(int(n)) {
					return fmt.Errorf("status equals must be an HTTP status")
				}
			}
			if a.Kind == "sfv-token" || a.Kind == "problem-if-present" {
				if _, ok := value.(string); !ok {
					return fmt.Errorf("%s equals must be a string", a.Kind)
				}
			}
			if a.Kind == "sfv-token" || (a.Kind == "sfv-strings" || a.Kind == "sfv-string-set") {
				if a.Header == "" || a.Member == "" {
					return fmt.Errorf("SFV assertion needs header/member")
				}
			}
			if a.Kind == "sfv-strings" || a.Kind == "sfv-string-set" {
				list, ok := value.([]any)
				if !ok {
					return fmt.Errorf("sfv-strings equals must be an array")
				}
				for _, v := range list {
					if _, ok := v.(string); !ok {
						return fmt.Errorf("sfv-strings requires strings")
					}
				}
			}
			if a.Kind == "json-member" && a.Member == "" {
				return fmt.Errorf("JSON assertion needs member")
			}
		}
	}
	return nil
}
func ValidateTargets(targets Targets, s Suite) error {
	if targets.Version != 1 || len(targets.Implementations) == 0 {
		return fmt.Errorf("targets version 1 and at least one implementation required")
	}
	known := map[string]bool{}
	for _, c := range s.Catalog.Clauses {
		known[c.ID] = true
	}
	ids := map[string]bool{}
	for _, t := range targets.Implementations {
		if t.ID == "" || ids[t.ID] || t.Revision == "" || (t.Unavailable == "" && (len(t.Command) == 0 || t.Command[0] == "")) || (t.Unavailable != "" && (targetRole(targets.Role) != SubagentRole || len(t.Command) != 0 || len(t.Claims) != 0)) {
			return fmt.Errorf("target requires unique id, revision and command")
		}
		ids[t.ID] = true
		seen := map[string]bool{}
		for _, c := range t.Claims {
			if !known[c] || seen[c] {
				return fmt.Errorf("unknown/repeated claim %q for %s", c, t.ID)
			}
			seen[c] = true
		}
	}
	return nil
}
