package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// GenericKinds are assertion kinds every extension role may use against an
// observed HTTP response.
var GenericKinds = []string{"status", "status-class", "sfv-token", "sfv-token-present", "sfv-strings", "sfv-string-set", "sfv-integer", "sfv-absent", "json-member", "json-path", "header-equals", "problem-if-present"}

// ExtensionRole is a slice specified in its own file. The scenario carries
// role-specific inputs in `input`; the fixture carries role-specific
// identities under `extensions`. Validate decodes both strictly.
type ExtensionRole struct {
	// Kinds are the role's own assertion kinds; GenericKinds stay available.
	Kinds []string
	// Validate checks the scenario's input and assertions against the fixture.
	Validate func(f Fixture, s Scenario) error
	// Run starts each target and grades every scenario of the role.
	Run func(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report
	// Unavailable permits targets that declare missing native support.
	Unavailable bool
}

var extensionRoles = map[string]ExtensionRole{}

// RegisterRole adds an extension role; role files call it from init.
func RegisterRole(name string, role ExtensionRole) {
	if _, exists := extensionRoles[name]; exists || name == "" || role.Validate == nil || role.Run == nil {
		panic("invalid or duplicate extension role " + name)
	}
	extensionRoles[name] = role
}

var legacyRoles = []string{ResourceRole, AgentRole, PersonServerRole, FederatedRole, DeferredRole, SubagentRole}

// KnownRole reports whether name is a built-in or registered extension role.
func KnownRole(name string) bool {
	_, extension := extensionRoles[name]
	return extension || slices.Contains(legacyRoles, name)
}

// Roles lists every role name in a stable order.
func Roles() []string {
	names := slices.Clone(legacyRoles)
	extensions := []string{}
	for name := range extensionRoles {
		extensions = append(extensions, name)
	}
	sort.Strings(extensions)
	return append(names, extensions...)
}

func allKinds() []string {
	kinds := []string{}
	for _, role := range extensionRoles {
		kinds = append(kinds, role.Kinds...)
	}
	return kinds
}

// validateExtensionScenario applies the shared rules, then the role's own.
func validateExtensionScenario(f Fixture, s Scenario, clauseRoles map[string]string) error {
	role := extensionRoles[s.Role]
	if s.Person != nil || s.Federated != nil || s.Deferred != nil || s.Subagent != nil {
		return fmt.Errorf("%s: inputs of another role", s.ID)
	}
	ids := map[string]bool{}
	for _, a := range s.Assertions {
		if a.ID == "" || ids[a.ID] || clauseRoles[a.Clause] != s.Role || !json.Valid(a.Equals) {
			return fmt.Errorf("invalid assertion %s/%s (clause %q)", s.ID, a.ID, a.Clause)
		}
		if !slices.Contains(GenericKinds, a.Kind) && !slices.Contains(role.Kinds, a.Kind) {
			return fmt.Errorf("assertion kind %s/%s is not available to %s", s.ID, a.ID, s.Role)
		}
		if err := validateGenericAssertion(a); err != nil {
			return fmt.Errorf("%s/%s: %w", s.ID, a.ID, err)
		}
		ids[a.ID] = true
	}
	return role.Validate(f, s)
}

// validateGenericAssertion checks the expected value of a generic kind.
func validateGenericAssertion(a Assertion) error {
	if !slices.Contains(GenericKinds, a.Kind) {
		return nil
	}
	var value any
	json.Unmarshal(a.Equals, &value)
	switch a.Kind {
	case "status":
		n, ok := value.(float64)
		if !ok || n < 100 || n > 599 || n != float64(int(n)) {
			return fmt.Errorf("status equals must be an HTTP status")
		}
	case "sfv-token", "problem-if-present", "header-equals":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s equals must be a string", a.Kind)
		}
	case "status-class":
		if !slices.Contains([]string{"1xx", "2xx", "3xx", "4xx", "5xx"}, fmt.Sprint(value)) {
			return fmt.Errorf("status-class equals must name a class such as 2xx")
		}
	case "sfv-token-present", "sfv-absent":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s equals must be a boolean", a.Kind)
		}
	case "sfv-integer":
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("sfv-integer equals must be a number")
		}
	case "sfv-strings", "sfv-string-set":
		list, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s equals must be an array", a.Kind)
		}
		for _, v := range list {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s requires strings", a.Kind)
			}
		}
	case "json-member", "json-path":
		if a.Member == "" {
			return fmt.Errorf("JSON assertion needs member")
		}
	}
	if slices.Contains([]string{"sfv-token", "sfv-token-present", "sfv-strings", "sfv-string-set", "sfv-integer", "sfv-absent"}, a.Kind) && (a.Header == "" || a.Member == "") {
		return fmt.Errorf("SFV assertion needs header/member")
	}
	return nil
}

// DecodeInput decodes a scenario's role input strictly.
func DecodeInput(s Scenario, v any) error {
	if len(s.Input) == 0 {
		return fmt.Errorf("%s: input required for %s", s.ID, s.Role)
	}
	if err := Decode(s.Input, v); err != nil {
		return fmt.Errorf("%s input: %w", s.ID, err)
	}
	return nil
}

// DecodeExtension decodes the fixture's named extension strictly.
func DecodeExtension(f Fixture, name string, v any) error {
	raw, ok := f.Extensions[name]
	if !ok {
		return fmt.Errorf("fixture extension %q required", name)
	}
	if err := Decode(raw, v); err != nil {
		return fmt.Errorf("fixture extension %q: %w", name, err)
	}
	return nil
}

// Grade applies one generic or role-specific assertion. The role's own kinds
// are checked by its check function; generic kinds use Check.
func Grade(a Assertion, claims []string, executionError string, response *Response, own func(Assertion) Result) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals}
	switch {
	case !slices.Contains(claims, a.Clause):
		result.State = "not_claimed"
	case executionError != "":
		result.State = "error"
		result.Detail = executionError
	case slices.Contains(GenericKinds, a.Kind):
		if response == nil {
			result.State = "error"
			result.Detail = "no response observed for this assertion"
			return result
		}
		return Check(a, *response)
	default:
		return own(a)
	}
	return result
}

// CompareResult fills a result from an observed value.
func CompareResult(a Assertion, actual any, detail string) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail", Actual: actual, Detail: detail}
	var expected any
	if err := json.Unmarshal(a.Equals, &expected); err != nil {
		result.Detail = err.Error()
		return result
	}
	normalized, _ := json.Marshal(actual)
	var observed any
	json.Unmarshal(normalized, &observed)
	if jsonEqual(observed, expected) {
		result.State = "pass"
		result.Detail = ""
	}
	return result
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// validSeed reports whether seed is a 32-byte Ed25519 seed in lowercase hex.
func validSeed(seed string) bool {
	return len(seed) == 64 && strings.Trim(seed, "0123456789abcdef") == ""
}
