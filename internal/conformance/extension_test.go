package conformance

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Catches an extension role whose inputs, kinds or clauses escape strict loading.
func TestExtensionRoleLoadsOnlyItsOwnInputsAndKinds(t *testing.T) {
	const role = "test.extension"
	type input struct {
		Mode string `json:"mode"`
	}
	if !KnownRole(role) {
		RegisterRole(role, ExtensionRole{
			Kinds: []string{"test-observed"},
			Validate: func(f Fixture, s Scenario) error {
				var in input
				return DecodeInput(s, &in)
			},
			Run:         func(context.Context, Suite, Targets, Options, string, Report) Report { return Report{} },
			Unavailable: true,
		})
	}
	suite := Suite{Fixture: fixture(), Catalog: Catalog{Version: 1, Sources: []Source{{ID: "core", Commit: strings.Repeat("a", 40), SHA256: strings.Repeat("b", 64), URL: "https://example.test"}}, Clauses: []Clause{{ID: "x", Role: role, Source: "core", Section: "s", Anchor: "a", Scope: "protocol"}}}}
	scenario := Scenario{Version: 1, ID: "one", Role: role, Given: suite.Fixture.ID, Input: json.RawMessage(`{"mode":"none"}`), Assertions: []Assertion{{ID: "a", Clause: "x", Kind: "test-observed", Equals: json.RawMessage(`true`)}}}
	suite.Scenarios = []Scenario{scenario}
	if err := suite.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Scenario){
		func(s *Scenario) { s.Input = json.RawMessage(`{"mode":"none","extra":1}`) },
		func(s *Scenario) { s.Input = nil },
		func(s *Scenario) { s.Assertions[0].Kind = "wire-proof" },
		func(s *Scenario) { s.Assertions[0].Clause = "core.verification" },
		func(s *Scenario) { s.Request.Method = "GET" },
		func(s *Scenario) {
			s.Assertions[0] = Assertion{ID: "a", Clause: "x", Kind: "status-class", Equals: json.RawMessage(`"9xx"`)}
		},
	} {
		changed := scenario
		changed.Assertions = append([]Assertion(nil), scenario.Assertions...)
		mutate(&changed)
		suite.Scenarios = []Scenario{changed}
		if err := suite.validate(); err == nil {
			t.Fatalf("invalid extension scenario accepted: %+v", changed)
		}
	}
	targets := Targets{Version: 1, Role: role, Implementations: []Target{{ID: "lib", Revision: "r", Unavailable: "no native support"}}}
	suite.Scenarios = []Scenario{scenario}
	if err := ValidateTargets(targets, suite); err != nil {
		t.Fatal(err)
	}
}
