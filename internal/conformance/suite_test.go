package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Catches silent scenario omission, misspelled clause IDs and invalid key input.
func TestSuiteValidationAndDigest(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(suite.Scenarios) != 77 || len(suite.Digest) != 64 {
		t.Fatalf("%+v", suite)
	}
	for _, mutate := range []func(string){
		func(dir string) {
			os.WriteFile(filepath.Join(dir, "scenarios/01-unsigned.json"), []byte(`{"version":9}`), 0600)
		},
		func(dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, "scenarios/01-unsigned.json"))
			os.WriteFile(filepath.Join(dir, "scenarios/01-unsigned.json"), []byte(strings.ReplaceAll(string(b), "core.agent-token-required", "missing.clause")), 0600)
		},
		func(dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, "fixture.json"))
			os.WriteFile(filepath.Join(dir, "fixture.json"), []byte(strings.ReplaceAll(string(b), fixture().APSeed, "not-a-key")), 0600)
		},
		func(dir string) { os.RemoveAll(filepath.Join(dir, "scenarios")) },
	} {
		dir := t.TempDir()
		os.Mkdir(filepath.Join(dir, "scenarios"), 0700)
		files, _ := filepath.Glob("../../scenarios/*.json")
		files = append(files, "../../fixture.json", "../../clauses.json")
		for _, src := range files {
			b, _ := os.ReadFile(src)
			rel, _ := filepath.Rel("../..", src)
			os.WriteFile(filepath.Join(dir, rel), b, 0600)
		}
		mutate(dir)
		if _, err := Load(dir); err == nil {
			t.Fatal("invalid suite accepted")
		}
	}
}

// Catches converting a refusal, transport error, or unclaimed clause into green.
func TestClauseMatrixPreservesFailureAndClaimBoundaries(t *testing.T) {
	report := Report{Catalog: Catalog{Clauses: []Clause{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}}, Runs: []Run{{Target: Target{ID: "one", Claims: []string{"a", "b", "c"}}, Cases: []Case{{Results: []Result{{Clause: "a", State: "pass"}, {Clause: "a", State: "fail"}, {Clause: "b", State: "error"}, {Clause: "d", State: "pass"}}}}}}}
	cells := report.Matrix()
	for clause, want := range map[string]string{"a": "fail", "b": "error", "c": "not_exercised", "d": "not_claimed"} {
		if cells[clause]["one"].State != want {
			t.Fatalf("%s: %+v", clause, cells)
		}
	}
	if report.Success() {
		t.Fatal("failed report passed")
	}
	report.Runs[0].Cases[0].Results = []Result{{Clause: "d", State: "not_claimed"}}
	if report.Success() {
		t.Fatal("all-unclaimed report passed")
	}
	report.Runs[0].Cases[0].Results = []Result{{Clause: "a", State: "pass"}}
	if !report.Success() {
		t.Fatal("observed pass failed")
	}
	var b strings.Builder
	if err := report.Markdown(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "not_claimed") {
		t.Fatal(b.String())
	}
	a := Assertion{Equals: json.RawMessage(`401`), Kind: "status"}
	if Check(a, Response{Status: 200}).State != "fail" {
		t.Fatal("wrong status accepted")
	}
}
