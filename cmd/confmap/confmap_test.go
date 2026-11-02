package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

const draftSrc = `%%%
title = "Test"
%%%

.# Abstract

Abstract text that MUST be ignored? No: abstracts are parsed.

# Conventions

{::boilerplate bcp14-tagged}

# Tokens {#tokens}

A token MUST be signed. Its holder MAY
cache it, e.g. for an hour. Lower-case must is not a keyword.

~~~ json
{"note": "a fence that MUST be skipped"}
~~~

Figure: Token flow {#fig-flow}

<!-- a comment that MUST be skipped
over two lines -->

## Claims

| Claim | Status |
|-------|--------|
| iss   | REQUIRED. MUST be a URL. |
| aud   | none |

- First item SHOULD NOT be empty.
- Second item is OPTIONAL and
  continues here. The verifier MUST NOT accept it twice.
- **exp**: Expiry. REQUIRED. Checked on use.

# Document History

- Made signing a MUST.
`

func TestParseDraft(t *testing.T) {
	d := ParseDraft(draftSrc)
	type row struct {
		Line           int
		Level, Section string
		Start          string
	}
	var got []row
	for _, s := range d.Statements {
		got = append(got, row{s.Line, s.Level, s.Section, strings.Join(strings.Fields(s.Text)[:2], " ")})
	}
	want := []row{
		{7, "must", "abstract", "Abstract text"},
		{15, "must", "tokens", "A token"},
		{15, "may", "tokens", "Its holder"},
		{31, "must", "claims", "| iss"},
		{34, "should", "claims", "- First"},
		{35, "may", "claims", "- Second"},
		{36, "must", "claims", "The verifier"},
		{37, "must", "claims", "- **exp**:"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements\n got %v\nwant %v", got, want)
	}
	if s := d.Statements[2].Text; s != "Its holder MAY cache it, e.g. for an hour." {
		t.Fatalf("joined sentence %q", s)
	}
	if s := d.Statements[3].Text; s != "| iss | REQUIRED. MUST be a URL. |" {
		t.Fatalf("table row %q", s)
	}
	if s := d.Statements[7].Text; s != "- **exp**: Expiry. REQUIRED." {
		t.Fatalf("short sentence %q", s)
	}
	if a := d.Anchors["tokens"]; a.Line != 13 || a.Section != 13 {
		t.Fatalf("tokens anchor %+v", a)
	}
	if a := d.Anchors["fig-flow"]; a.Line != 22 || a.Section != 13 {
		t.Fatalf("figure anchor %+v", a)
	}
	if a, ok := d.Anchors["claims"]; !ok || a.Line != 27 {
		t.Fatalf("claims anchor %+v", a)
	}
	if !reflect.DeepEqual(d.Statements[3].Path, []int{13, 27}) {
		t.Fatalf("path %v", d.Statements[3].Path)
	}
}

func testInputs() Inputs {
	suite := conformance.Suite{Digest: "d1", Catalog: conformance.Catalog{
		Sources: []conformance.Source{{ID: "t", Commit: "c", SHA256: "s", URL: "https://example.test/x/test.md"}},
		Clauses: []conformance.Clause{
			{ID: "t.tokens", Source: "t", Anchor: "tokens", Scope: "protocol", Role: "r.one"},
			{ID: "t.claims", Source: "t", Anchor: "claims", Scope: "protocol", Role: "r.two"},
			{ID: "t.flow", Source: "t", Anchor: "fig-flow", Scope: "adapter-contract", Role: "r.one"},
			{ID: "t.gone", Source: "t", Anchor: "nowhere", Scope: "protocol", Role: "r.one"},
		}},
		Scenarios: []conformance.Scenario{
			{ID: "s2", Role: "r.two", Assertions: []conformance.Assertion{{Clause: "t.claims"}, {Clause: "t.claims"}}},
			{ID: "s1", Role: "r.one", Assertions: []conformance.Assertion{{Clause: "t.tokens"}, {Clause: "t.gone"}}},
		}}
	return Inputs{Suite: suite, ScenarioFiles: []string{"scenarios/02.json", "scenarios/01.json"},
		Drafts: map[string]Draft{"t": ParseDraft(draftSrc)}, DraftFiles: map[string]string{"t": "test.md"}, ReportsSource: "unit"}
}

func TestFromReportsAndBuild(t *testing.T) {
	one := conformance.Report{Role: "r.one", Execution: "passed", SuiteSHA256: "d1",
		Catalog: conformance.Catalog{Clauses: []conformance.Clause{{ID: "t.tokens"}, {ID: "t.flow"}, {ID: "t.gone"}}},
		Runs: []conformance.Run{
			{Target: conformance.Target{ID: "lib-a", Revision: "ra", Claims: []string{"t.tokens", "t.gone"}},
				Cases: []conformance.Case{{ID: "s1", Results: []conformance.Result{
					{Clause: "t.tokens", State: "pass"},
					{Clause: "t.gone", State: "not_exercised", Detail: "not\n offered"}}}}},
			{Target: conformance.Target{ID: "lib-b", Revision: "rb", Unavailable: "no such role"}},
		}}
	two := conformance.Report{Role: "r.two", Execution: "failed_or_incomplete", SuiteSHA256: "d0",
		Catalog: conformance.Catalog{Clauses: []conformance.Clause{{ID: "t.claims"}}},
		Runs: []conformance.Run{{Target: conformance.Target{ID: "lib-a", Revision: "ra", Claims: []string{"t.claims"}},
			Cases: []conformance.Case{{ID: "s2", Results: []conformance.Result{{Clause: "t.claims", State: "fail"}, {Clause: "t.claims", State: "pass"}}}}}}}
	st, err := FromReports([]conformance.Report{two, one})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus := map[string]map[string]string{
		"t.tokens": {"lib-a": "pass", "lib-b": "not-applicable"},
		"t.flow":   {"lib-a": "not-claimed", "lib-b": "not-applicable"},
		"t.gone":   {"lib-a": "not-exercised", "lib-b": "not-applicable"},
		"t.claims": {"lib-a": "fail"},
	}
	if !reflect.DeepEqual(st.Status, wantStatus) {
		t.Fatalf("status %v", st.Status)
	}
	if st.Reason["t.gone"]["lib-a"] != "not offered" || st.Reason["t.tokens"]["lib-b"] != "no such role" {
		t.Fatalf("reason %v", st.Reason)
	}
	if st.Reports[0].Role != "r.one" || st.Reports[2].Execution != "failed-or-incomplete" {
		t.Fatalf("reports %v", st.Reports)
	}
	if _, err := FromReports([]conformance.Report{one, one}); err == nil {
		t.Fatal("duplicate role and library accepted")
	}

	in := testInputs()
	in.Statuses = st
	m, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Entry{}
	for _, e := range m.Clauses {
		byID[e.ID] = e
	}
	if e := byID["t:15.2"]; e.Level != "may" || !reflect.DeepEqual(e.SuiteClauses, []string{"t.tokens", "t.flow"}) ||
		!reflect.DeepEqual(e.Scenarios, []string{"s1"}) || e.Status["lib-a"] != "pass" || e.Status["lib-b"] != "not-applicable" ||
		e.Reason["lib-b"] != "no such role" {
		t.Fatalf("entry t:15.2 %+v", e)
	}
	// A subsection statement links its own section and every enclosing one.
	if e := byID["t:31"]; !reflect.DeepEqual(e.SuiteClauses, []string{"t.tokens", "t.claims", "t.flow"}) ||
		!reflect.DeepEqual(e.Scenarios, []string{"s2", "s1"}) || e.Status["lib-a"] != "fail" {
		t.Fatalf("entry t:31 %+v", e)
	}
	if e := byID["t:7"]; len(e.SuiteClauses) != 0 || len(e.Scenarios) != 0 || e.Status != nil && len(e.Status) != 0 {
		t.Fatalf("entry t:7 %+v", e)
	}
	gone := m.SuiteClauses[3]
	if gone.AnchorLine != 0 || gone.Linked != 0 || !reflect.DeepEqual(gone.Scenarios, []string{"s1"}) {
		t.Fatalf("unresolved suite clause %+v", gone)
	}

	a, b := Render(m), Render(m)
	if !bytes.Equal(a, b) {
		t.Fatal("render is not deterministic")
	}
	v, err := ParseEDN(string(a))
	if err != nil {
		t.Fatal(err)
	}
	root := v.(map[any]any)
	entries := items(root, "clauses")
	if len(entries) != len(m.Clauses) || text(entries[2], "id") != "t:15.2" || text(entries[2], "level") != "may" ||
		kwStrings(entries[2], "reason")["lib-b"] != "no such role" {
		t.Fatalf("round trip %v", entries[2])
	}
	if line := items(root, "suite-clauses")[3][Keyword("anchor-line")]; line != nil {
		t.Fatalf("anchor-line %v", line)
	}
}

func TestEDNStrings(t *testing.T) {
	for _, s := range []string{"plain", `quote " and \ slash`, "tab\tnew\nline\x01", "unicode é ✓"} {
		v, err := ParseEDN(str(s))
		if err != nil || v != s {
			t.Fatalf("%q -> %q, %v", s, v, err)
		}
	}
	for _, bad := range []string{`{:a 1 :a 2}`, `[1 2`, `"open`, `{:a}`, `#{1}`} {
		if _, err := ParseEDN(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

// TestCheckFindsMissingNames checks a map naming things the suite lacks.
func TestCheckFindsMissingNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "map.edn")
	m := `{:scenarios [{:id "no-such" :file "scenarios/no-such.json"}]
 :suite-clauses [{:id "no.clause" :scenarios ["no-such"]}]
 :clauses [{:id "core:1" :draft "core" :line 1 :text "x" :suite-clauses ["no.clause"] :scenarios ["also-missing"]}]
 :drafts [{:id "no-draft" :file "x.md"}]}`
	if err := os.WriteFile(p, []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err := Check("../..", "", p)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"scenario no-such does not exist", "file scenarios/no-such.json does not exist",
		"suite clause no.clause names scenario no-such", "suite clause no.clause does not exist",
		"clause core:1 names scenario also-missing", "names suite clause no.clause", "draft no-draft is not a catalog source"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in\n%s", want, joined)
		}
	}
}

// TestCommittedMap checks the project's conformance-map.edn. Draft lines and
// regeneration are checked when CONFMAP_DRAFTS names the drafts directory.
func TestCommittedMap(t *testing.T) {
	drafts := os.Getenv("CONFMAP_DRAFTS")
	problems, err := Check("../..", drafts, "../../conformance-map.edn")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if drafts == "" {
		t.Log("CONFMAP_DRAFTS unset: draft lines and regeneration not checked")
	}
}
