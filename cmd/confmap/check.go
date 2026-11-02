package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

// Check verifies a map against the suite and, when draftsDir is not empty,
// the pinned drafts. It returns one line per problem: a scenario, suite
// clause, draft, draft line or file the map names that does not exist, and,
// with drafts, any difference from the map regenerated with the map's own
// report statuses.
func Check(suiteDir, draftsDir, mapPath string) ([]string, error) {
	src, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, err
	}
	v, err := ParseEDN(string(src))
	if err != nil {
		return nil, err
	}
	root, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a map", mapPath)
	}
	suite, err := conformance.Load(suiteDir)
	if err != nil {
		return nil, err
	}
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	scenarios := map[string]bool{}
	for _, s := range suite.Scenarios {
		scenarios[s.ID] = true
	}
	clauses, sources := map[string]bool{}, map[string]conformance.Source{}
	for _, c := range suite.Catalog.Clauses {
		clauses[c.ID] = true
	}
	for _, s := range suite.Catalog.Sources {
		sources[s.ID] = s
	}

	for _, s := range items(root, "scenarios") {
		id, file := text(s, "id"), text(s, "file")
		if !scenarios[id] {
			bad("scenario %s does not exist", id)
		}
		var sc conformance.Scenario
		if err := conformance.ReadJSON(filepath.Join(suiteDir, filepath.FromSlash(file)), &sc); err != nil {
			bad("scenario %s: file %s does not exist or does not decode", id, file)
		} else if sc.ID != id {
			bad("scenario %s: file %s holds scenario %s", id, file, sc.ID)
		}
	}
	named := func(kind string, entries []map[any]any) {
		for _, e := range entries {
			for _, s := range stringList(e, "scenarios") {
				if !scenarios[s] {
					bad("%s %s names scenario %s, which does not exist", kind, text(e, "id"), s)
				}
			}
		}
	}
	suiteClauses, entries := items(root, "suite-clauses"), items(root, "clauses")
	named("suite clause", suiteClauses)
	named("clause", entries)
	for _, c := range suiteClauses {
		if !clauses[text(c, "id")] {
			bad("suite clause %s does not exist", text(c, "id"))
		}
	}
	for _, e := range entries {
		for _, c := range stringList(e, "suite-clauses") {
			if !clauses[c] {
				bad("clause %s names suite clause %s, which does not exist", text(e, "id"), c)
			}
		}
	}

	drafts := map[string][]string{} // draft id -> lines of the pinned file
	for _, d := range items(root, "drafts") {
		id, file := text(d, "id"), text(d, "file")
		s, ok := sources[id]
		if !ok {
			bad("draft %s is not a catalog source", id)
			continue
		}
		if draftsDir == "" {
			continue
		}
		b, err := readDraft(draftsDir, file, s.SHA256)
		if err != nil {
			bad("draft %s: %v", id, err)
			continue
		}
		drafts[id] = strings.Split(string(b), "\n")
	}
	if draftsDir == "" {
		return problems, nil
	}
	for _, e := range entries {
		id, lines := text(e, "id"), drafts[text(e, "draft")]
		if lines == nil {
			bad("clause %s names draft %s, which is not available", id, text(e, "draft"))
			continue
		}
		n, _ := e[Keyword("line")].(int)
		words := strings.Fields(text(e, "text"))
		switch {
		case n < 1 || n > len(lines):
			bad("clause %s names line %d, which does not exist", id, n)
		case len(words) == 0 || !strings.Contains(lines[n-1], words[0]):
			bad("clause %s: line %d does not start its text", id, n)
		}
	}
	if len(problems) > 0 {
		return problems, nil
	}

	// Regenerate with the map's own statuses and compare.
	in, err := LoadInputs(suiteDir, draftsDir)
	if err != nil {
		return nil, err
	}
	in.ReportsSource = text(root, "reports-source")
	in.Statuses = Statuses{Status: map[string]map[string]string{}, Reason: map[string]map[string]string{}}
	for _, r := range items(root, "reports") {
		in.Statuses.Reports = append(in.Statuses.Reports, ReportRef{Role: text(r, "role"), Library: text(r, "library"),
			Revision: text(r, "revision"), Execution: text(r, "execution"), SuiteSHA256: text(r, "suite-sha256")})
	}
	for _, c := range suiteClauses {
		if s := kwStrings(c, "status"); len(s) > 0 {
			in.Statuses.Status[text(c, "id")] = s
		}
		if r := kwStrings(c, "reason"); len(r) > 0 {
			in.Statuses.Reason[text(c, "id")] = r
		}
	}
	m, err := Build(in)
	if err != nil {
		return nil, err
	}
	if want := Render(m); !bytes.Equal(want, src) {
		have, regen := bytes.Split(src, []byte("\n")), bytes.Split(want, []byte("\n"))
		i := 0
		for i < len(have) && i < len(regen) && bytes.Equal(have[i], regen[i]) {
			i++
		}
		bad("map differs from the regenerated map from line %d", i+1)
	}
	return problems, nil
}

func items(m map[any]any, key string) []map[any]any {
	v, _ := m[Keyword(key)].([]any)
	out := make([]map[any]any, 0, len(v))
	for _, x := range v {
		if e, ok := x.(map[any]any); ok {
			out = append(out, e)
		}
	}
	return out
}

// text returns a string or keyword value as a string.
func text(m map[any]any, key string) string {
	switch v := m[Keyword(key)].(type) {
	case string:
		return v
	case Keyword:
		return string(v)
	}
	return ""
}

func stringList(m map[any]any, key string) []string {
	v, _ := m[Keyword(key)].([]any)
	var out []string
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// kwStrings reads a map keyed by keywords whose values are strings or keywords.
func kwStrings(m map[any]any, key string) map[string]string {
	v, _ := m[Keyword(key)].(map[any]any)
	out := map[string]string{}
	for k := range v {
		if k, ok := k.(Keyword); ok {
			out[string(k)] = text(v, string(k))
		}
	}
	return out
}
