package main

import (
	"fmt"
	"slices"
	"strings"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

// Map is the conformance map. Every slice is in a fixed order: drafts and
// suite clauses in catalog order, scenarios in file order, reports by role
// then library, clauses by draft then line.
type Map struct {
	Version       int
	SuiteSHA256   string
	ReportsSource string
	Drafts        []DraftRef
	Reports       []ReportRef
	Scenarios     []ScenarioRef
	SuiteClauses  []SuiteClause
	Clauses       []Entry
}
type DraftRef struct {
	ID, File, Commit, SHA256 string
	Lines                    int
}
type ReportRef struct {
	Role, Library, Revision, Execution, SuiteSHA256 string
}
type ScenarioRef struct {
	ID, Role, File string
}
type SuiteClause struct {
	ID, Draft, Anchor, Role, Scope string
	AnchorLine                     int // 0 when the anchor is not declared in the draft
	Linked                         int // number of map clauses in the anchored section
	Scenarios                      []string
	Status, Reason                 map[string]string
}
type Entry struct {
	ID, Draft, Level, Section, Text string
	Line                            int
	SuiteClauses, Scenarios         []string
	Status, Reason                  map[string]string
}

// Inputs are the parsed sources a map is built from.
type Inputs struct {
	Suite         conformance.Suite
	ScenarioFiles []string // suite-relative, parallel to Suite.Scenarios
	Drafts        map[string]Draft
	DraftFiles    map[string]string // source id -> file name
	Statuses      Statuses
	ReportsSource string
}

// Statuses are what the map takes from reports: the reports themselves and,
// per suite clause and library, a state and a reason.
type Statuses struct {
	Reports        []ReportRef
	Status, Reason map[string]map[string]string
}

// statusOrder ranks the per-library states an entry combines: the first
// state present among its suite clauses is the entry's state.
var statusOrder = []string{"fail", "error", "pass", "not-exercised", "not-claimed", "not-applicable"}

func reportState(s string) string { return strings.ReplaceAll(s, "_", "-") }

// Build makes the map.
func Build(in Inputs) (Map, error) {
	m := Map{Version: 1, SuiteSHA256: in.Suite.Digest, ReportsSource: in.ReportsSource}
	for _, s := range in.Suite.Catalog.Sources {
		d, ok := in.Drafts[s.ID]
		if !ok {
			return m, fmt.Errorf("no draft for source %s", s.ID)
		}
		m.Drafts = append(m.Drafts, DraftRef{ID: s.ID, File: in.DraftFiles[s.ID], Commit: s.Commit, SHA256: s.SHA256, Lines: d.Lines})
	}
	if len(in.ScenarioFiles) != len(in.Suite.Scenarios) {
		return m, fmt.Errorf("%d scenario files for %d scenarios", len(in.ScenarioFiles), len(in.Suite.Scenarios))
	}
	exercising := map[string][]string{} // suite clause -> scenario ids, file order
	for i, sc := range in.Suite.Scenarios {
		m.Scenarios = append(m.Scenarios, ScenarioRef{ID: sc.ID, Role: sc.Role, File: in.ScenarioFiles[i]})
		for _, a := range sc.Assertions {
			if ids := exercising[a.Clause]; len(ids) == 0 || ids[len(ids)-1] != sc.ID {
				exercising[a.Clause] = append(ids, sc.ID)
			}
		}
	}
	m.Reports = in.Statuses.Reports
	status, reason := in.Statuses.Status, in.Statuses.Reason

	// Section heading line -> suite clauses anchored there, per draft.
	anchored := map[string]map[int][]int{}
	for i, c := range in.Suite.Catalog.Clauses {
		sc := SuiteClause{ID: c.ID, Draft: c.Source, Anchor: c.Anchor, Role: c.Role, Scope: c.Scope,
			Scenarios: exercising[c.ID], Status: status[c.ID], Reason: reason[c.ID]}
		if sc.Role == "" {
			sc.Role = "resource.agent-identity"
		}
		if a, ok := in.Drafts[c.Source].Anchors[c.Anchor]; ok {
			sc.AnchorLine = a.Line
			if anchored[c.Source] == nil {
				anchored[c.Source] = map[int][]int{}
			}
			anchored[c.Source][a.Section] = append(anchored[c.Source][a.Section], i)
		}
		m.SuiteClauses = append(m.SuiteClauses, sc)
	}

	order := map[string]int{}
	for i, s := range m.Scenarios {
		order[s.ID] = i
	}
	for _, d := range m.Drafts {
		seen := map[int]int{}
		for _, st := range in.Drafts[d.ID].Statements {
			seen[st.Line]++
			id := fmt.Sprintf("%s:%d", d.ID, st.Line)
			if n := seen[st.Line]; n > 1 {
				id = fmt.Sprintf("%s.%d", id, n)
			}
			e := Entry{ID: id, Draft: d.ID, Line: st.Line, Level: st.Level, Section: st.Section, Text: st.Text,
				SuiteClauses: []string{}, Scenarios: []string{}}
			var linked []int
			for _, h := range st.Path {
				linked = append(linked, anchored[d.ID][h]...)
			}
			slices.Sort(linked)
			linked = slices.Compact(linked)
			for _, i := range linked {
				sc := &m.SuiteClauses[i]
				sc.Linked++
				e.SuiteClauses = append(e.SuiteClauses, sc.ID)
				for _, s := range sc.Scenarios {
					if !slices.Contains(e.Scenarios, s) {
						e.Scenarios = append(e.Scenarios, s)
					}
				}
			}
			slices.SortFunc(e.Scenarios, func(a, b string) int { return order[a] - order[b] })
			e.Status, e.Reason = combine(linked, m.SuiteClauses)
			m.Clauses = append(m.Clauses, e)
		}
	}
	return m, nil
}

// FromReports reads each report's clause matrix: per suite clause, the
// state and (for not-applicable and not-exercised) reason per library.
func FromReports(reports []conformance.Report) (Statuses, error) {
	out := Statuses{Status: map[string]map[string]string{}, Reason: map[string]map[string]string{}}
	status, reason := out.Status, out.Reason
	set := func(t map[string]map[string]string, clause, lib, v string) {
		if t[clause] == nil {
			t[clause] = map[string]string{}
		}
		t[clause][lib] = v
	}
	seen := map[[2]string]bool{}
	for _, r := range reports {
		matrix := r.Matrix()
		for _, run := range r.Runs {
			lib := run.Target.ID
			if seen[[2]string{r.Role, lib}] {
				return out, fmt.Errorf("two reports for role %s, library %s", r.Role, lib)
			}
			seen[[2]string{r.Role, lib}] = true
			out.Reports = append(out.Reports, ReportRef{Role: r.Role, Library: lib, Revision: run.Target.Revision, Execution: reportState(r.Execution), SuiteSHA256: r.SuiteSHA256})
			for _, c := range r.Catalog.Clauses {
				if run.Target.Unavailable != "" {
					set(status, c.ID, lib, "not-applicable")
					set(reason, c.ID, lib, oneLine(run.Target.Unavailable))
					continue
				}
				state := reportState(matrix[c.ID][lib].State)
				set(status, c.ID, lib, state)
				if state != "not-exercised" {
					continue
				}
			found:
				for _, cs := range run.Cases {
					for _, res := range cs.Results {
						if res.Clause == c.ID && res.State == "not_exercised" && res.Detail != "" {
							set(reason, c.ID, lib, oneLine(res.Detail))
							break found
						}
					}
				}
			}
		}
	}
	slices.SortFunc(out.Reports, func(a, b ReportRef) int {
		return strings.Compare(a.Role+"\x00"+a.Library, b.Role+"\x00"+b.Library)
	})
	return out, nil
}

// combine picks, per library, the highest-ranked state among the linked
// suite clauses, with the reason of the first of them in that state.
func combine(linked []int, clauses []SuiteClause) (map[string]string, map[string]string) {
	status, reason := map[string]string{}, map[string]string{}
	for _, i := range linked {
		for lib, s := range clauses[i].Status {
			if cur, ok := status[lib]; !ok || slices.Index(statusOrder, s) < slices.Index(statusOrder, cur) {
				status[lib] = s
			}
		}
	}
	for lib, s := range status {
		if s != "not-applicable" && s != "not-exercised" {
			continue
		}
		for _, i := range linked {
			if clauses[i].Status[lib] == s && clauses[i].Reason[lib] != "" {
				reason[lib] = clauses[i].Reason[lib]
				break
			}
		}
	}
	return status, reason
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
