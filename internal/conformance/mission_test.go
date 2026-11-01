package conformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Catches a mission oracle that accepts a digest over other bytes, a padded
// encoding or a blob without its required members.
func TestMissionApprovalOracle(t *testing.T) {
	f := fixture()
	blob := []byte(`{"agent":"` + f.Subject + `","approved_at":"2027-01-15T08:00:00Z","description":"# Reconcile"}`)
	approval := func(s256, mission string) Response {
		body, _ := json.Marshal(map[string]string{"s256": s256, "mission": mission})
		return Response{Status: 200, Body: body}
	}
	encoded := base64.RawURLEncoding.EncodeToString(blob)
	d := &missionDriver{f: f, approval: readMissionApproval(approval(missionDigest(blob), encoded))}
	for kind, want := range map[string]bool{"mission-s256": true, "mission-encoded": true, "mission-blob": true} {
		if got := d.check(Assertion{Kind: kind, Equals: json.RawMessage(`true`)}).State; (got == "pass") != want {
			t.Fatalf("%s: %s", kind, got)
		}
	}
	d.approval = readMissionApproval(approval(missionDigest([]byte("other bytes")), encoded))
	if d.check(Assertion{Kind: "mission-s256", Equals: json.RawMessage(`true`)}).State == "pass" {
		t.Fatal("digest over other bytes accepted")
	}
	if readMissionApproval(approval(missionDigest(blob), base64.URLEncoding.EncodeToString(blob)+"=")).Error == "" {
		t.Fatal("padded mission encoding accepted")
	}
	d.approval = readMissionApproval(approval(missionDigest([]byte(`{"agent":"x"}`)), base64.RawURLEncoding.EncodeToString([]byte(`{"agent":"x"}`))))
	if d.check(Assertion{Kind: "mission-blob", Equals: json.RawMessage(`true`)}).State == "pass" {
		t.Fatal("blob without approved_at and description accepted")
	}
}

// Catches a disclosure check that treats a different body or header set as
// equivalent, or a server Date as a difference.
func TestMissionNotFoundEquivalence(t *testing.T) {
	base := Response{Status: 404, Header: http.Header{"Content-Type": {"application/problem+json"}, "Date": {"a"}}, Body: []byte(`{"error":"mission_not_found"}`)}
	same := base
	same.Header = http.Header{"Content-Type": {"application/problem+json"}, "Date": {"b"}}
	if ok, detail := equivalentResponses(base, same); !ok {
		t.Fatal(detail)
	}
	other := same
	other.Body = []byte(`{"error":"mission_terminated"}`)
	if ok, _ := equivalentResponses(base, other); ok {
		t.Fatal("different body accepted")
	}
	extra := same
	extra.Header = http.Header{"Content-Type": {"application/problem+json"}, "Cache-Control": {"no-store"}}
	if ok, _ := equivalentResponses(base, extra); ok {
		t.Fatal("different header set accepted")
	}
}

// Catches mission scenarios that name a stage their flow never reaches or a
// kind at a stage it cannot observe.
func TestMissionScenarioValidation(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	var base Scenario
	for _, s := range suite.Scenarios {
		if s.ID == "mission-completion" {
			base = s
		}
	}
	if base.ID == "" {
		t.Fatal("mission-completion scenario missing")
	}
	for name, mutate := range map[string]func(*Scenario){
		"unreached stage":     func(s *Scenario) { s.Assertions[0].Stage = "before-token" },
		"kind at wrong stage": func(s *Scenario) { s.Assertions[0].Kind = "mission-s256" },
		"non-boolean own kind": func(s *Scenario) {
			s.Assertions[0] = Assertion{ID: "x", Stage: "after-person", Kind: "mission-no-token", Clause: "mission.status-error", Equals: json.RawMessage(`"yes"`)}
		},
		"expiry outside flow":   func(s *Scenario) { s.Input = json.RawMessage(`{"flow":"completion","expires_in":30}`) },
		"unknown flow":          func(s *Scenario) { s.Input = json.RawMessage(`{"flow":"suspend"}`) },
		"prescribed token":      func(s *Scenario) { s.Token.EXPOffset = 60 },
		"resource-role clause":  func(s *Scenario) { s.Assertions[0].Clause = "mission.resource-token-copy" },
		"unknown input members": func(s *Scenario) { s.Input = json.RawMessage(`{"flow":"completion","extra":true}`) },
	} {
		changed := base
		changed.Assertions = append([]Assertion(nil), base.Assertions...)
		mutate(&changed)
		probe := suite
		probe.Scenarios = []Scenario{changed}
		if err := probe.validate(); err == nil || strings.Contains(err.Error(), "invalid fixture") {
			t.Fatalf("%s accepted (%v)", name, err)
		}
	}
}
