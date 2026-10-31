package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func supervisionSuite(t *testing.T) (Suite, SupervisionFixture) {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := supervisionFixture(suite.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	return suite, ss
}

// Catches a supervision scenario whose script, stage or expectation the
// runner could not execute as written.
func TestSupervisionScenariosLoadAndRefuseMalformedInput(t *testing.T) {
	suite, _ := supervisionSuite(t)
	counts := map[string]int{}
	for _, scenario := range suite.Scenarios {
		counts[scenario.Role]++
	}
	if counts[SupervisionServerRole] != 14 || counts[SupervisionPersonServerRole] != 10 {
		t.Fatalf("supervision scenarios: %v", counts)
	}
	find := func(id string) Scenario {
		for _, scenario := range suite.Scenarios {
			if scenario.ID == id {
				return scenario
			}
		}
		t.Fatalf("missing %s", id)
		return Scenario{}
	}
	for _, mutate := range []struct {
		id     string
		change func(*Scenario)
	}{
		{"supervision.ss-signed-allow", func(s *Scenario) {
			s.Input = json.RawMessage(bytes.Replace(s.Input, []byte(`"decision"`), []byte(`"decisions"`), 1))
		}},
		{"supervision.ss-signed-allow", func(s *Scenario) { s.Assertions[0].Stage = "nowhere" }},
		{"supervision.ss-idempotent", func(s *Scenario) { s.Assertions[3].Member = "again" }},
		{"supervision.ss-unsigned", func(s *Scenario) {
			s.Input = json.RawMessage(bytes.Replace(s.Input, []byte(`"$agent"`), []byte(`"$unknown"`), 1))
		}},
		{"supervision.ps-deny", func(s *Scenario) { s.Input = json.RawMessage(`{"act":"person_token","decision":"maybe"}`) }},
		{"supervision.ps-deny", func(s *Scenario) { s.Assertions[0].Kind = "ps-credential-exp" }},
		{"supervision.ps-allow", func(s *Scenario) { s.Assertions[3].Stage = "person" }},
	} {
		changed := find(mutate.id)
		changed.Assertions = append([]Assertion(nil), changed.Assertions...)
		mutate.change(&changed)
		broken := suite
		broken.Scenarios = []Scenario{changed}
		if err := broken.validate(); err == nil {
			t.Fatalf("malformed %s accepted", mutate.id)
		}
	}
}

// Catches a signed-decision oracle that accepts a tampered body, another
// key under the supervisor's name, or another supervisor's signature.
func TestSupervisionResponseSignatureOracle(t *testing.T) {
	suite, ss := supervisionSuite(t)
	body := []byte(`{"sdi":"d-1","act":"permission"}`)
	digest := sha256.Sum256(body)
	request := Captured{Method: "POST", URL: ss.Issuer + "/decision", Headers: http.Header{
		"Content-Digest":   {"sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"},
		"Accept-Signature": {supervisionAcceptSignature},
	}, Body: body}
	harness := &harnessSupervisor{fixture: suite.Fixture, ss: ss}
	sign := func(seed, issuer, kid string) Response {
		status, header, payload := harness.signedDecision(request, map[string]any{"sdi": "d-1", "decision": "allow"}, seed, issuer, kid, false)
		return Response{Status: status, Header: header, Body: payload}
	}
	good := sign(ss.Seed, ss.Issuer, ss.Kid)
	if ok, observed := signedDecision(ss, good, request); !ok || len(observed.Covered) != 6 {
		t.Fatalf("valid signed decision refused: %+v", observed)
	}
	tampered := good
	tampered.Body = []byte(`{"sdi":"d-1","decision":"deny"}`)
	if ok, _ := signedDecision(ss, tampered, request); ok {
		t.Fatal("tampered body accepted")
	}
	if ok, _ := signedDecision(ss, sign(ss.Foreign.Seed, ss.Issuer, ss.Kid), request); ok {
		t.Fatal("foreign key under the supervisor's id accepted")
	}
	if ok, _ := signedDecision(ss, sign(ss.Foreign.Seed, ss.Foreign.Issuer, ss.Foreign.Kid), request); ok {
		t.Fatal("another supervisor's signature accepted")
	}
	moved := request
	moved.URL = ss.Issuer + "/mission"
	if ok, _ := signedDecision(ss, good, moved); ok {
		t.Fatal("signature bound to another request path accepted")
	}
}

// Catches a PS-request oracle that accepts an uncovered body or another signer.
func TestSupervisionPersonServerRequestOracle(t *testing.T) {
	suite, ss := supervisionSuite(t)
	p := *suite.Fixture.Person
	capture := func(seed, issuer, kid string, omit bool) Captured {
		request, _, err := signServerRequest(suite.Fixture, seed, issuer, "aauth-person.json", kid, "POST", ss.Issuer+"/decision", []byte(`{"sdi":"d-1"}`), "", omit)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(request.Body)
		return Captured{Method: "POST", URL: request.URL.String(), Headers: request.Header, Body: body}
	}
	good := capture(p.Seed, p.Issuer, p.Kid, false)
	if proof := observePSRequestProof(suite.Fixture, good, good.URL, "POST"); !proof.ValidProof {
		t.Fatalf("valid PS request refused: %+v", proof)
	}
	if proof := observePSRequestProof(suite.Fixture, capture(p.Seed, p.Issuer, p.Kid, true), good.URL, "POST"); proof.ValidProof {
		t.Fatal("uncovered body accepted")
	}
	if proof := observePSRequestProof(suite.Fixture, capture(ss.OtherPS.Seed, ss.OtherPS.Issuer, ss.OtherPS.Kid, false), good.URL, "POST"); proof.ValidProof {
		t.Fatal("another Person Server accepted")
	}
	if _, err := substitute(map[string]any{"x": "$nothing"}, supervisionPlaceholders(suite.Fixture, ss, "id")); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
}
