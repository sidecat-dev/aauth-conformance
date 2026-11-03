package conformance

import (
	"encoding/json"
	"net/http"
	"testing"
)

func sigkeyTestSuite(t *testing.T) (Fixture, SigkeyFixture) {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	k, err := sigkeyFixture(suite.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	return suite.Fixture, k
}

func sigkeyCaptured(record *requestRecord) Captured {
	return Captured{Method: record.request.Method, URL: record.request.URL.String(), Headers: record.request.Header.Clone(), Body: record.body}
}

// Catches an oracle that accepts a request it did not sign, a wrong key, a
// tampered target, an extra hwk kid or a different jwks_uri identity.
func TestSigkeyOracleVerifiesOnlyTheExpectedKeyAndMember(t *testing.T) {
	f, k := sigkeyTestSuite(t)
	for _, alg := range []string{"Ed25519", "ES256", "ES384", "RS256", "PS256"} {
		scenario := Scenario{ID: "oracle-" + alg, Input: json.RawMessage(`{"scheme":"hwk","alg":"` + alg + `","mutation":"none"}`)}
		record, err := sigkeyVerifierRequest(f, k, scenario)
		if err != nil {
			t.Fatal(alg, err)
		}
		key, err := sigkeyAlgKey(k, alg, f.AgentSeed)
		if err != nil {
			t.Fatal(err)
		}
		job := sigkeySignJob{Scheme: "hwk", Method: "GET", URL: k.Verifier}
		if o := sigkeyObserveSigned(job, key, sigkeyCaptured(record)); !o.Signed || !o.Member || o.Created != f.Now {
			t.Fatalf("%s: valid hwk request not accepted: %+v", alg, o)
		}
		tampered := sigkeyCaptured(record)
		tampered.Method = http.MethodPost
		if o := sigkeyObserveSigned(job, key, tampered); o.Signed {
			t.Fatalf("%s: tampered method accepted", alg)
		}
		if other, _ := sigkeyAlgKey(k, "Ed25519", k.Signer.Seed); alg == "Ed25519" && sigkeyObserveSigned(job, other, sigkeyCaptured(record)).Signed {
			t.Fatal("request accepted under another key")
		}
	}
	kid := Scenario{ID: "oracle-kid", Input: json.RawMessage(`{"scheme":"hwk","alg":"Ed25519","mutation":"hwk-kid"}`)}
	record, err := sigkeyVerifierRequest(f, k, kid)
	if err != nil {
		t.Fatal(err)
	}
	if o := sigkeyObserveSigned(sigkeySignJob{Scheme: "hwk"}, sigkeyEd25519(f.AgentSeed), sigkeyCaptured(record)); o.Member {
		t.Fatal("hwk member carrying kid accepted")
	}
	uri := Scenario{ID: "oracle-uri", Input: json.RawMessage(`{"scheme":"jwks_uri","alg":"Ed25519","mutation":"none"}`)}
	record, err = sigkeyVerifierRequest(f, k, uri)
	if err != nil {
		t.Fatal(err)
	}
	signer := sigkeyEd25519(k.Signer.Seed)
	job := sigkeySignJob{Scheme: "jwks_uri", ID: k.Signer.Issuer, DWK: k.Signer.DWK, Kid: k.Signer.Kid}
	if o := sigkeyObserveSigned(job, signer, sigkeyCaptured(record)); !o.Signed || !o.Member {
		t.Fatalf("jwks_uri request not accepted: %+v", o)
	}
	job.ID = "https://other.conformance.test"
	if sigkeyObserveSigned(job, signer, sigkeyCaptured(record)).Member {
		t.Fatal("another jwks_uri identity accepted")
	}
	named := Scenario{ID: "oracle-named", Input: json.RawMessage(`{"scheme":"jwks_uri","alg":"Ed25519","mutation":"named-document"}`)}
	record, err = sigkeyVerifierRequest(f, k, named)
	if err != nil {
		t.Fatal(err)
	}
	job = sigkeySignJob{Scheme: "jwks_uri", ID: k.Signer.Issuer, DWK: sigkeyNamedDocument, Kid: k.Signer.Kid}
	if o := sigkeyObserveSigned(job, signer, sigkeyCaptured(record)); !o.Signed || !o.Member {
		t.Fatalf("jwks_uri request naming %s not accepted: %+v", sigkeyNamedDocument, o)
	}
	job.DWK = k.Signer.DWK
	if sigkeyObserveSigned(job, signer, sigkeyCaptured(record)).Member {
		t.Fatal("named-document request carries the role document")
	}
	uncovered := Scenario{ID: "oracle-uncovered", Input: json.RawMessage(`{"scheme":"hwk","alg":"Ed25519","mutation":"uncovered-signature-key"}`)}
	record, err = sigkeyVerifierRequest(f, k, uncovered)
	if err != nil {
		t.Fatal(err)
	}
	if sigkeyObserveSigned(sigkeySignJob{Scheme: "hwk"}, sigkeyEd25519(f.AgentSeed), sigkeyCaptured(record)).Signed {
		t.Fatal("signature without signature-key coverage accepted")
	}
}

// Catches a post-quantum outcome check that accepts an undefined failure.
func TestSigkeyPQOutcomeRequiresVerificationOrDefinedRefusal(t *testing.T) {
	a := Assertion{ID: "outcome", Kind: "sigkey-pq", Equals: json.RawMessage(`"unsupported_algorithm"`)}
	cases := []struct {
		response Response
		want     string
	}{
		{Response{Status: 200}, "pass"},
		{Response{Status: 401, Header: http.Header{"Signature-Error": {"error=unsupported_algorithm"}}}, "pass"},
		{Response{Status: 401, Header: http.Header{"Signature-Error": {"error=invalid_key"}}}, "fail"},
		{Response{Status: 401}, "fail"},
		{Response{Status: 500, Header: http.Header{"Signature-Error": {"error=unsupported_algorithm"}}}, "fail"},
	}
	for _, c := range cases {
		if got := sigkeyCheckPQ(a, &c.response).State; got != c.want {
			t.Fatalf("%+v: %s, want %s", c.response, got, c.want)
		}
	}
	any := Assertion{ID: "outcome", Kind: "sigkey-pq", Equals: json.RawMessage(`""`)}
	if sigkeyCheckPQ(any, &Response{Status: 401, Header: http.Header{"Signature-Error": {"error=invalid_jwt"}}}).State != "pass" {
		t.Fatal("any defined code rejected where the draft fixes none")
	}
}

// Catches a missing-member request that still names the signature's label.
func TestSigkeyMissingMemberMovesOnlyTheSignatureKeyLabel(t *testing.T) {
	f, k := sigkeyTestSuite(t)
	record, err := sigkeyVerifierRequest(f, k, Scenario{ID: "oracle-missing", Input: json.RawMessage(`{"scheme":"jwt","alg":"Ed25519","mutation":"missing-member"}`)})
	if err != nil {
		t.Fatal(err)
	}
	key := record.request.Header.Get("Signature-Key")
	if key[:5] != "sig1=" || record.request.Header.Get("Signature-Input")[:4] != "sig=" || record.request.Header.Get("Signature")[:4] != "sig=" {
		t.Fatalf("labels: %q %q", key, record.request.Header.Get("Signature-Input"))
	}
}

// Catches running a scheme a library does not offer because a role-wide
// clause, such as the adapter-contract echo, is still claimed.
func TestSigkeyOfferedFollowsTheScenarioClause(t *testing.T) {
	s := Scenario{Assertions: []Assertion{{Clause: "sigkey.v.hwk-ed25519"}, {Clause: "sigkey.v.echo"}}}
	if sigkeyOffered(s, Target{Claims: []string{"sigkey.v.echo"}}) {
		t.Fatal("scenario run on a role-wide clause alone")
	}
	if !sigkeyOffered(s, Target{Claims: []string{"sigkey.v.hwk-ed25519", "sigkey.v.echo"}}) {
		t.Fatal("offered scenario skipped")
	}
	if sigkeyOffered(s, Target{Unavailable: "no", Claims: []string{"sigkey.v.hwk-ed25519"}}) {
		t.Fatal("unavailable target run")
	}
}
