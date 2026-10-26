package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func fixture() Fixture {
	return Fixture{Version: 1, ID: "agent-identity", Now: 1800000000, Issuer: "https://ap.conformance.test", Origin: "https://resource.conformance.test", Path: "/whoami", Kid: "ap-1", Subject: "aauth:Agent@ap.conformance.test", APSeed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", AgentSeed: strings.Repeat("02", 32)}
}

// Catches signing a different base than the RFC 9421 serialized components.
func TestIndependentPeerUsesLiteralCanonicalBase(t *testing.T) {
	f := fixture()
	s := Scenario{ID: "valid", Request: RequestSpec{Method: "GET", Path: "/whoami", Proof: "jwt", Covered: []string{"@method", "@authority", "@path", "signature-key"}}, Token: TokenSpec{IATOffset: -10, EXPOffset: 300}}
	req, base, err := BuildRequest(f, s)
	if err != nil {
		t.Fatal(err)
	}
	want := "\"@method\": GET\n\"@authority\": resource.conformance.test\n\"@path\": /whoami\n\"signature-key\": " + req.Header.Get("Signature-Key") + "\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1800000000"
	if string(base) != want {
		t.Fatalf("base:\n%s", base)
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(req.Header.Get("Signature"), "sig=:"), ":")
	sig, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := seedKey(f.AgentSeed)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), base, sig) {
		t.Fatal("proof does not verify")
	}
	s.Request.Tamper = true
	bad, _, err := BuildRequest(f, s)
	if err != nil {
		t.Fatal(err)
	}
	raw = strings.TrimSuffix(strings.TrimPrefix(bad.Header.Get("Signature"), "sig=:"), ":")
	sig, _ = base64.StdEncoding.DecodeString(raw)
	if ed25519.Verify(key.Public().(ed25519.PublicKey), base, sig) {
		t.Fatal("tamper did not alter proof")
	}
}

// Pins RFC 8032 test-vector seed interpretation, rather than a SUT's key helper.
func TestAPFixtureAndJWTSignature(t *testing.T) {
	f := fixture()
	public := seedKey(f.APSeed).Public().(ed25519.PublicKey)
	if hex.EncodeToString(public) != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatal("wrong RFC key")
	}
	compact, err := MintToken(f, TokenSpec{IATOffset: -10, EXPOffset: 300}, "vector")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(compact, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(p[2])
	if !ed25519.Verify(public, []byte(p[0]+"."+p[1]), sig) {
		t.Fatal("bad JWS")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(p[1])
	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["exp"] != float64(1800000300) || claims["dwk"] != "aauth-agent.json" {
		t.Fatal(claims)
	}
}

// A string containing an error name must not pass a Token-valued SFV assertion.
func TestAssertionsParseStructuredFieldsAndOptionalProblems(t *testing.T) {
	a := Assertion{ID: "error", Clause: "key.invalid-signature", Kind: "sfv-token", Header: "Signature-Error", Member: "error", Equals: json.RawMessage(`"invalid_signature"`)}
	for _, tc := range []struct{ header, state string }{{"x=?1, error=invalid_signature", "pass"}, {`error="invalid_signature"`, "fail"}, {"error=expired_jwt", "fail"}, {"error=@broken", "fail"}} {
		response := Response{Status: 401, Header: http.Header{"Signature-Error": []string{tc.header}}}
		if got := Check(a, response); got.State != tc.state {
			t.Fatalf("%s: %+v", tc.header, got)
		}
	}
	a = Assertion{ID: "problem", Clause: "key.response-body", Kind: "problem-if-present", Equals: json.RawMessage(`"invalid_signature"`)}
	r := Response{Status: 401, Header: http.Header{}}
	if got := Check(a, r); got.State != "not_exercised" {
		t.Fatal(got)
	}
	r.Header.Set("Content-Type", "application/problem+json")
	r.Body = []byte(`{"type":"urn:ietf:params:sig-error:expired_jwt","status":401}`)
	if got := Check(a, r); got.State != "fail" {
		t.Fatal(got)
	}
	r.Body = []byte(`{"type":"urn:ietf:params:sig-error:invalid_signature","status":401}`)
	if got := Check(a, r); got.State != "pass" {
		t.Fatal(got)
	}
}

// A missing JSON member must not satisfy an explicit null expectation.
func TestJSONMemberRequiresPresenceEvenWhenExpectedNull(t *testing.T) {
	a := Assertion{ID: "null", Clause: "test", Kind: "json-member", Member: "claim", Equals: json.RawMessage(`null`)}
	if Check(a, Response{Body: []byte(`{}`)}).State != "fail" {
		t.Fatal("absent member matched null")
	}
	if Check(a, Response{Body: []byte(`{"claim":null}`)}).State != "pass" {
		t.Fatal("present null failed")
	}
}

// The draft's required_input list does not prescribe a component order.
func TestRequiredCoverageIsComparedAsASet(t *testing.T) {
	a := Assertion{ID: "coverage", Clause: "core.verification", Kind: "sfv-string-set", Header: "Signature-Error", Member: "required_input", Equals: json.RawMessage(`["@method","@authority","@path","signature-key"]`)}
	for _, tc := range []struct{ header, state string }{
		{`error=invalid_input, required_input=("signature-key" "@path" "@authority" "@method")`, "pass"},
		{`error=invalid_input, required_input=("signature-key" "@path" "@authority")`, "fail"},
		{`error=invalid_input, required_input=(signature-key "@path" "@authority" "@method")`, "fail"},
	} {
		if got := Check(a, Response{Header: http.Header{"Signature-Error": []string{tc.header}}}); got.State != tc.state {
			t.Fatalf("%s: %+v", tc.header, got)
		}
	}
}
