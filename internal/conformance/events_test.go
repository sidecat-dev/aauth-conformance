package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func eventsTestFixture(t *testing.T) (Fixture, EventsFixture) {
	t.Helper()
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	e, err := eventsFixture(suite.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	return suite.Fixture, e
}

// Catches an oracle that accepts an AP subscribe token with the wrong holder
// key, audience or use limit, or rejects a correct one.
func TestEventsSubscribeTokenOracle(t *testing.T) {
	f, e := eventsTestFixture(t)
	claims := func() map[string]any {
		return map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "aud": e.Resource.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}, "eid": "evt-1", "jti": "st-1", "iat": f.Now, "exp": f.Now + 600, "max_uses": 2}
	}
	good, _ := mintJWT(f.APSeed, f.Kid, "aa-subscribe+jwt", claims())
	if ok, _, detail := observeSubscribeToken(f, e, good, 2); !ok {
		t.Fatal(detail)
	}
	for name, mutate := range map[string]func(map[string]any){
		"cnf":      func(c map[string]any) { c["cnf"] = map[string]any{"jwk": publicJWK(e.OtherKeySeed)} },
		"aud":      func(c map[string]any) { c["aud"] = e.OtherResource.Issuer },
		"max_uses": func(c map[string]any) { c["max_uses"] = 3 },
		"eid":      func(c map[string]any) { c["eid"] = "" },
	} {
		c := claims()
		mutate(c)
		token, _ := mintJWT(f.APSeed, f.Kid, "aa-subscribe+jwt", c)
		if ok, _, _ := observeSubscribeToken(f, e, token, 2); ok {
			t.Fatalf("%s mutation accepted", name)
		}
	}
	if ok, _, _ := observeSubscribeToken(f, e, good, 0); ok {
		t.Fatal("unrequested max_uses accepted")
	}
	forged, _ := mintJWT(e.OtherKeySeed, f.Kid, "aa-subscribe+jwt", claims())
	if ok, _, _ := observeSubscribeToken(f, e, forged, 2); ok {
		t.Fatal("token signed by another key accepted")
	}
}

// Catches a delivery builder whose mutation does not change the property it
// names, or whose valid proof would not verify with the Resource key.
func TestEventsDeliveryInputs(t *testing.T) {
	f, e := eventsTestFixture(t)
	valid, err := eventsDelivery(f, e, eventsDeliveryInput{Mutation: "none", Body: true}, "evt-1", "ev-1", "delivery-1")
	if err != nil {
		t.Fatal(err)
	}
	signature := strings.TrimSuffix(strings.TrimPrefix(valid.request.Header.Get("Signature"), "sig=:"), ":")
	raw, _ := base64.StdEncoding.DecodeString(signature)
	if !ed25519.Verify(seedKey(e.Resource.Seed).Public().(ed25519.PublicKey), []byte(valid.base), raw) || !strings.Contains(valid.base, `"content-digest"`) || !strings.HasPrefix(valid.request.Header.Get("Signature-Key"), "sig=self-jwt;") {
		t.Fatalf("valid delivery proof: %s", valid.base)
	}
	claims := func(record *requestRecord) map[string]any {
		value := strings.TrimSuffix(strings.TrimPrefix(record.request.Header.Get("Signature-Key"), `sig=self-jwt;jwt="`), `"`)
		return unverifiedClaims(value)
	}
	if claims(valid)["body_s256"] != bodyS256(eventsPayload) || claims(valid)["cnf"] != nil {
		t.Fatal("valid delivery claims")
	}
	uncovered, _ := eventsDelivery(f, e, eventsDeliveryInput{Mutation: "uncovered-content-digest", Body: true}, "evt-1", "ev-2", "delivery-1")
	if strings.Contains(uncovered.request.Header.Get("Signature-Input"), "content-digest") || uncovered.request.Header.Get("Content-Digest") == "" {
		t.Fatal("uncovered content-digest still covered or absent")
	}
	empty, _ := eventsDelivery(f, e, eventsDeliveryInput{Mutation: "digest-without-body"}, "evt-1", "ev-3", "delivery-1")
	if len(empty.body) != 0 || claims(empty)["body_s256"] == nil {
		t.Fatal("digest-without-body")
	}
	other, _ := eventsDelivery(f, e, eventsDeliveryInput{Mutation: "other-resource", Body: true}, "evt-1", "ev-4", "delivery-1")
	if claims(other)["iss"] != e.OtherResource.Issuer {
		t.Fatal("other-resource issuer")
	}
	if caseVariant("aauth:Agent@ap.conformance.test") != "aauth:aGENT@ap.conformance.test" {
		t.Fatal(caseVariant("aauth:Agent@ap.conformance.test"))
	}
}
