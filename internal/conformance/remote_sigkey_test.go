package conformance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Catches variant key sets served under the names every other case uses,
// which a deployed verifier's cache would carry from case to case.
func TestRemoteSigkeyVariantsHaveTheirOwnParties(t *testing.T) {
	suite := loadSuite(t)
	k, _ := sigkeyFixture(suite.Fixture)
	documents := HarnessDocuments(suite.Fixture)
	kids := func(set string) []string {
		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		json.Unmarshal(documents[set], &jwks)
		out := []string{}
		for _, key := range jwks.Keys {
			out = append(out, key["kid"].(string))
		}
		return out
	}
	if got := kids(suite.Fixture.Issuer + "/.well-known/jwks.json"); strings.Join(got, ",") != suite.Fixture.Kid {
		t.Fatalf("fixture Agent Provider publishes %v", got)
	}
	if got := kids(k.Signer.Issuer + "/.well-known/jwks.json"); strings.Join(got, ",") != k.Signer.Kid {
		t.Fatalf("signer publishes %v", got)
	}
	mixed := kids("https://ap-mixed.conformance.test/.well-known/jwks.json")
	if len(mixed) == 0 || mixed[0] != suite.Fixture.Kid {
		t.Fatalf("mixed Agent Provider publishes %v", mixed)
	}
	if _, err := sigkeyMLDSA44(k.PQSeed); err == nil {
		if strings.Join(mixed, ",") != suite.Fixture.Kid+","+k.APPQKid || strings.Join(kids("https://signer-pq-only.conformance.test/.well-known/jwks.json"), ",") != k.PQKid {
			t.Fatalf("variant sets %v %v", mixed, kids("https://signer-pq-only.conformance.test/.well-known/jwks.json"))
		}
	}
	if _, ok := documents["https://signer-mixed.conformance.test/.well-known/aauth-resource.json"]; !ok {
		t.Fatal("no mixed signer metadata")
	}
}

// Catches a remote verifier case sent to the fixture verifier, signed with
// the fixture clock, naming the shared party for a variant key set, or run
// for a clause the deployment does not claim; and a direct JWKS URL the
// verifier cannot fetch during its case.
func TestRemoteSigkeyReachesDeployedVerifier(t *testing.T) {
	suite := loadSuite(t)
	k, _ := sigkeyFixture(suite.Fixture)
	harness := NewHarness(suite.Fixture)
	var mu sync.Mutex
	seen := map[string]http.Header{}
	var network *Network
	verifier := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		member := r.Header.Get("Signature-Key")
		scheme := strings.SplitN(strings.TrimPrefix(member, "sig="), ";", 2)[0]
		status := http.StatusOK
		if scheme == "jwks" {
			// The verifier fetches the direct JWKS URL through the suite.
			request, _ := http.NewRequest(http.MethodGet, k.JWKSURL, nil)
			response, err := Exchange(WithNetwork(context.Background(), network), request, "", time.Second)
			if err != nil || response.Status != http.StatusOK || !strings.Contains(string(response.Body), k.Signer.Kid) {
				status = http.StatusBadGateway
			}
		}
		mu.Lock()
		seen[r.Host+" "+member] = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"scheme": scheme})
	})
	names := append(HarnessNames(suite.Fixture), "verifier.example")
	network = testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "verifier.example" {
			verifier.ServeHTTP(w, r)
			return
		}
		harness.ServeHTTP(w, r)
	}), names...)
	claims := []string{}
	for _, c := range Claims(suite, SigkeyVerifierRole) {
		if c != "sigkey.v.self-jwt" {
			claims = append(claims, c)
		}
	}
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{SigkeyVerifierRole: {Resource: "https://verifier.example/v1/verify", Claims: claims}}}
	ctx := WithHarness(WithNetwork(context.Background(), network), harness)
	reports, err := RunRemote(ctx, suite, d, RemoteOptions{Timeout: 2 * time.Second, Skew: 5})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Case{}
	for _, c := range reports[0].Runs[0].Cases {
		cases[c.ID] = c
	}
	if c := cases["sigkey-self-jwt"]; c.Results[0].State != "not_claimed" || c.URL != "" {
		t.Fatalf("unclaimed self-jwt case ran: %+v", c)
	}
	if c := cases["sigkey-jwks"]; c.Results[0].State != "pass" || c.Results[1].State != "pass" {
		t.Fatalf("jwks case: %+v", c.Results)
	}
	if c := cases["sigkey-hwk-ed25519"]; c.Results[0].State != "pass" || !strings.HasPrefix(c.URL, "https://verifier.example/v1/verify") {
		t.Fatalf("hwk case: %s %+v", c.URL, c.Results)
	}
	now := time.Now().Unix()
	jwtIssuer := func(member string) string {
		token := strings.TrimSuffix(member[strings.Index(member, `jwt="`)+5:], `"`)
		payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
		var claims map[string]any
		json.Unmarshal(payload, &claims)
		return claims["iss"].(string) + " " + claims["sub"].(string)
	}
	mixedAP, mixedSigner := false, false
	for key, header := range seen {
		host, member, _ := strings.Cut(key, " ")
		if host != "verifier.example" {
			t.Fatalf("request reached %s", host)
		}
		_, created, _ := strings.Cut(header.Get("Signature-Input"), ";created=")
		stamp, _ := strconv.ParseInt(created, 10, 64)
		if stamp < now-120 || stamp > now+120 {
			t.Fatalf("signed with created=%s", created)
		}
		if strings.HasPrefix(member, "sig=jwt;") && jwtIssuer(member) == "https://ap-mixed.conformance.test aauth:Agent@ap-mixed.conformance.test" {
			mixedAP = true
		}
		if strings.Contains(member, `id="https://signer-mixed.conformance.test"`) {
			mixedSigner = true
		}
	}
	_, pqErr := sigkeyMLDSA44(k.PQSeed)
	if pqErr != nil {
		// Variant cases report the missing ML-DSA-44 support before sending.
		if c := cases["sigkey-ap-mixed-jwks"]; c.Results[0].State != "error" || !strings.Contains(c.Error, "ML-DSA-44") {
			t.Fatalf("%+v", c)
		}
		return
	}
	if !mixedAP || !mixedSigner {
		t.Fatalf("variant cases did not name their own parties: %v %v", mixedAP, mixedSigner)
	}
}
