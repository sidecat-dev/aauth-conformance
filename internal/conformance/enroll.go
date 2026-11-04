package conformance

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EnrolledAgent is an agent token a bootstrap Agent Provider signed for the
// suite's durable key. Seed is the ephemeral key the token's cnf binds;
// HTTP signatures that present Token are made with it.
type EnrolledAgent struct {
	Provider string
	Agent    string
	Token    string
	Seed     string
	PS       string
}

// enrollAgent enrolls durableSeed at provider and refreshes an agent token.
// ps is the Person Server the token must name. An empty ps leaves the
// provider's default. now is the Unix second written as created.
func enrollAgent(ctx context.Context, provider, durableSeed, ps string, now int64, timeout time.Duration) (EnrolledAgent, error) {
	if err := validateEnrollProvider(provider); err != nil {
		return EnrolledAgent{}, err
	}
	provider = strings.TrimRight(provider, "/")
	agent, err := bootstrapEnroll(ctx, provider, durableSeed, now, timeout)
	if err != nil {
		return EnrolledAgent{}, err
	}
	ephemeral, err := randomSeed()
	if err != nil {
		return EnrolledAgent{}, err
	}
	jti, err := randomID()
	if err != nil {
		return EnrolledAgent{}, err
	}
	naming := namingJWT(Fixture{Now: now}, durableSeed, ephemeral, durableSeed, jti, "")
	body := []byte(`{"evidence":{}}`)
	if ps != "" {
		encoded, err := json.Marshal(map[string]any{"ps": ps, "evidence": map[string]any{}})
		if err != nil {
			return EnrolledAgent{}, err
		}
		body = encoded
	}
	credential := `sig=jkt-jwt;jwt="` + naming + `"`
	result, status, err := bootstrapPOST(ctx, provider+"/bootstrap/refresh", ephemeral, credential, body, now, timeout)
	if err != nil {
		return EnrolledAgent{}, err
	}
	if status != http.StatusOK {
		return EnrolledAgent{}, fmt.Errorf("refresh at %s returned HTTP %d", provider, status)
	}
	token, _ := result["agent_token"].(string)
	if token == "" {
		return EnrolledAgent{}, fmt.Errorf("refresh at %s returned no agent_token", provider)
	}
	stamped, ok := jwtStringClaim(token, "ps")
	if ps != "" && (!ok || stamped != ps) {
		if !ok {
			stamped = "none"
		}
		return EnrolledAgent{}, fmt.Errorf("agent provider %s stamped ps %s, not %s", provider, stamped, ps)
	}
	return EnrolledAgent{Provider: provider, Agent: agent, Token: token, Seed: ephemeral, PS: stamped}, nil
}

func validateEnrollProvider(provider string) error {
	u, err := url.Parse(provider)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("bootstrap provider must be an https origin, got %q", provider)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("bootstrap provider must be https, got %q", provider)
		}
	default:
		return fmt.Errorf("bootstrap provider must be https, got %q", provider)
	}
	return nil
}

func bootstrapEnroll(ctx context.Context, provider, seed string, now int64, timeout time.Duration) (string, error) {
	credential := sigkeyMember("sig", "hwk", sigkeyHWKParams(publicJWK(seed))...)
	result, status, err := bootstrapPOST(ctx, provider+"/bootstrap/enroll", seed, credential, []byte(`{}`), now, timeout)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("enrollment at %s returned HTTP %d", provider, status)
	}
	agent, _ := result["agent"].(string)
	if agent == "" {
		return "", fmt.Errorf("enrollment at %s returned no agent", provider)
	}
	return agent, nil
}

func bootstrapPOST(ctx context.Context, target, seed, credential string, body []byte, now int64, timeout time.Duration) (map[string]any, int, error) {
	record, err := signEventsRequest(Fixture{Now: now}, "bootstrap", seed, http.MethodPost, target, credential, body, eventsCovered(true))
	if err != nil {
		return nil, 0, err
	}
	record.request = record.request.WithContext(ctx)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: providerTransport(ctx)}
	defer client.CloseIdleConnections()
	response, err := client.Do(record.request)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", target, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return nil, response.StatusCode, err
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return nil, response.StatusCode, fmt.Errorf("%s returned HTTP %d, not a JSON object", target, response.StatusCode)
	}
	return result, response.StatusCode, nil
}

// providerTransport dials the bootstrap provider with system roots. A
// deployment's -ca is for the servers under test, not for this provider.
// -resolve still applies, so a pinned provider is reached at that address.
func providerTransport(ctx context.Context) *http.Transport {
	n := networkFrom(ctx)
	return (&Network{Resolve: n.Resolve}).transport()
}

func randomSeed() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func jwtStringClaim(compact, name string) (string, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) < 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return "", false
	}
	value, ok := claims[name].(string)
	return value, ok && value != ""
}

// presentEnrolled makes f present e's token. HTTP signatures use e.Seed,
// which is the key the token confirms.
func presentEnrolled(f Fixture, e *EnrolledAgent) Fixture {
	if e == nil {
		return f
	}
	f.Enrolled = e
	f.AgentSeed = e.Seed
	return f
}

// enrolledGap is why a scenario cannot run with an enrolled agent token.
// The provider signs one lifetime. A scenario that needs an expired token,
// or a shorter one, is not exercised.
func enrolledGap(s Scenario) string {
	expired := s.Token.EXPOffset < 0
	short := s.Person != nil && s.Person.Mutation == "short-parent" || s.Federated != nil && s.Federated.Mutation == "short-agent"
	if !expired && !short {
		return ""
	}
	return "the agent token is issued by the named provider and this scenario needs a different lifetime"
}

// presentedSubject expects the enrolled agent identifier where an assertion
// names the fixture agent: a response's sub, or a value a supervised Person
// Server forwards to the suite's supervisor. Other values are left as written.
func presentedSubject(f Fixture, a Assertion) Assertion {
	named := a.Kind == "json-member" && a.Member == "sub" || a.Kind == "ss-request-equals"
	if f.Enrolled == nil || !named {
		return a
	}
	var expected string
	if json.Unmarshal(a.Equals, &expected) != nil || expected != f.Subject {
		return a
	}
	raw, err := json.Marshal(f.Enrolled.Agent)
	if err != nil {
		return a
	}
	a.Equals = raw
	return a
}

// agentJWT is the agent credential a request presents. An enrolled token is
// used for an ordinary lifetime. A lifetime the provider did not sign is an
// error, so the caller does not fall back to a fixture-signed token.
// presentsSuiteAgent reports whether this role sends the suite's own agent
// token to a server under test. Other roles sign as a harness party, or
// they grade an agent the deployment itself runs.
func presentsSuiteAgent(role string) bool {
	switch role {
	case ResourceRole, PersonServerRole, FederatedRole, R3IssuerRole, R3FederatedIssuerRole, SupervisionPersonServerRole:
		return true
	default:
		return false
	}
}

// trustTargets is the person server each such role asks the provider to
// name. The empty key is a token for a role that has no Person Server.
func trustTargets(d Deployment) map[string]struct{} {
	out := map[string]struct{}{}
	for role, spec := range d.Roles {
		if !presentsSuiteAgent(role) {
			continue
		}
		out[spec.PersonServer] = struct{}{}
	}
	return out
}

// providerFor is the Agent Provider that stamps ps. A map entry wins over
// fallback. The empty ps is a role with no Person Server and uses fallback.
// An empty fallback with no entry is an error. The suite does not invent one.
func providerFor(fallback string, providers map[string]string, ps string) (string, error) {
	if ps != "" {
		if named := providers[ps]; named != "" {
			return named, nil
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	if ps == "" {
		return "", fmt.Errorf("no bootstrap provider for a role with no Person Server")
	}
	return "", fmt.Errorf("no bootstrap provider for %s", ps)
}

// enrollTrust enrolls one agent token per person server. providers maps a
// Person Server to the provider that stamps it. A server with no entry, and
// the empty key, use fallback.
func enrollTrust(ctx context.Context, fallback string, providers map[string]string, durableSeed string, targets map[string]struct{}, now int64, timeout time.Duration) (map[string]*EnrolledAgent, error) {
	out := map[string]*EnrolledAgent{}
	for ps := range targets {
		provider, err := providerFor(fallback, providers, ps)
		if err != nil {
			return nil, err
		}
		enrolled, err := enrollAgent(ctx, provider, durableSeed, ps, now, timeout)
		if err != nil {
			label := ps
			if label == "" {
				label = "a role with no Person Server"
			}
			return nil, fmt.Errorf("agent trust for %s: %w", label, err)
		}
		out[ps] = &enrolled
	}
	return out, nil
}

func agentJWT(f Fixture, id string, issued, expires int64, ps string) (string, error) {
	if f.Enrolled != nil {
		if issued > f.Now || expires <= f.Now {
			return "", fmt.Errorf("enrolled agent token cannot represent %s", id)
		}
		return f.Enrolled.Token, nil
	}
	claims := map[string]any{
		"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": id,
		"iat": issued, "exp": expires, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
	}
	if ps != "" {
		claims["ps"] = ps
	}
	return mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", claims)
}
