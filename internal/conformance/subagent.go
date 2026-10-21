package conformance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

type SubagentSpec struct {
	Outcome         string            `json:"outcome"`
	ForeignProvider *SubagentProvider `json:"foreign_provider,omitempty"`
}
type SubagentProvider struct {
	Issuer string `json:"issuer"`
	Kid    string `json:"kid"`
	Seed   string `json:"seed_hex"`
}

var subagentOutcomes = []string{"direct", "immediate", "approval", "payment", "denied", "cancel", "expiry", "revoked-pending", "revoked-binding", "wrong-parent", "wrong-provider", "wrong-key", "depth", "expired-child", "child-direct", "child-poll", "short-child", "short-parent"}

func validateSubagentScenario(f Fixture, s Scenario) error {
	if s.Subagent == nil || !slices.Contains(subagentOutcomes, s.Subagent.Outcome) || s.Deferred != nil || s.Federated != nil || s.Person != nil || !reflect.DeepEqual(s.Request, RequestSpec{}) {
		return fmt.Errorf("invalid subagent profile")
	}
	if p := s.Subagent.ForeignProvider; p != nil {
		u, err := url.Parse(p.Issuer)
		seed, keyErr := hex.DecodeString(p.Seed)
		primarySeed, _ := hex.DecodeString(f.APSeed)
		if s.Subagent.Outcome != "wrong-provider" || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || p.Issuer == f.Issuer || p.Kid == "" || keyErr != nil || len(seed) != 32 || bytes.Equal(seed, primarySeed) {
			return fmt.Errorf("invalid independently trusted foreign AP fixture")
		}
	} else if s.Subagent.Outcome == "wrong-provider" {
		return fmt.Errorf("wrong-provider requires independently trusted foreign AP fixture")
	}
	copy := s
	copy.Subagent = nil
	copy.Federated = &FederatedSpec{Mutation: "none"}
	return validateFederatedScenario(f, copy)
}
func validSubagentAssertion(a Assertion) bool {
	if !slices.Contains([]string{"person", "challenge", "access", "pending", "waiting", "child-poll", "child-final", "approval", "result", "token", "protected", "parent-use", "gone", "as-gone", "cancel", "revoked", "timeout"}, a.Stage) {
		return false
	}
	if slices.Contains([]string{"status", "json-member"}, a.Kind) {
		return true
	}
	var b any
	if json.Unmarshal(a.Equals, &b) != nil {
		return false
	}
	if _, ok := b.(bool); !ok {
		return false
	}
	switch a.Kind {
	case "subagent-cancelled":
		return a.Stage == "cancel"
	case "subagent-jwt":
		return a.Stage == "person" || a.Stage == "token"
	case "subagent-proof":
		return a.Stage == "access" || a.Stage == "approval" || a.Stage == "result"
	case "subagent-forwarded":
		return a.Stage == "access"
	case "subagent-refused", "subagent-no-token":
		return true
	case "subagent-pending":
		return slices.Contains([]string{"access", "pending", "waiting", "approval"}, a.Stage)
	}
	return false
}

const childSeed = "0606060606060606060606060606060606060606060606060606060606060606"

func runSubagents(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	f, p, a := s.Fixture, *s.Fixture.Person, *s.Fixture.Access
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			if target.Unavailable != "" {
				c := Case{ID: scenario.ID}
				for _, a := range scenario.Assertions {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: target.Unavailable})
				}
				run.Cases = append(run.Cases, c)
				continue
			}
			// Each case gets native state and a clock of its own. Revocation, expiry
			// and terminal continuation consumption cannot contaminate another case.
			relay := &deferredRelay{fixture: f, timeout: o.Timeout}
			listener := httptest.NewServer(relay)
			config := Bootstrap{PersonDirect: slices.Contains([]string{"direct", "wrong-key", "revoked-binding"}, scenario.Subagent.Outcome), Version: 1, Role: SubagentRole, Now: f.Now, Issuer: f.Issuer, Resource: f.Origin + f.Path, APTransport: ap, PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid, PersonSubject: p.Subject, PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime, PermittedScopes: p.PermittedScopes, ResourceKid: p.ResourceKid, ResourceJWK: publicJWK(p.ResourceSeed), ResourceSeed: p.ResourceSeed, AccessServer: a.Issuer, AccessSeed: a.Seed, AccessKid: a.Kid, FederationTransport: listener.URL}
			var stopAP func()
			var ready Ready
			var stop func()
			var err error
			if provider := scenario.Subagent.ForeignProvider; provider != nil {
				foreign := f
				foreign.Issuer, foreign.Kid, foreign.APSeed = provider.Issuer, provider.Kid, provider.Seed
				var transport string
				transport, stopAP, err = startAP(foreign)
				config.AdditionalAgentProviders = []AgentProviderTrust{{Issuer: provider.Issuer, Transport: transport}}
			}
			if err == nil {
				ready, stop, err = startAdapter(ctx, target, config, o)
			}
			run.Cases = append(run.Cases, runSubagentCase(ctx, f, scenario, target, ready.URL, o, relay, err))
			if stop != nil {
				stop()
			}
			listener.Close()
			if stopAP != nil {
				stopAP()
			}
		}
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}
func runSubagentCase(ctx context.Context, f Fixture, s Scenario, t Target, physical string, o Options, relay *deferredRelay, startError error) Case {
	c := Case{ID: s.ID}
	responses := map[string]Response{}
	observations := map[string]PersonObservation{}
	proofs := map[string]bool{}
	forwarded := false
	childFixture := f
	childFixture.AgentSeed = childSeed
	nowFixture := f
	exchange := func(stage string, r *http.Request, base string) (Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		e := PersonExchange{Stage: stage, Method: r.Method, URL: r.URL.String(), Headers: r.Header.Clone(), Body: body, SignatureBase: base}
		response, err := Exchange(ctx, r, physical, o.Timeout)
		if err != nil {
			e.Error = err.Error()
		} else {
			e.Response = &response
			responses[stage] = response
		}
		c.Exchanges = append(c.Exchanges, e)
		return response, err
	}
	send := func(stage, seed, method, location, token string, body []byte) (Response, error) {
		r, base, err := signedFixtureRequest(nowFixture, seed, method, location, `sig=jwt;jwt="`+token+`"`, body)
		if err != nil {
			return Response{}, err
		}
		return exchange(stage, r, base)
	}
	control := func(stage int, reference string, extra map[string]any) error {
		body := map[string]any{"stage": stage, "reference": reference}
		for k, v := range extra {
			body[k] = v
		}
		b, _ := json.Marshal(body)
		r, _ := http.NewRequest("POST", f.Person.Issuer+"/__fixture/subagent", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		response, err := exchange("host-control", r, "")
		if err == nil && response.Status != 204 {
			err = fmt.Errorf("host control HTTP %d", response.Status)
		}
		return err
	}
	capture := func(stage string) error {
		c.DeferredHandoffs = relay.snapshot()
		if len(c.DeferredHandoffs) == 0 {
			return fmt.Errorf("no AS exchange")
		}
		h := c.DeferredHandoffs[len(c.DeferredHandoffs)-1]
		if h.Error != "" {
			return fmt.Errorf("AS exchange: %s", h.Error)
		}
		if h.NativeResponse == nil {
			return fmt.Errorf("no native AS response")
		}
		responses[stage] = *h.NativeResponse
		proofs[stage] = h.Proof.ValidProof
		if stage == "access" {
			forwarded = h.Forwarded
		}
		return nil
	}
	execute := func() error {
		if startError != nil {
			return startError
		}
		outcome := s.Subagent.Outcome
		parentExp, childExp := f.Now+s.Token.EXPOffset, f.Now+s.Token.EXPOffset
		if outcome == "short-child" {
			childExp = f.Now + 45
		}
		if outcome == "short-parent" {
			parentExp = f.Now + 45
		}
		parent, err := federationAgentToken(f, s.ID+"-parent", f.Now+s.Token.IATOffset, parentExp)
		if err != nil {
			return err
		}
		childClaims := map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": strings.Replace(f.Subject, "@", "+child@", 1), "parent_agent": f.Subject, "cnf": map[string]any{"jwk": publicJWK(childSeed)}, "jti": s.ID + "-child", "iat": f.Now + s.Token.IATOffset, "exp": childExp}
		childAPSeed, childAPKid := f.APSeed, f.Kid
		switch outcome {
		case "wrong-parent":
			childClaims["parent_agent"] = strings.Replace(f.Subject, "Agent@", "Other@", 1)
		case "wrong-provider":
			foreign := s.Subagent.ForeignProvider
			if foreign == nil {
				return fmt.Errorf("missing foreign AP fixture")
			}
			issuer, err := url.Parse(foreign.Issuer)
			if err != nil {
				return err
			}
			childClaims["iss"] = foreign.Issuer
			local, _, _ := strings.Cut(childClaims["sub"].(string), "@")
			childClaims["sub"] = local + "@" + issuer.Hostname()
			childAPSeed, childAPKid = foreign.Seed, foreign.Kid
		case "expired-child":
			childClaims["iat"] = f.Now - 120
			childClaims["exp"] = f.Now - 1
		case "depth":
			// Keep the signer top-level so this exercises the grandchild
			// parameter refusal rather than the child-signed endpoint guard.
			childClaims["parent_agent"] = strings.Replace(f.Subject, "@", "+child@", 1)
			childClaims["sub"] = strings.Replace(f.Subject, "@", "+child+grandchild@", 1)
			childClaims["cnf"] = map[string]any{"jwk": publicJWK(strings.Repeat("08", 32))}
		}
		child, err := mintJWT(childAPSeed, childAPKid, "aa-agent+jwt", childClaims)
		if err != nil {
			return err
		}
		negativePerson := slices.Contains([]string{"wrong-parent", "wrong-provider", "depth", "expired-child", "child-direct"}, outcome)
		if !negativePerson && outcome != "direct" && outcome != "wrong-key" && outcome != "revoked-binding" {
			stage := 2
			if slices.Contains([]string{"approval", "child-poll", "denied", "cancel", "expiry", "revoked-pending"}, outcome) {
				stage = 1
			}
			if outcome == "payment" {
				stage = 0
			}
			if err := control(stage, "", nil); err != nil {
				return err
			}
		}
		body, _ := json.Marshal(map[string]string{"resource": f.Origin, "subagent_token": child})
		signer, credential := f.AgentSeed, parent
		if outcome == "child-direct" {
			signer, credential = childSeed, child
		}
		personResponse, err := send("person", signer, "POST", f.Person.Issuer+"/person", credential, body)
		if err != nil {
			return err
		}
		if negativePerson {
			return nil
		}
		person, err := responseToken(personResponse, "person_token")
		if err != nil {
			return err
		}
		po := checkResponseExpiry(personResponse, observePersonJWT(childFixture, *f.Person, person, "person", nil, min(parentExp, childExp)))
		observations["person"] = po
		if !po.Valid {
			return fmt.Errorf("invalid child Person: %s", po.Error)
		}
		var resource string
		direct := outcome == "direct" || outcome == "wrong-key" || outcome == "revoked-binding"
		if direct {
			key := childSeed
			if outcome == "wrong-key" {
				key = f.AgentSeed
			}
			resource, err = mintJWT(f.Person.ResourceSeed, f.Person.ResourceKid, "aa-resource+jwt", map[string]any{"iss": f.Origin, "dwk": "aauth-resource.json", "aud": f.Person.Issuer, "sub": f.Person.Subject, "ps": f.Person.Issuer, "presented_jti": po.Claims["jti"], "agent_jkt": thumbprint(key), "jti": s.ID + "-resource", "iat": f.Now, "exp": f.Now + 120, "scope": "read"})
		} else {
			challenge, err := send("challenge", childSeed, "GET", f.Origin+f.Path, person, nil)
			if err != nil {
				return err
			}
			resource, err = challengedResourceToken(challenge)
			if err != nil {
				return err
			}
			ro := observeFederatedResource(childFixture, resource, po.Claims)
			observations["challenge"] = ro
			if !ro.Valid {
				return fmt.Errorf("invalid child Resource: %s", ro.Error)
			}
		}
		if err != nil {
			return err
		}
		if outcome == "revoked-binding" {
			if err := control(2, "", map[string]any{"revoke": true, "parent_issuer": f.Issuer, "parent_subject": f.Subject}); err != nil {
				return err
			}
		}
		relay.reset(physical, "none", map[string]string{"resource_token": resource, "presented_token": person, "agent_token": parent, "subagent_token": child})
		body, _ = json.Marshal(map[string]string{"resource_token": resource, "presented_token": person, "subagent_token": child})
		pending, err := send("pending", f.AgentSeed, "POST", f.Person.Issuer+"/token", parent, body)
		if err != nil {
			return err
		}
		if outcome == "wrong-key" || outcome == "revoked-binding" {
			return nil
		}
		var tokenResponse Response
		if direct {
			tokenResponse = pending
			responses["token"] = pending
		} else {
			if err := capture("access"); err != nil {
				return err
			}
			if outcome == "immediate" || outcome == "short-child" || outcome == "short-parent" {
				tokenResponse = pending
				responses["token"] = pending
			} else {
				location := deferredLocation(pending, f.Person.Issuer+"/token")
				if location == "" {
					return fmt.Errorf("invalid parent pending URL")
				}
				id := location[strings.LastIndex(location, "/")+1:]
				if _, err := send("child-poll", childSeed, "GET", location, child, nil); err != nil {
					return err
				}
				if _, err := send("waiting", f.AgentSeed, "GET", location, parent, nil); err != nil {
					return err
				}
				if len(relay.snapshot()) != 1 {
					return fmt.Errorf("parent poll made implicit AS request")
				}
				if outcome == "cancel" {
					if _, err := send("cancel", f.AgentSeed, "DELETE", location, parent, nil); err != nil {
						return err
					}
					_, err := send("gone", f.AgentSeed, "GET", location, parent, nil)
					return err
				}
				if outcome == "expiry" {
					if err := control(1, "", map[string]any{"now_offset": 31}); err != nil {
						return err
					}
					nowFixture.Now += 31
					if _, err := send("timeout", f.AgentSeed, "GET", location, parent, nil); err != nil {
						return err
					}
					_, err := send("gone", f.AgentSeed, "GET", location, parent, nil)
					return err
				}
				if outcome == "revoked-pending" {
					if err := control(2, "", map[string]any{"revoke": true, "parent_issuer": f.Issuer, "parent_subject": f.Subject}); err != nil {
						return err
					}
					_, err := send("revoked", f.AgentSeed, "GET", location, parent, nil)
					return err
				}
				if outcome == "payment" {
					if err := control(1, id, nil); err != nil {
						return err
					}
					if err := capture("approval"); err != nil {
						return err
					}
				}
				stage := 2
				if outcome == "denied" {
					stage = -1
				}
				if err := control(stage, id, nil); err != nil {
					return err
				}
				if err := capture("result"); err != nil {
					return err
				}
				if outcome == "child-poll" {
					if _, err := send("child-final", childSeed, "GET", location, child, nil); err != nil {
						return err
					}
				}
				tokenResponse, err = send("token", f.AgentSeed, "GET", location, parent, nil)
				if err != nil {
					return err
				}
				if _, err := send("gone", f.AgentSeed, "GET", location, parent, nil); err != nil {
					return err
				}
				if outcome == "denied" {
					return nil
				}
			}
		}
		compact, err := responseToken(tokenResponse, "auth_token")
		if err != nil {
			return err
		}
		var auth PersonObservation
		if direct {
			auth = observePersonJWT(childFixture, *f.Person, compact, "auth", po.Claims, min(parentExp, childExp))
		} else {
			auth = observeFederatedAuth(childFixture, compact, po.Claims, min(parentExp, childExp))
		}
		auth = checkResponseExpiry(tokenResponse, auth)
		observations["token"] = auth
		if !auth.Valid {
			return fmt.Errorf("invalid child Auth: %s", auth.Error)
		}
		if !direct {
			if _, err := send("protected", childSeed, "GET", f.Origin+f.Path, compact, nil); err != nil {
				return err
			}
			if _, err := send("parent-use", f.AgentSeed, "GET", f.Origin+f.Path, compact, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	for i := range c.Exchanges {
		if v, ok := observations[c.Exchanges[i].Stage]; ok {
			c.Exchanges[i].JWT = &v
		}
	}
	for _, a := range s.Assertions {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals}
		response, ok := responses[a.Stage]
		switch {
		case !slices.Contains(t.Claims, a.Clause):
			result.State = "not_claimed"
		case !ok:
			result.State = "error"
			result.Detail = "required stage not exercised: " + c.Error
		case strings.HasPrefix(a.Kind, "subagent-"):
			actual := false
			switch a.Kind {
			case "subagent-jwt":
				actual = observations[a.Stage].Valid
			case "subagent-proof":
				actual = proofs[a.Stage]
			case "subagent-forwarded":
				actual = forwarded
			case "subagent-pending":
				base := f.Person.Issuer + "/token"
				if a.Stage == "access" || a.Stage == "approval" {
					base = f.Access.Issuer + "/token"
				}
				actual = validDeferredPending(response, base, "")
			case "subagent-cancelled":
				actual = response.Status >= 200 && response.Status < 300 && noCredential(response)
			case "subagent-refused":
				actual = response.Status >= 400 && response.Status < 500 && noCredential(response)
			case "subagent-no-token":
				actual = noCredential(response)
			}
			var want bool
			json.Unmarshal(a.Equals, &want)
			result.Actual = actual
			result.State = "fail"
			if actual == want {
				result.State = "pass"
			}
		default:
			result = Check(a, response)
		}
		c.Results = append(c.Results, result)
	}
	return c
}
func noCredential(r Response) bool {
	var v map[string]any
	if json.Unmarshal(r.Body, &v) != nil {
		return true
	}
	for _, name := range []string{"person_token", "auth_token", "access_token"} {
		if _, ok := v[name]; ok {
			return false
		}
	}
	return true
}
