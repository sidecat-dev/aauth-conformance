package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"

	"github.com/dunglas/httpsfv"
)

func runFederated(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	f, p, a := s.Fixture, *s.Fixture.Person, *s.Fixture.Access
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		relay := &federationRelay{fixture: f, timeout: options.Timeout}
		relayServer := httptest.NewServer(relay)
		config := Bootstrap{
			Version: 1, Role: FederatedRole, Now: f.Now, Issuer: f.Issuer,
			Resource: f.Origin + f.Path, APTransport: ap,
			PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid,
			PersonSubject: p.Subject, PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime,
			PermittedScopes: p.PermittedScopes, ResourceKid: p.ResourceKid,
			ResourceJWK: publicJWK(p.ResourceSeed), ResourceSeed: p.ResourceSeed,
			AccessServer: a.Issuer, AccessSeed: a.Seed, AccessKid: a.Kid,
			FederationTransport: relayServer.URL,
		}
		ready, stop, startError := startAdapter(ctx, target, config, options)
		if startError != nil {
			run.Error = startError.Error()
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runFederatedCase(ctx, f, scenario, target, ready.URL, options, relay, startError))
		}
		if stop != nil {
			stop()
		}
		relayServer.Close()
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}

func runFederatedCase(ctx context.Context, f Fixture, s Scenario, target Target, physical string, options Options, relay *federationRelay, startError error) Case {
	c := Case{ID: s.ID}
	responses := map[string]Response{}
	observations := map[string]PersonObservation{}
	relay.reset(physical, s.Federated.Mutation, nil)
	exchange := func(stage string, request *http.Request, base string) (Response, error) {
		var body []byte
		if request.Body != nil {
			var err error
			body, err = io.ReadAll(request.Body)
			if err != nil {
				return Response{}, err
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
		entry := PersonExchange{Stage: stage, Method: request.Method, URL: request.URL.String(),
			Headers: request.Header.Clone(), Body: body, SignatureBase: base}
		response, err := Exchange(ctx, request, physical, options.Timeout)
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.Response = &response
			responses[stage] = response
		}
		c.Exchanges = append(c.Exchanges, entry)
		return response, err
	}
	sendHeaders := func(stage, method, url, token string, body []byte, headers map[string]string) (Response, error) {
		request, base, err := signedFixtureRequest(f, f.AgentSeed, method, url, `sig=jwt;jwt="`+token+`"`, body)
		if err != nil {
			return Response{}, err
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		return exchange(stage, request, base)
	}
	send := func(stage, method, url, token string, body []byte) (Response, error) {
		return sendHeaders(stage, method, url, token, body, nil)
	}
	resourceURL := f.Origin + f.Path
	protectedURL := resourceURL
	switch s.Federated.Budget {
	case "grant", "consume":
		protectedURL += "-budget-grant"
	case "omit":
		protectedURL += "-budget-omit"
	case "header":
		protectedURL += "-budget-reserve"
	case "usage":
		protectedURL += "-budget-usage"
	}
	execute := func() error {
		if startError != nil {
			return startError
		}
		agentExp := f.Now + s.Token.EXPOffset
		agentToken, err := federationAgentToken(f, s.ID, f.Now+s.Token.IATOffset, agentExp)
		if err != nil {
			return err
		}
		if _, err := send("initial", "GET", resourceURL, agentToken, nil); err != nil {
			return err
		}
		var person string
		var po PersonObservation
		if s.Federated.HarnessPS {
			person, err = mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{
				"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": f.Origin,
				"sub": f.Person.Subject, "jti": "harness-" + s.ID,
				"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
				"iat": f.Now, "exp": min(f.Now+f.Person.Lifetime, agentExp),
			})
			if err != nil {
				return err
			}
			po = observePersonJWT(f, *f.Person, person, "person", nil, agentExp)
		} else {
			personBody, _ := json.Marshal(map[string]string{"resource": f.Origin})
			personResponse, err := send("person", "POST", f.Person.Issuer+"/person", agentToken, personBody)
			if err != nil {
				return err
			}
			person, err = responseToken(personResponse, "person_token")
			if err != nil {
				return err
			}
			po = checkResponseExpiry(personResponse, observePersonJWT(f, *f.Person, person, "person", nil, agentExp))
			observations["person"] = po
		}
		if !po.Valid {
			return fmt.Errorf("cannot advance from invalid Person token: %s", po.Error)
		}
		var challengeResponse Response
		var resource string
		if s.Federated.Budget != "" {
			body, bodyErr := budgetAuthorizationBody(s.Federated.Budget)
			if bodyErr != nil {
				return bodyErr
			}
			challengeResponse, err = send("challenge", "POST", f.Origin+"/authorize", person, body)
			if err != nil {
				return err
			}
			resource, err = responseToken(challengeResponse, "resource_token")
		} else {
			challengeResponse, err = send("challenge", "GET", resourceURL, person, nil)
			if err != nil {
				return err
			}
			resource, err = challengedResourceToken(challengeResponse)
		}
		if err != nil {
			return err
		}
		ro := observeFederatedResource(f, resource, po.Claims)
		observations["challenge"] = ro
		if !ro.Valid {
			return fmt.Errorf("cannot redeem invalid Resource challenge: %s", ro.Error)
		}
		// A shorter Agent credential is used only after Person issuance, so its
		// ceiling is decisive independently of the Person expiry.
		if s.Federated.Mutation == "short-agent" {
			agentExp = f.Now + 45
			agentToken, err = federationAgentToken(f, s.ID+"-short", f.Now-10, agentExp)
			if err != nil {
				return err
			}
		}
		if s.Federated.HarnessPS {
			body, _ := json.Marshal(map[string]string{
				"resource_token": resource, "presented_token": person, "agent_token": agentToken,
			})
			credential := fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-person.json";kid=%q`, f.Person.Issuer, f.Person.Kid)
			request, base, err := signedFixtureRequest(f, f.Person.Seed, "POST", f.Access.Issuer+"/token", credential, body)
			if err != nil {
				return err
			}
			if err := mutateASRequest(f, s.Federated.Mutation, request); err != nil {
				return err
			}
			if s.Federated.Mutation != "none" && s.Federated.Mutation != "short-agent" {
				base = "" // The original base does not describe the deliberately changed input.
			}
			response, err := exchange("access", request, base)
			if err != nil || response.Status != 200 {
				return err
			}
			compact, err := responseToken(response, "auth_token")
			if err != nil {
				return err
			}
			o := checkResponseExpiry(response, observeFederatedAuth(f, compact, po.Claims, agentExp))
			observations["access"] = o
			if s.Federated.Mutation == "none" || s.Federated.Mutation == "short-agent" {
				if !o.Valid {
					return fmt.Errorf("cannot use invalid AS Auth token: %s", o.Error)
				}
				_, err = send("protected", "GET", protectedURL, compact, nil)
			}
			return err
		}
		relay.reset(physical, s.Federated.Mutation, map[string]string{
			"resource_token": resource, "presented_token": person, "agent_token": agentToken,
		})
		tokenBody, _ := json.Marshal(map[string]string{"resource_token": resource, "presented_token": person})
		tokenResponse, err := send("token", "POST", f.Person.Issuer+"/token", agentToken, tokenBody)
		if err != nil {
			return err
		}
		c.Handoff = relay.snapshot()
		if c.Handoff == nil {
			return fmt.Errorf("PS made no observable AS request")
		}
		if c.Handoff.Error != "" {
			return fmt.Errorf("PS-to-AS exchange: %s", c.Handoff.Error)
		}
		if c.Handoff.NativeResponse == nil {
			return fmt.Errorf("no native AS response")
		}
		responses["access"] = *c.Handoff.NativeResponse
		if responses["access"].Status == 200 {
			compact, err := responseToken(responses["access"], "auth_token")
			if err != nil {
				return err
			}
			observations["access"] = checkResponseExpiry(responses["access"], observeFederatedAuth(f, compact, po.Claims, agentExp))
		}
		if tokenResponse.Status == 200 {
			compact, err := responseToken(tokenResponse, "auth_token")
			if err != nil {
				return err
			}
			o := checkResponseExpiry(tokenResponse, observeFederatedAuth(f, compact, po.Claims, agentExp))
			observations["token"] = o
			if s.Federated.Mutation == "none" || s.Federated.Mutation == "short-agent" {
				if !o.Valid {
					return fmt.Errorf("cannot use invalid delivered Auth token: %s", o.Error)
				}
				if s.Federated.Budget == "consume" {
					return presentBudgetConsumption(f, sendHeaders, observations, protectedURL, compact)
				}
				if s.Federated.Budget == "header" {
					return presentBudgetHeader(sendHeaders, protectedURL, compact)
				}
				if s.Federated.Budget == "usage" {
					return presentBudgetUsage(f, exchange, sendHeaders, protectedURL, compact)
				}
				_, err = send("protected", "GET", protectedURL, compact, nil)
				return err
			}
		}
		return nil
	}
	if err := execute(); err != nil {
		c.Error = err.Error()
	}
	for i := range c.Exchanges {
		if o, exists := observations[c.Exchanges[i].Stage]; exists {
			c.Exchanges[i].JWT = &o
		}
	}
	for _, assertion := range s.Assertions {
		result := Result{Assertion: assertion.ID, Clause: assertion.Clause, Expected: assertion.Equals}
		response, exists := responses[assertion.Stage]
		switch {
		case !slices.Contains(target.Claims, assertion.Clause):
			result.State = "not_claimed"
		case assertion.Stage == "handoff" && c.Handoff != nil:
			result.State = "fail"
			actual := c.Handoff.Forwarded
			if assertion.Kind == "fed-ps-proof" {
				actual = c.Handoff.Proof.ValidProof
			}
			var want bool
			json.Unmarshal(assertion.Equals, &want)
			result.Actual = actual
			if actual == want {
				result.State = "pass"
			}
		case exists:
			if assertion.Kind == "fed-budget" {
				result = checkFederatedBudget(assertion, observations[assertion.Stage])
				break
			}
			if assertion.Kind == "fed-consumed" {
				result = checkFederatedConsumed(assertion, observations[assertion.Stage], observations["token"])
				break
			}
			if assertion.Kind == "fed-challenge" {
				assertion.Kind = "ps-jwt"
			}
			result = checkPerson(assertion, response, observations[assertion.Stage])
		default:
			result.State, result.Detail = "error", c.Error
			if result.Detail == "" {
				result.Detail = "required stage was not exercised"
			}
		}
		c.Results = append(c.Results, result)
	}
	return c
}

func checkFederatedBudget(a Assertion, observation PersonObservation) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	var want any
	if err := json.Unmarshal(a.Equals, &want); err != nil {
		result.Detail = err.Error()
		return result
	}
	raw, present := observation.Claims["budget"]
	if want == nil {
		result.Actual = raw
		if !present {
			result.Actual = nil
			result.State = "pass"
		} else {
			result.Detail = "budget claim is present"
		}
		return result
	}
	if !present {
		result.Detail = "missing budget claim"
		return result
	}
	result.Actual = raw
	if reflect.DeepEqual(raw, want) {
		result.State = "pass"
	}
	return result
}

func presentBudgetUsage(
	f Fixture,
	exchange func(stage string, request *http.Request, base string) (Response, error),
	send func(stage, method, url, token string, body []byte, headers map[string]string) (Response, error),
	protectedURL, compact string,
) error {
	if _, err := send("protected", "GET", protectedURL, compact, nil, nil); err != nil {
		return err
	}
	credential := fmt.Sprintf(`sig=jwks_uri;id=%q;dwk="aauth-access.json";kid=%q`, f.Access.Issuer, f.Access.Kid)
	post := func(stage, body string) error {
		request, base, err := signedFixtureRequest(f, f.Access.Seed, "POST", f.Origin+"/usage", credential, []byte(body))
		if err != nil {
			return err
		}
		_, err = exchange(stage, request, base)
		return err
	}
	known := fmt.Sprintf(`{"sub":%q,"ps":%q}`, f.Person.Subject, f.Person.Issuer)
	if err := post("usage", known); err != nil {
		return err
	}
	if err := post("usage-unknown", fmt.Sprintf(`{"sub":"unknown-person","ps":%q}`, f.Person.Issuer)); err != nil {
		return err
	}
	if err := post("usage-no-ps", fmt.Sprintf(`{"sub":%q}`, f.Person.Subject)); err != nil {
		return err
	}
	if err := post("usage-two-keys", fmt.Sprintf(`{"sub":%q,"tenant":"fixture","ps":%q}`, f.Person.Subject, f.Person.Issuer)); err != nil {
		return err
	}
	return post("usage-jkts", `{"jkts":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}`)
}

func presentBudgetHeader(
	send func(stage, method, url, token string, body []byte, headers map[string]string) (Response, error),
	protectedURL, compact string,
) error {
	if _, err := send("reserved", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Hold":   "800000",
		"X-Fixture-Settle": "400000",
	}); err != nil {
		return err
	}
	if _, err := send("abandoned", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Hold": "500000",
	}); err != nil {
		return err
	}
	_, err := send("following", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Hold":   "100000",
		"X-Fixture-Settle": "100000",
	})
	return err
}

func presentBudgetConsumption(
	f Fixture,
	send func(stage, method, url, token string, body []byte, headers map[string]string) (Response, error),
	observations map[string]PersonObservation,
	protectedURL, compact string,
) error {
	if _, err := send("protected", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Cost": "1500000",
	}); err != nil {
		return err
	}
	same, err := send("step-up", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Cost": "1000000",
	})
	if err != nil {
		return err
	}
	if token, tokenErr := challengedResourceToken(same); tokenErr == nil {
		observations["step-up"] = observeFederatedResource(f, token, observations["token"].Claims)
	}
	other, err := send("step-up-other", "GET", protectedURL, compact, nil, map[string]string{
		"X-Fixture-Cost":  "1000000",
		"X-Fixture-Offer": "points",
	})
	if err != nil {
		return err
	}
	if token, tokenErr := challengedResourceToken(other); tokenErr == nil {
		observations["step-up-other"] = observeFederatedResource(f, token, observations["token"].Claims)
	}
	return nil
}

func checkFederatedConsumed(a Assertion, observation, auth PersonObservation) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	var want any
	if err := json.Unmarshal(a.Equals, &want); err != nil {
		result.Detail = err.Error()
		return result
	}
	raw, present := observation.Claims["budget_consumed"]
	if want == nil {
		result.Actual = raw
		if !present {
			result.Actual = nil
			result.State = "pass"
		} else {
			result.Detail = "budget_consumed claim is present"
		}
		return result
	}
	if !present {
		result.Detail = "missing budget_consumed claim"
		return result
	}
	result.Actual = raw
	expected, ok := want.(map[string]any)
	got, gotOK := raw.(map[string]any)
	consumed, consumedOK := expected["consumed"].(float64)
	authJTI, jtiOK := auth.Claims["jti"].(string)
	if !ok || !gotOK || !consumedOK || !jtiOK || len(expected) != 1 || len(got) != 2 {
		result.Detail = "budget_consumed shape does not match"
		return result
	}
	if got["jti"] == authJTI && got["consumed"] == consumed {
		result.State = "pass"
	}
	return result
}

func budgetAuthorizationBody(mode string) ([]byte, error) {
	amount := int64(5_000_000)
	if mode == "omit" {
		amount = 9_000_000
	}
	return json.Marshal(map[string]any{
		"scope":  "read",
		"budget": map[string]any{"amount": amount, "unit": "credits", "decimals": 0},
	})
}

func federationAgentToken(f Fixture, id string, issued, expires int64) (string, error) {
	return mintJWT(f.APSeed, f.Kid, "aa-agent+jwt", map[string]any{
		"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "jti": id,
		"iat": issued, "exp": expires, "ps": f.Person.Issuer,
		"cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)},
	})
}

func responseToken(response Response, name string) (string, error) {
	var body map[string]json.RawMessage
	if response.Status != 200 || json.Unmarshal(response.Body, &body) != nil {
		return "", fmt.Errorf("expected %s response, got HTTP %d", name, response.Status)
	}
	var compact string
	if json.Unmarshal(body[name], &compact) != nil || compact == "" {
		return "", fmt.Errorf("missing %s", name)
	}
	return compact, nil
}

func checkResponseExpiry(response Response, o PersonObservation) PersonObservation {
	var body map[string]json.RawMessage
	var expires int64
	iat, ok := o.Claims["iat"].(float64)
	if json.Unmarshal(response.Body, &body) != nil || json.Unmarshal(body["expires_in"], &expires) != nil ||
		!ok || o.Claims["exp"] != iat+float64(expires) {
		o.Valid, o.Lifetime = false, false
		o.Error = "expires_in disagrees with signed expiration"
	}
	return o
}

func challengedResourceToken(response Response) (string, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(response.Header.Values("AAuth-Requirement"))
	if err != nil {
		return "", err
	}
	value, _ := dictionary.Get("requirement")
	item, ok := value.(httpsfv.Item)
	if !ok || item.Value != httpsfv.Token("auth-token") || item.Params == nil {
		return "", fmt.Errorf("missing auth-token requirement")
	}
	parameter, _ := item.Params.Get("resource-token")
	token, ok := parameter.(string)
	if !ok || strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("missing Resource token in challenge")
	}
	return token, nil
}
