package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
)

type PersonExchange struct {
	Stage         string             `json:"stage"`
	Method        string             `json:"method"`
	URL           string             `json:"url"`
	Headers       http.Header        `json:"request_headers"`
	Body          []byte             `json:"request_body_base64"`
	SignatureBase string             `json:"signature_base"`
	Response      *Response          `json:"response,omitempty"`
	JWT           *PersonObservation `json:"jwt,omitempty"`
	Error         string             `json:"error,omitempty"`
}

func runPersonServers(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	p := *s.Fixture.Person
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		config := Bootstrap{Version: 1, Role: PersonServerRole, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: s.Fixture.Origin + s.Fixture.Path, APTransport: ap, PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid, PersonSubject: p.Subject, PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime, PermittedScopes: p.PermittedScopes, ResourceKid: p.ResourceKid, ResourceJWK: publicJWK(p.ResourceSeed)}
		ready, stop, startError := startAdapter(ctx, target, config, options)
		if startError != nil {
			run.Error = startError.Error()
		}
		for _, scenario := range s.Scenarios {
			run.Cases = append(run.Cases, runPersonCase(ctx, s.Fixture, scenario, target, ready.URL, options, startError))
		}
		if stop != nil {
			stop()
		}
		report.Runs = append(report.Runs, run)
	}
	report.Execution = "failed_or_incomplete"
	if report.Success() {
		report.Execution = "passed"
	}
	return report
}

// runPersonCase performs one scenario's person and token exchanges against a
// Person Server and grades them.
func runPersonCase(ctx context.Context, f Fixture, scenario Scenario, target Target, physical string, options Options, startError error) Case {
	p := *f.Person
	c := Case{ID: scenario.ID}
	executionError := startError
	responses := map[string]Response{}
	observations := map[string]PersonObservation{}
	person := ""
	var claims map[string]any
	for _, stage := range []string{"person", "token"} {
		if executionError != nil {
			break
		}
		if stage == "token" && (scenario.Person.Mutation == "tampered-proof" || scenario.Person.Mutation == "tampered-body") {
			break
		}
		req, base, e := buildPersonExchange(f, p, scenario, stage, person, claims)
		if e != nil {
			executionError = e
			break
		}
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		exchange := PersonExchange{Stage: stage, Method: req.Method, URL: req.URL.String(), Headers: req.Header.Clone(), Body: body, SignatureBase: string(base)}
		response, e := Exchange(ctx, req, physical, options.Timeout)
		if e != nil {
			exchange.Error = e.Error()
			executionError = e
		} else {
			exchange.Response = &response
			responses[stage] = response
			if response.Status == 200 {
				var result map[string]json.RawMessage
				if e = json.Unmarshal(response.Body, &result); e != nil {
					executionError = fmt.Errorf("%s response JSON: %w", stage, e)
				} else {
					token := ""
					field := "person_token"
					kind := "person"
					if stage == "token" {
						field = "auth_token"
						kind = "auth"
					}
					json.Unmarshal(result[field], &token)
					agentExp := f.Now + scenario.Token.EXPOffset
					if scenario.Person.Mutation == "short-parent" {
						agentExp = f.Now + 45
					}
					observed := observePersonJWT(f, p, token, kind, claims, agentExp)
					var expires int64
					if json.Unmarshal(result["expires_in"], &expires) != nil || !f.signedExpiry(observed.Claims, expires) {
						observed.Lifetime = false
						observed.Valid = false
						observed.Error = "expires_in disagrees with signed expiration"
					}
					exchange.JWT = &observed
					observations[stage] = observed
					if stage == "person" {
						person = token
						claims = observed.Claims
						if !observed.Valid {
							executionError = fmt.Errorf("cannot construct Resource token from unverified Person response: %s", observed.Error)
						}
					}
				}
			} else if stage == "person" && scenario.Person.Mutation != "tampered-proof" && scenario.Person.Mutation != "tampered-body" {
				executionError = fmt.Errorf("person binding returned HTTP %d before token exchange", response.Status)
			}
		}
		c.Exchanges = append(c.Exchanges, exchange)
	}
	if executionError != nil {
		c.Error = executionError.Error()
	}
	for _, a := range scenario.Assertions {
		result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals}
		response, exists := responses[a.Stage]
		switch {
		case !slices.Contains(target.Claims, a.Clause):
			result.State = "not_claimed"
		case exists:
			result = checkPerson(a, response, observations[a.Stage])
		default:
			result.State = "error"
			result.Detail = c.Error
			if result.Detail == "" {
				result.Detail = "required stage was not exercised"
			}
		}
		c.Results = append(c.Results, result)
	}
	return c
}
