package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// eventsPayload is the fixture AsyncAPI message every delivery with a body carries.
var eventsPayload = []byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}`)

// eventsRegistration is the fixture registration body.
var eventsRegistration = []byte(`{"event_types":["slot.available"]}`)

// requestRecord is one logical request the harness built, with the signature
// base it signed.
type requestRecord struct {
	stage   string
	request *http.Request
	body    []byte
	base    string
}

func bodyS256(body []byte) string {
	digest := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// signEventsRequest signs with independent Ed25519 code. A body carries
// Content-Type and Content-Digest; covered lists the components signed.
func signEventsRequest(f Fixture, stage, seed, method, target, credential string, body []byte, covered []string) (*requestRecord, error) {
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Signature-Key", credential)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	}
	var names, lines []string
	for _, component := range covered {
		value := canonicalField(request.Header, component)
		switch component {
		case "@method":
			value = method
		case "@authority":
			value = request.URL.Host
		case "@path":
			value = request.URL.EscapedPath()
		}
		names = append(names, fmt.Sprintf("%q", component))
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	params := fmt.Sprintf("(%s);created=%d", strings.Join(names, " "), f.Now)
	lines = append(lines, `"@signature-params": `+params)
	base := strings.Join(lines, "\n")
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(seedKey(seed), []byte(base)))+":")
	return &requestRecord{stage: stage, request: request, body: body, base: base}, nil
}

func eventsCovered(body bool) []string {
	covered := []string{"@method", "@authority", "@path", "signature-key"}
	if body {
		covered = append(covered, "content-type", "content-digest")
	}
	return covered
}

// startEventsDocuments serves the fixture Resources' and Person Server's
// metadata and public JWKS, each on its own loopback listener. The result maps
// each logical issuer to its physical transport.
func startEventsDocuments(f Fixture, e EventsFixture) (map[string]string, func(), error) {
	type identity struct{ issuer, dwk, seed, kid string }
	identities := []identity{{e.Resource.Issuer, "aauth-resource.json", e.Resource.Seed, e.Resource.Kid}, {e.OtherResource.Issuer, "aauth-resource.json", e.OtherResource.Seed, e.OtherResource.Kid}}
	if f.Person != nil {
		identities = append(identities, identity{f.Person.Issuer, "aauth-person.json", f.Person.Seed, f.Person.Kid})
	}
	transports := map[string]string{}
	var stops []func()
	stopAll := func() {
		for _, stop := range stops {
			stop()
		}
	}
	for _, id := range identities {
		key := publicJWK(id.seed)
		key["kid"] = id.kid
		metadata, _ := json.Marshal(map[string]any{"issuer": id.issuer, "jwks_uri": id.issuer + "/.well-known/jwks.json"})
		jwks, _ := json.Marshal(map[string]any{"keys": []any{key}})
		mux := http.NewServeMux()
		for path, body := range map[string][]byte{"/.well-known/" + id.dwk: metadata, "/.well-known/jwks.json": jwks} {
			mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				w.Write(body)
			})
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			stopAll()
			return nil, nil, err
		}
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		done := make(chan struct{})
		go func() { defer close(done); server.Serve(listener) }()
		stops = append(stops, func() { server.Close(); <-done })
		transports[id.issuer] = "http://" + listener.Addr().String()
	}
	return transports, stopAll, nil
}

// mintEventToken builds the event token for one delivery or Agent case and
// returns it with the seed that signs the HTTP request carrying it.
func mintEventToken(f Fixture, e EventsFixture, mutation, eid, jti string, body []byte) (string, string, error) {
	signer := e.Resource
	if mutation == "other-resource" {
		signer = e.OtherResource
	}
	claims := map[string]any{"iss": signer.Issuer, "dwk": "aauth-resource.json", "aud": f.Subject, "eid": eid, "jti": jti, "iat": f.Now, "exp": f.Now + 300}
	if len(body) > 0 {
		claims["body_s256"] = bodyS256(body)
	}
	typ, kid, seed := "aa-event+jwt", signer.Kid, signer.Seed
	switch mutation {
	case "body-mismatch":
		claims["body_s256"] = bodyS256([]byte(`{"event_type":"slot.cancelled"}`))
	case "missing-digest":
		delete(claims, "body_s256")
	case "digest-without-body":
		claims["body_s256"] = bodyS256(eventsPayload)
	case "cnf":
		claims["cnf"] = map[string]any{"jwk": publicJWK(signer.Seed)}
	case "expired":
		claims["iat"], claims["exp"] = f.Now-120, f.Now-60
	case "wrong-typ":
		typ = "aa-agent+jwt"
	case "wrong-dwk":
		claims["dwk"] = "aauth-agent.json"
	case "unknown-kid":
		kid = signer.Kid + "-unknown"
	case "unknown-eid":
		claims["eid"] = eid + "-unknown"
	case "wrong-aud":
		claims["aud"] = e.OtherAgent
	case "aud-other":
		claims["aud"] = e.OtherAgent
	case "aud-case":
		claims["aud"] = caseVariant(f.Subject)
	case "bad-signature":
		seed = e.OtherKeySeed
	}
	token, err := mintJWT(seed, kid, typ, claims)
	proofSeed := signer.Seed
	if mutation == "proof-key" {
		proofSeed = e.OtherKeySeed
	}
	return token, proofSeed, err
}

// caseVariant changes the case of the identifier's local part only.
func caseVariant(identifier string) string {
	local, domain, _ := strings.Cut(strings.TrimPrefix(identifier, "aauth:"), "@")
	swapped := []rune(local)
	for i, r := range swapped {
		switch {
		case r >= 'a' && r <= 'z':
			swapped[i] = r - 32
		case r >= 'A' && r <= 'Z':
			swapped[i] = r + 32
		}
	}
	return "aauth:" + string(swapped) + "@" + domain
}

func eventsDelivery(f Fixture, e EventsFixture, d eventsDeliveryInput, eid, jti, stage string) (*requestRecord, error) {
	var body []byte
	if d.Body {
		body = eventsPayload
	}
	token, proofSeed, err := mintEventToken(f, e, d.Mutation, eid, jti, body)
	if err != nil {
		return nil, err
	}
	covered := eventsCovered(d.Body)
	switch d.Mutation {
	case "uncovered-content-digest":
		covered = slices.DeleteFunc(covered, func(c string) bool { return c == "content-digest" })
	case "uncovered-content-type":
		covered = slices.DeleteFunc(covered, func(c string) bool { return c == "content-type" })
	}
	return signEventsRequest(f, stage, proofSeed, http.MethodPost, e.EventEndpoint, `sig=self-jwt;jwt="`+token+`"`, body, covered)
}

func eventsSubscribeToken(f Fixture, e EventsFixture, mutation, eid, jti string) (string, error) {
	claims := map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "aud": e.Resource.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}, "eid": eid, "jti": jti, "iat": f.Now - 10, "exp": f.Now + 300}
	typ, seed := "aa-subscribe+jwt", f.APSeed
	switch mutation {
	case "expired":
		claims["iat"], claims["exp"] = f.Now-120, f.Now-60
	case "wrong-aud":
		claims["aud"] = e.OtherResource.Issuer
	case "wrong-typ":
		typ = "aa-agent+jwt"
	case "wrong-dwk":
		claims["dwk"] = "aauth-person.json"
	case "empty-eid":
		claims["eid"] = ""
	case "bad-signature":
		seed = e.OtherKeySeed
	}
	return mintJWT(seed, f.Kid, typ, claims)
}

func eventsRegistrationRequest(f Fixture, e EventsFixture, mutation, target, eid, jti, stage string) (*requestRecord, error) {
	token, err := eventsSubscribeToken(f, e, mutation, eid, jti)
	if err != nil {
		return nil, err
	}
	signer := f.AgentSeed
	if mutation == "cnf-mismatch" {
		signer = e.OtherKeySeed
	}
	return signEventsRequest(f, stage, signer, http.MethodPost, target, `sig=jwt;jwt="`+token+`"`, eventsRegistration, eventsCovered(true))
}

func controlRequest(stage, target string, value any) (*requestRecord, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return &requestRecord{stage: stage, request: request, body: body}, nil
}

func controlMember(r *Response, member string) (string, error) {
	if r.Status != http.StatusOK {
		return "", fmt.Errorf("host control returned %d: %s", r.Status, strings.TrimSpace(string(r.Body)))
	}
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return "", err
	}
	value, ok := body[member].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("host control response lacks %s", member)
	}
	return value, nil
}

func runEventsSubscription(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	return runEventsRole(ctx, s, targets, o, ap, report, EventsSubscriptionRole,
		func(e EventsFixture) string { return e.Resource.Issuer + e.SubscriptionPath },
		func(f Fixture, e EventsFixture, documents map[string]string) eventsLauncher {
			config := eventsLauncher{Resource: &e.Resource, SubscriptionPath: e.SubscriptionPath, TicketPath: e.TicketPath}
			if f.Person != nil {
				config.PersonServers = []AgentProviderTrust{{Issuer: f.Person.Issuer, Transport: documents[f.Person.Issuer]}}
			}
			return config
		},
		func(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
			var in eventsSubscriptionInput
			DecodeInput(s, &in)
			stages, exchanges := map[string]*Response{}, []PersonExchange{}
			target := e.Resource.Issuer + e.SubscriptionPath
			if in.Ticket != "" {
				if f.Person == nil {
					return stages, exchanges, nil, fmt.Errorf("ticket scenarios need fixture person_server")
				}
				holder := f.AgentSeed
				if in.Ticket == "other-key" {
					holder = e.OtherKeySeed
				}
				person, err := mintJWT(f.Person.Seed, f.Person.Kid, "aa-person+jwt", map[string]any{"iss": f.Person.Issuer, "dwk": "aauth-person.json", "aud": e.Resource.Issuer, "sub": f.Person.Subject, "jti": s.ID + "-person", "iat": f.Now - 10, "exp": f.Now + 300, "cnf": map[string]any{"jwk": publicJWK(holder)}})
				if err != nil {
					return stages, exchanges, nil, err
				}
				control, err := controlRequest("ticket", e.Resource.Issuer+"/__fixture/ticket", map[string]string{"person_token": person})
				if err != nil {
					return stages, exchanges, nil, err
				}
				if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
					return stages, exchanges, nil, err
				}
				ticket, err := controlMember(stages["ticket"], "url")
				if err != nil {
					return stages, exchanges, nil, err
				}
				if !strings.HasPrefix(ticket, e.Resource.Issuer+e.TicketPath) || strings.ContainsAny(ticket[len(e.Resource.Issuer+e.TicketPath):], "/?#") {
					return stages, exchanges, nil, fmt.Errorf("ticket URL %q is not under the configured ticket path", ticket)
				}
				target = ticket
			}
			if in.Ticket == "reused" {
				first, err := eventsRegistrationRequest(f, e, "none", target, s.ID+"-first", s.ID+"-first", "first")
				if err != nil {
					return stages, exchanges, nil, err
				}
				if err := eventsExchange(ctx, first, ready, o, stages, &exchanges); err != nil {
					return stages, exchanges, nil, err
				}
			}
			registration, err := eventsRegistrationRequest(f, e, in.Mutation, target, s.ID, s.ID, "registration")
			if err != nil {
				return stages, exchanges, nil, err
			}
			err = eventsExchange(ctx, registration, ready, o, stages, &exchanges)
			return stages, exchanges, nil, err
		})
}

func runEventsProvider(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	return runEventsRole(ctx, s, targets, o, ap, report, EventsProviderRole,
		func(e EventsFixture) string { return e.EventEndpoint },
		func(f Fixture, e EventsFixture, documents map[string]string) eventsLauncher {
			return eventsLauncher{EventEndpoint: e.EventEndpoint, APSeed: f.APSeed, APKid: f.Kid, SubscriptionResource: e.Resource.Issuer, TrustedResources: []AgentProviderTrust{
				{Issuer: e.Resource.Issuer, Transport: documents[e.Resource.Issuer]},
				{Issuer: e.OtherResource.Issuer, Transport: documents[e.OtherResource.Issuer]},
			}}
		},
		func(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
			var in eventsProviderInput
			DecodeInput(s, &in)
			stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
			metadata, _ := http.NewRequest(http.MethodGet, f.Issuer+"/.well-known/aauth-agent.json", nil)
			if err := eventsExchange(ctx, &requestRecord{stage: "metadata", request: metadata}, ready, o, stages, &exchanges); err != nil {
				return stages, exchanges, own, err
			}
			control, err := controlRequest("subscribe", f.Issuer+"/__fixture/subscribe", map[string]int64{"max_uses": in.MaxUses})
			if err != nil {
				return stages, exchanges, own, err
			}
			if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
				return stages, exchanges, own, err
			}
			token, err := controlMember(stages["subscribe"], "token")
			if err != nil {
				return stages, exchanges, own, err
			}
			valid, claims, detail := observeSubscribeToken(f, e, token, in.MaxUses)
			for _, a := range s.Assertions {
				if a.Kind == "events-subscribe-token" {
					own[a.ID] = CompareResult(a, valid, detail)
					own[a.ID] = withActual(own[a.ID], claims)
				}
			}
			eid, _ := claims["eid"].(string)
			if eid == "" && len(in.Deliveries) > 0 {
				return stages, exchanges, own, fmt.Errorf("native subscribe token carries no eid to deliver to")
			}
			sent := []*requestRecord{}
			for i, d := range in.Deliveries {
				stage := fmt.Sprintf("delivery-%d", i+1)
				delivery, err := eventsDelivery(f, e, d, eid, s.ID+"-"+stage, stage)
				if err != nil {
					return stages, exchanges, own, err
				}
				if err := eventsExchange(ctx, delivery, ready, o, stages, &exchanges); err != nil {
					return stages, exchanges, own, err
				}
				sent = append(sent, delivery)
			}
			if in.Pending {
				control, err := controlRequest("pending", f.Issuer+"/__fixture/pending", map[string]string{})
				if err != nil {
					return stages, exchanges, own, err
				}
				if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
					return stages, exchanges, own, err
				}
				unchanged, detail, err := observePending(stages, sent)
				if err != nil {
					return stages, exchanges, own, err
				}
				for _, a := range s.Assertions {
					if a.Kind == "events-pending" {
						own[a.ID] = CompareResult(a, unchanged, detail)
					}
				}
			}
			return stages, exchanges, own, nil
		})
}

func withActual(r Result, claims map[string]any) Result {
	if claims != nil {
		r.Actual = map[string]any{"valid": r.Actual, "claims": claims}
	}
	return r
}

// observeSubscribeToken independently verifies a native AP's subscribe token:
// Ed25519 under the fixture AP key with typ and kid, and the claims the
// Structure section lists for this fixture's Agent and Resource.
func observeSubscribeToken(f Fixture, e EventsFixture, compact string, maxUses int64) (bool, map[string]any, string) {
	_, claims, err := verifyJWT(compact, f.APSeed, f.Kid, "aa-subscribe+jwt")
	if err != nil {
		return false, unverifiedClaims(compact), err.Error()
	}
	problems := []string{}
	expect := func(member string, want any) {
		if claims[member] != want {
			problems = append(problems, member)
		}
	}
	expect("iss", f.Issuer)
	expect("dwk", "aauth-agent.json")
	expect("sub", f.Subject)
	expect("aud", e.Resource.Issuer)
	if cnf, ok := claims["cnf"].(map[string]any); !ok || !bytes.Equal(confirmationPublicKey(cnf["jwk"]), seedKey(f.AgentSeed).Public().(ed25519.PublicKey)) {
		problems = append(problems, "cnf")
	}
	for _, member := range []string{"eid", "jti"} {
		if value, ok := claims[member].(string); !ok || value == "" {
			problems = append(problems, member)
		}
	}
	iat, iatOK := claims["iat"].(float64)
	exp, expOK := claims["exp"].(float64)
	if !iatOK || !expOK || exp <= iat || exp <= float64(f.Now) {
		problems = append(problems, "iat/exp")
	}
	uses, present := claims["max_uses"]
	if maxUses > 0 && uses != float64(maxUses) || maxUses == 0 && present {
		problems = append(problems, "max_uses")
	}
	if len(problems) > 0 {
		return false, claims, "subscribe token claims differ: " + strings.Join(problems, ", ")
	}
	return true, claims, ""
}

func unverifiedClaims(compact string) map[string]any {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

func runEventsAgent(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	return runEventsRole(ctx, s, targets, o, ap, report, EventsAgentRole,
		func(EventsFixture) string { return s.Fixture.Issuer + "/__fixture/event" },
		func(f Fixture, e EventsFixture, documents map[string]string) eventsLauncher {
			token, _ := MintToken(f, TokenSpec{IATOffset: -10, EXPOffset: 3600}, "events-agent")
			return eventsLauncher{AgentToken: token, TrustedResources: []AgentProviderTrust{{Issuer: e.Resource.Issuer, Transport: documents[e.Resource.Issuer]}}}
		},
		func(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
			var in eventsAgentInput
			DecodeInput(s, &in)
			stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
			var body []byte
			if in.Body {
				body = eventsPayload
			}
			token, _, err := mintEventToken(f, e, in.Mutation, "evt-"+s.ID, s.ID, body)
			if err != nil {
				return stages, exchanges, own, err
			}
			// The payload is JSON text, so the job carries its exact bytes as a string.
			job := map[string]string{"event_token": token, "body": string(body)}
			if len(body) > 0 {
				job["content_type"] = "application/json"
			}
			control, err := controlRequest("event", f.Issuer+"/__fixture/event", job)
			if err != nil {
				return stages, exchanges, own, err
			}
			if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
				return stages, exchanges, own, err
			}
			response := stages["event"]
			var decision struct {
				Accepted *bool  `json:"accepted"`
				Error    string `json:"error"`
			}
			if response.Status != http.StatusOK || json.Unmarshal(response.Body, &decision) != nil || decision.Accepted == nil {
				return stages, exchanges, own, fmt.Errorf("Agent host control returned %d: %s", response.Status, strings.TrimSpace(string(response.Body)))
			}
			for _, a := range s.Assertions {
				own[a.ID] = CompareResult(a, *decision.Accepted, decision.Error)
			}
			return stages, exchanges, own, nil
		})
}

// observePending compares the native AP's retained deliveries for the Agent
// with what the harness sent: every delivery answered 202 appears once with
// its exact token and body bytes, and no refused delivery appears.
func observePending(stages map[string]*Response, sent []*requestRecord) (bool, string, error) {
	response := stages["pending"]
	if response.Status != http.StatusOK {
		return false, "", fmt.Errorf("pending control returned %d: %s", response.Status, strings.TrimSpace(string(response.Body)))
	}
	var pending struct {
		Events []struct {
			EventToken string `json:"event_token"`
			Body       string `json:"body"`
		} `json:"events"`
	}
	if err := json.Unmarshal(response.Body, &pending); err != nil {
		return false, "", err
	}
	retained := map[string]string{}
	for _, event := range pending.Events {
		if _, repeated := retained[event.EventToken]; repeated {
			return false, "a delivery is pending twice", nil
		}
		retained[event.EventToken] = event.Body
	}
	accepted := 0
	for _, delivery := range sent {
		value := delivery.request.Header.Get("Signature-Key")
		token := strings.TrimSuffix(strings.TrimPrefix(value, `sig=self-jwt;jwt="`), `"`)
		body, present := retained[token]
		if stages[delivery.stage].Status != http.StatusAccepted {
			if present {
				return false, delivery.stage + " was refused but is pending for the Agent", nil
			}
			continue
		}
		accepted++
		if !present || body != string(delivery.body) {
			return false, delivery.stage + " is not pending with its exact token and body", nil
		}
	}
	if accepted != len(retained) {
		return false, "pending holds deliveries the harness did not send", nil
	}
	return true, "", nil
}
