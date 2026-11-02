package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
)

var eventsDeliveryProperties = []string{"self-jwt", "eid", "cnf-absent", "body-s256", "coverage", "proof"}

// eventsInbox plays the Agent Provider for the native Resource's deliveries:
// it publishes metadata naming event_endpoint and captures each delivery.
type eventsInbox struct {
	mu        sync.Mutex
	captured  []Captured
	remaining int64
}

func (inbox *eventsInbox) reset(maxUses int64) {
	inbox.mu.Lock()
	defer inbox.mu.Unlock()
	inbox.captured, inbox.remaining = nil, maxUses
}

func (inbox *eventsInbox) deliveries() []Captured {
	inbox.mu.Lock()
	defer inbox.mu.Unlock()
	return slices.Clone(inbox.captured)
}

// receive captures one delivery and accepts it, with remaining_uses while
// the subscription has a use limit.
func (inbox *eventsInbox) receive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(body) > 65536 {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	inbox.mu.Lock()
	inbox.captured = append(inbox.captured, Captured{Method: r.Method, URL: "https://" + r.Host + r.URL.RequestURI(), Headers: r.Header.Clone(), Body: body})
	reply := []byte{}
	if inbox.remaining > 0 {
		inbox.remaining--
		reply, _ = json.Marshal(map[string]int64{"remaining_uses": inbox.remaining})
	}
	inbox.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	if len(reply) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(reply)))
	w.WriteHeader(http.StatusAccepted)
	w.Write(reply)
}

func startEventsInbox(f Fixture, e EventsFixture) (string, *eventsInbox, func(), error) {
	inbox := &eventsInbox{}
	endpoint, _ := url.Parse(e.EventEndpoint)
	key := publicJWK(f.APSeed)
	key["kid"] = f.Kid
	metadata, _ := json.Marshal(map[string]any{"issuer": f.Issuer, "jwks_uri": f.Issuer + "/.well-known/jwks.json", "event_endpoint": e.EventEndpoint})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{key}})
	mux := http.NewServeMux()
	for path, body := range map[string][]byte{"/.well-known/aauth-agent.json": metadata, "/.well-known/jwks.json": jwks} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Write(body)
		})
	}
	mux.HandleFunc("POST "+endpoint.EscapedPath(), inbox.receive)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	return "http://" + listener.Addr().String(), inbox, func() { server.Close(); <-done }, nil
}

// eventsDeliveryObservation is the independent reading of one captured delivery.
type eventsDeliveryObservation struct {
	Properties map[string]bool `json:"properties"`
	Covered    []string        `json:"covered,omitempty"`
	Claims     map[string]any  `json:"claims,omitempty"`
	Base       string          `json:"signature_base,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// observeEventsDelivery reads a delivery with independent Structured Field,
// SHA-256 and signature code: the self-jwt event token under the Resource key,
// its claims against the subscription, coverage and the HTTP proof.
func observeEventsDelivery(f Fixture, e EventsFixture, c Captured, eid string) eventsDeliveryObservation {
	o := eventsDeliveryObservation{Properties: map[string]bool{}}
	for _, property := range eventsDeliveryProperties {
		o.Properties[property] = false
	}
	inputs, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Input"))
	if err != nil || len(inputs.Names()) != 1 {
		o.Error = "expected exactly one Signature-Input label"
		return o
	}
	label := inputs.Names()[0]
	keys, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature-Key"))
	if err != nil {
		o.Error = err.Error()
		return o
	}
	member, _ := keys.Get(label)
	item, ok := member.(httpsfv.Item)
	if !ok || item.Value != httpsfv.Token("self-jwt") || item.Params == nil {
		o.Error = "Signature-Key member is not a self-jwt"
		return o
	}
	value, _ := item.Params.Get("jwt")
	token, _ := value.(string)
	resourceKeys := e.Resource.keys()
	head, claims, err := verifyJWTWith(token, resourceKeys, "aa-event+jwt")
	o.Claims = claims
	if err != nil {
		o.Claims = unverifiedClaims(token)
		o.Error = err.Error()
	} else {
		iat, iatOK := claims["iat"].(float64)
		exp, expOK := claims["exp"].(float64)
		jti, _ := claims["jti"].(string)
		o.Properties["self-jwt"] = claims["iss"] == e.Resource.Issuer && claims["dwk"] == "aauth-resource.json" && claims["aud"] == f.Subject && jti != "" && iatOK && expOK && exp > iat && exp > float64(f.Now)
		o.Properties["eid"] = claims["eid"] == eid
		_, hasCNF := claims["cnf"]
		o.Properties["cnf-absent"] = !hasCNF
		digest, hasDigest := claims["body_s256"]
		o.Properties["body-s256"] = len(c.Body) > 0 && hasDigest && digest == bodyS256(c.Body) || len(c.Body) == 0 && !hasDigest
	}
	member, _ = inputs.Get(label)
	input, ok := member.(httpsfv.InnerList)
	if !ok {
		o.Error = "Signature-Input member is not an Inner List"
		return o
	}
	target, err := url.Parse(c.URL)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	lines := []string{}
	valid := true
	for _, entry := range input.Items {
		component, ok := entry.Value.(string)
		if !ok || slices.Contains(o.Covered, component) || entry.Params != nil && len(entry.Params.Names()) > 0 {
			valid = false
			break
		}
		o.Covered = append(o.Covered, component)
		var value string
		switch component {
		case "@method":
			value = c.Method
		case "@authority":
			value = strings.ToLower(target.Host)
		case "@path":
			value = target.EscapedPath()
		case "@query":
			value = "?" + target.RawQuery
		default:
			if strings.HasPrefix(component, "@") || len(c.Headers.Values(component)) == 0 {
				valid = false
			}
			value = canonicalField(c.Headers, component)
		}
		lines = append(lines, fmt.Sprintf("%q: %s", component, value))
	}
	required := []string{"@method", "@authority", "@path", "signature-key"}
	if len(c.Body) > 0 {
		required = append(required, "content-digest", "content-type")
	}
	covered := true
	for _, component := range required {
		covered = covered && slices.Contains(o.Covered, component)
	}
	if len(c.Body) > 0 {
		sum := sha256.Sum256(c.Body)
		covered = covered && contentDigestMatches(c.Headers.Values("Content-Digest"), sum[:]) && c.Headers.Get("Content-Type") != ""
	}
	o.Properties["coverage"] = covered
	params, err := httpsfv.Marshal(input)
	if err != nil || !valid {
		o.Error = "Signature-Input names a component this oracle cannot rebuild"
		return o
	}
	lines = append(lines, `"@signature-params": `+params)
	o.Base = strings.Join(lines, "\n")
	signatures, err := httpsfv.UnmarshalDictionary(c.Headers.Values("Signature"))
	if err != nil {
		o.Error = err.Error()
		return o
	}
	member, _ = signatures.Get(label)
	if signature, ok := member.(httpsfv.Item); ok {
		if raw, ok := signature.Value.([]byte); ok {
			// self-jwt: the key that signs the event token signs the request.
			// A deployed Resource's is the published key the token's kid names.
			var key map[string]any
			if e.Resource.Published != nil {
				kid, _ := head["kid"].(string)
				key = resourceKeys[kid]
			} else {
				key = publicJWK(e.Resource.Seed)
			}
			o.Properties["proof"] = SigvecVerifyJWK(key, []byte(o.Base), raw)
		}
	}
	return o
}

// contentDigestMatches requires a sha-256 member equal to the body digest.
func contentDigestMatches(values []string, sum []byte) bool {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return false
	}
	member, ok := dictionary.Get("sha-256")
	item, isItem := member.(httpsfv.Item)
	digest, isBytes := item.Value.([]byte)
	return ok && isItem && isBytes && bytes.Equal(digest, sum)
}

func runEventsDelivery(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report) Report {
	e, _ := eventsFixture(s.Fixture)
	transport, inbox, stop, inboxErr := startEventsInbox(s.Fixture, e)
	if stop != nil {
		defer stop()
	}
	return runEventsRole(ctx, s, targets, o, ap, report, EventsDeliveryRole,
		func(e EventsFixture) string { return e.Resource.Issuer + e.SubscriptionPath },
		func(f Fixture, e EventsFixture, _ map[string]string) eventsLauncher {
			return eventsLauncher{Resource: &e.Resource, SubscriptionPath: e.SubscriptionPath, TicketPath: e.TicketPath, AgentProviders: []AgentProviderTrust{{Issuer: f.Issuer, Transport: transport}}}
		},
		eventsDeliveryCase(inbox, inboxErr))
}

// eventsDeliveryCase registers a subscription at the Resource, has its host
// fire events, and reads each delivery the inbox captured.
func eventsDeliveryCase(inbox *eventsInbox, inboxErr error) eventsCase {
	return func(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
		stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
		if inboxErr != nil {
			return stages, exchanges, own, inboxErr
		}
		var in eventsDeliveryRoleInput
		DecodeInput(s, &in)
		inbox.reset(in.MaxUses)
		eid := "evt-" + s.ID
		token, err := eventsSubscribeTokenWithUses(f, e, eid, s.ID, in.MaxUses)
		if err != nil {
			return stages, exchanges, own, err
		}
		registration, err := signEventsRequest(f, "registration", f.AgentSeed, http.MethodPost, e.Resource.Issuer+e.SubscriptionPath, `sig=jwt;jwt="`+token+`"`, eventsRegistration, eventsCovered(true))
		if err != nil {
			return stages, exchanges, own, err
		}
		if err := eventsExchange(ctx, registration, ready, o, stages, &exchanges); err != nil {
			return stages, exchanges, own, err
		}
		observations := []eventsDeliveryObservation{}
		for i, body := range in.Fires {
			control, err := controlRequest(fmt.Sprintf("fire-%d", i+1), eventsControlURL(ctx, e.Resource.Issuer, "/__fixture/fire"), map[string]any{"agent_provider": f.Issuer, "eid": eid, "body": body})
			if err != nil {
				return stages, exchanges, own, err
			}
			if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
				return stages, exchanges, own, err
			}
			captured := inbox.deliveries()
			if len(captured) != i+1 {
				return stages, exchanges, own, fmt.Errorf("fire %d: the inbox captured %d deliveries", i+1, len(captured))
			}
			if (len(captured[i].Body) > 0) != body {
				return stages, exchanges, own, fmt.Errorf("fire %d: delivery body presence differs from the requested event", i+1)
			}
			observation := observeEventsDelivery(f, e, captured[i], eid)
			observations = append(observations, observation)
			exchanges = append(exchanges, PersonExchange{Stage: fmt.Sprintf("delivery-%d", i+1), Method: captured[i].Method, URL: captured[i].URL, Headers: captured[i].Headers, Body: captured[i].Body, SignatureBase: observation.Base, Error: observation.Error})
		}
		for _, a := range s.Assertions {
			if a.Kind != "events-delivery" {
				continue
			}
			var n int
			fmt.Sscanf(a.Stage, "delivery-%d", &n)
			observation := observations[n-1]
			result := CompareResult(a, observation.Properties[a.Member], observation.Error)
			result.Actual = observation
			own[a.ID] = result
		}
		return stages, exchanges, own, nil
	}
}

func eventsSubscribeTokenWithUses(f Fixture, e EventsFixture, eid, jti string, maxUses int64) (string, error) {
	claims := map[string]any{"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "aud": e.Resource.Issuer, "cnf": map[string]any{"jwk": publicJWK(f.AgentSeed)}, "eid": eid, "jti": jti, "iat": f.Now - 10, "exp": f.Now + 300}
	if maxUses > 0 {
		claims["max_uses"] = maxUses
	}
	return mintJWT(f.APSeed, f.Kid, "aa-subscribe+jwt", claims)
}
