package main

// Events roles: the native Resource registration surface, the native Agent
// Provider inbox and the native Agent event check. This file supplies host
// trust snapshots, fixed clocks and fixture controls; every subscribe-token,
// event-token and proof decision belongs to aauth-go, and so do the Resource
// and Agent Provider stores (testutil.NewProtectedEventStore and
// testutil.NewEventInboxStore), which consume tickets, compare deliveries with
// the subscription, count uses and retain the delivered bytes.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() {
	extensionLaunchers["events.subscription"] = runEventsSubscription
	extensionLaunchers["events.agent-provider"] = runEventsProvider
	extensionLaunchers["events.agent"] = runEventsAgent
	extensionLaunchers["events.delivery"] = runEventsSubscription
}

type eventsIdentity struct {
	Issuer string `json:"issuer"`
	Seed   string `json:"seed_hex"`
	Kid    string `json:"kid"`
}

type eventsExtension struct {
	Resource             *eventsIdentity      `json:"resource"`
	SubscriptionPath     string               `json:"subscription_path"`
	TicketPath           string               `json:"ticket_path"`
	EventEndpoint        string               `json:"event_endpoint"`
	APSeed               string               `json:"ap_seed_hex"`
	APKid                string               `json:"ap_kid"`
	TrustedResources     []agentProviderTrust `json:"trusted_resources"`
	PersonServers        []agentProviderTrust `json:"trusted_person_servers"`
	SubscriptionResource string               `json:"subscription_resource"`
	AgentProviders       []agentProviderTrust `json:"agent_providers"`
	Agent                string               `json:"agent"`
	AgentToken           string               `json:"agent_token"`
}

func eventsConfig(config bootstrap) (eventsExtension, aauth.Clock, error) {
	var extension eventsExtension
	if err := json.Unmarshal(config.Extension, &extension); err != nil {
		return extension, nil, fmt.Errorf("events extension: %w", err)
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	return extension, clock, nil
}

func eventsSigningKey(seedHex, kid string) (jose.SigningKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return jose.SigningKey{}, fmt.Errorf("signing seed must be 32-byte hex")
	}
	return jose.NewEd25519SigningKey(kid, ed25519.NewKeyFromSeed(seed))
}

// eventsTrust admits fixture issuers' published keys under one discovery
// document name. It is host trust configuration, fetched from runner-owned
// loopback documents, and never a credential decision.
func eventsTrust(keys signaturekey.StaticKeyResolver, trusts []agentProviderTrust, document string) error {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("unexpected redirect") }}
	fetch := func(base, path string, v any) error {
		response, err := client.Get(base + path)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("fixture document HTTP %d", response.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(b) > 65536 {
			return fmt.Errorf("fixture document unreadable")
		}
		return json.Unmarshal(b, v)
	}
	for _, trust := range trusts {
		var metadata struct {
			Issuer string `json:"issuer"`
			JWKS   string `json:"jwks_uri"`
		}
		if err := fetch(trust.Transport, "/.well-known/"+document, &metadata); err != nil {
			return err
		}
		if metadata.Issuer != trust.Issuer || metadata.JWKS != trust.Issuer+"/.well-known/jwks.json" {
			return fmt.Errorf("fixture metadata for %s differs", trust.Issuer)
		}
		var jwks struct {
			Keys []jose.JWK `json:"keys"`
		}
		if err := fetch(trust.Transport, "/.well-known/jwks.json", &jwks); err != nil {
			return err
		}
		for _, key := range jwks.Keys {
			keys[signaturekey.StaticKeyReference{Issuer: trust.Issuer, DiscoveryDocument: document, KeyID: key.Kid}] = key
		}
	}
	return nil
}

func eventsServe(path string, handler http.Handler) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme, r.URL.Host = "https", r.Host
		handler.ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path}); err != nil {
		return err
	}
	return (&http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

func eventsControl(w http.ResponseWriter, r *http.Request, job any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(job); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func eventsReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func eventsSequence(prefix string) func() string {
	var next atomic.Uint64
	return func() string { return prefix + strconv.FormatUint(next.Add(1), 10) }
}

// runEventsSubscription serves the native public and protected registration
// handlers. The subscribe-token, ticket-binding and proof checks are native,
// and so is the store that consumes a ticket on its one registration.
func runEventsSubscription(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	extension, clock, err := eventsConfig(config)
	if err != nil {
		return err
	}
	if extension.Resource == nil {
		return errors.New("events subscription role needs the Resource identity")
	}
	if err := eventsTrust(keys, extension.PersonServers, aauth.PersonDiscoveryDocument); err != nil {
		return err
	}
	key, err := eventsSigningKey(extension.Resource.Seed, extension.Resource.Kid)
	if err != nil {
		return err
	}
	issuer := extension.Resource.Issuer
	// Delivery reaches the fixture AP over loopback: the client changes only the
	// physical destination of an admitted logical HTTPS URL, after signing.
	physical := map[string]*url.URL{}
	for _, provider := range extension.AgentProviders {
		logical, lerr := url.Parse(provider.Issuer)
		transport, terr := url.Parse(provider.Transport)
		if lerr != nil || terr != nil {
			return fmt.Errorf("invalid fixture Agent Provider %q", provider.Issuer)
		}
		physical[logical.Host] = transport
	}
	admit := func(_ context.Context, endpoint string) error {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || physical[u.Host] == nil {
			return errors.New("egress outside the fixture Agent Providers")
		}
		return nil
	}
	loopback := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		target := physical[request.URL.Host]
		if target == nil {
			return nil, errors.New("no fixture transport for " + request.URL.Host)
		}
		return loopback.RoundTrip(mapPhysicalRequest(request, target))
	})}
	resolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{Client: client, Admit: admit})
	if err != nil {
		return err
	}
	allow := func(context.Context, resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
		return resource.PublicSubscriptionDecision{}, nil
	}
	service, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer: issuer, SigningKey: key, KeyResolver: keys, Clock: clock,
		SubscriptionEndpoint: issuer + extension.SubscriptionPath,
		Store:                testutil.NewProtectedEventStore(),
		RegisterPublic:       allow,
		Protected: &resource.ProtectedSubscriptionConfig{
			EndpointPrefix: issuer + extension.TicketPath, NewTicketID: eventsSequence("ticket-"),
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(context.Context, resource.ProtectedSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				return resource.PublicSubscriptionDecision{}, nil
			},
		},
		ResolveEventEndpoint: resolver,
		AdmitEventEndpoint:   admit,
		HTTPClient:           client,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(extension.SubscriptionPath, service.PublicSubscriptionHandler())
	mux.Handle(extension.TicketPath, service.ProtectedSubscriptionHandler())
	// Protected Subscriptions step 2: a Resource issues a ticket while serving a
	// request it verified with a person token. The control verifies the
	// fixture person token natively and passes its confirmation key.
	mux.HandleFunc("POST /__fixture/ticket", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			PersonToken string `json:"person_token"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		person, err := aauth.VerifyPersonToken(r.Context(), job.PersonToken, keys, clock)
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		issued, err := service.IssueProtectedSubscriptionTicket(r.Context(), resource.ProtectedSubscriptionTicketRequest{
			ConfirmationKey: person.Confirmation.JWK, Context: []byte("conformance fixture"), Lifetime: 2 * time.Minute,
		})
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]string{"url": issued.URL})
	})
	// Event Delivery: the host asks the native Resource to prepare and deliver
	// one event on a registered subscription and reports the AP's status.
	mux.HandleFunc("POST /__fixture/fire", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			AgentProvider string `json:"agent_provider"`
			EventID       string `json:"eid"`
			Body          bool   `json:"body"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		input := resource.EventInput{AgentProvider: job.AgentProvider, EventID: job.EventID, Lifetime: 5 * time.Minute}
		if job.Body {
			input.ContentType, input.Payload = "application/json", []byte(`{"event_type":"slot.available"}`)
		}
		prepared, err := service.PrepareEvent(r.Context(), input)
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		if _, err := service.DeliverEvent(r.Context(), prepared); err != nil {
			var failure *resource.EventDeliveryError
			if errors.As(err, &failure) {
				eventsReply(w, http.StatusOK, map[string]any{"status": failure.StatusCode, "error": err.Error()})
				return
			}
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]int{"status": http.StatusAccepted})
	})
	return eventsServe(extension.SubscriptionPath, mux)
}

// runEventsProvider serves the native Agent Provider: metadata, JWKS and the
// event endpoint, plus a control that calls native subscribe-token issuance.
func runEventsProvider(config bootstrap, _ signaturekey.StaticKeyResolver) error {
	extension, clock, err := eventsConfig(config)
	if err != nil {
		return err
	}
	resourceKeys := signaturekey.StaticKeyResolver{}
	if err := eventsTrust(resourceKeys, extension.TrustedResources, aauth.ResourceDiscoveryDocument); err != nil {
		return err
	}
	key, err := eventsSigningKey(extension.APSeed, extension.APKid)
	if err != nil {
		return err
	}
	agentKey, err := eventsSigningKey(config.AgentSeed, "fixture-agent")
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(extension.EventEndpoint)
	if err != nil {
		return err
	}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: config.Issuer, SigningKey: key, Clock: clock, NewID: eventsSequence("agent-token-"),
		Events: &agentprovider.EventsConfig{
			EventEndpoint: extension.EventEndpoint, NewEventID: eventsSequence("evt-"),
			KeyResolver: resourceKeys, Store: testutil.NewEventInboxStore(),
		},
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", server.Handler())
	mux.HandleFunc("POST /__fixture/subscribe", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			MaxUses int64 `json:"max_uses"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		issued, err := server.IssueSubscribeToken(r.Context(), agentprovider.SubscribeRequest{
			Agent: extension.Agent, Resource: extension.SubscriptionResource,
			ConfirmationKey: agentKey.PublicJWK(), Lifetime: 10 * time.Minute, MaxUses: job.MaxUses,
		})
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]string{"token": issued.Compact})
	})
	// The AP-to-Agent read path the host transport uses (native PendingEvents).
	mux.HandleFunc("POST /__fixture/pending", func(w http.ResponseWriter, r *http.Request) {
		pending, err := server.PendingEvents(r.Context(), extension.Agent)
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		list := []map[string]string{}
		for _, delivery := range pending {
			list = append(list, map[string]string{"event_token": delivery.Token, "body": string(delivery.Payload)})
		}
		eventsReply(w, http.StatusOK, map[string]any{"events": list})
	})
	return eventsServe(endpoint.EscapedPath(), mux)
}

// runEventsAgent hands one AP-delivered event token and body to the native
// Agent and reports whether it accepted the event.
func runEventsAgent(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	extension, clock, err := eventsConfig(config)
	if err != nil {
		return err
	}
	if err := eventsTrust(keys, extension.TrustedResources, aauth.ResourceDiscoveryDocument); err != nil {
		return err
	}
	key, err := eventsSigningKey(config.AgentSeed, "fixture-agent")
	if err != nil {
		return err
	}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: extension.Agent, SigningKey: key, AgentToken: extension.AgentToken, KeyResolver: keys,
		HTTPClient: &http.Client{Timeout: 5 * time.Second}, Clock: clock,
		Events: &agent.EventsConfig{Store: eventsAgentStore{}},
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__fixture/event", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			EventToken  string `json:"event_token"`
			Body        string `json:"body"`
			ContentType string `json:"content_type"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		_, err := client.AcceptEvent(r.Context(), agent.EventDeliveryInput{EventToken: job.EventToken, Payload: []byte(job.Body), ContentType: job.ContentType})
		if err != nil {
			eventsReply(w, http.StatusOK, map[string]any{"accepted": false, "error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]any{"accepted": true})
	})
	return eventsServe("/__fixture/event", mux)
}

// eventsAgentStore returns a context for every eid. Context lookup (Agent
// Verification step 4) and deduplication (a SHOULD) are not graded here; the
// native AcceptEvent verifies the token, aud and body before calling it.
type eventsAgentStore struct{}

func (eventsAgentStore) BindContext(context.Context, agent.EventContext) error { return nil }
func (eventsAgentStore) AcceptEvent(_ context.Context, candidate agent.AcceptedEvent) (agent.EventAcceptance, error) {
	return agent.EventAcceptance{Context: agent.EventContext{EventID: candidate.EventID, Resource: candidate.Resource}}, nil
}
