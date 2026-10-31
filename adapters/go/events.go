package main

// Events roles: the native Resource registration surface, the native Agent
// Provider inbox and the native Agent event check. This file supplies host
// trust snapshots, fixed clocks, in-memory stores and fixture controls; every
// subscribe-token, event-token and proof decision belongs to aauth-go.

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
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
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
// handlers. The subscribe-token, ticket-binding and proof checks are native;
// the in-memory store only retains records and marks a consumed ticket.
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
		Store:                newEventsResourceStore(),
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

// eventsResourceStore follows resource.ProtectedSubscriptionStore. It does not
// compare ticket thumbprints: the native handler compares them after Load, so
// a binding refusal is the library's. Marking a ticket used on commit is the
// store's contract duty, so single use is not graded for aauth-go.
type eventsResourceStore struct {
	mu      sync.Mutex
	records map[resource.EventSubscriptionRef]resource.EventSubscription
	tickets map[string]resource.ProtectedSubscriptionTicket
}

func newEventsResourceStore() *eventsResourceStore {
	return &eventsResourceStore{records: map[resource.EventSubscriptionRef]resource.EventSubscription{}, tickets: map[string]resource.ProtectedSubscriptionTicket{}}
}

func (store *eventsResourceStore) Commit(_ context.Context, record resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.commit(record)
}

func (store *eventsResourceStore) commit(record resource.EventSubscription) (resource.EventSubscription, error) {
	ref := resource.EventSubscriptionRef{AgentProvider: record.AgentProvider, EventID: record.EventID}
	if retained, ok := store.records[ref]; ok {
		if retained.RegistrationSHA256 == record.RegistrationSHA256 {
			return retained, nil
		}
		return resource.EventSubscription{}, resource.ErrEventSubscriptionConflict
	}
	record.Parameters = append([]byte(nil), record.Parameters...)
	store.records[ref] = record
	return record, nil
}

func (store *eventsResourceStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[ref]
	if !ok {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	return record, nil
}

func (store *eventsResourceStore) CreateProtectedSubscriptionTicket(_ context.Context, ticket resource.ProtectedSubscriptionTicket) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.tickets[ticket.ID]; ok {
		return resource.ErrProtectedSubscriptionConflict
	}
	store.tickets[ticket.ID] = ticket
	return nil
}

func (store *eventsResourceStore) LoadProtectedSubscriptionTicket(_ context.Context, id, _ string, at time.Time) (resource.ProtectedSubscriptionTicket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[id]
	if !ok {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionNotFound
	}
	if ticket.UsedAt.IsZero() && !at.Before(ticket.ExpiresAt) {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionExpired
	}
	return ticket, nil
}

func (store *eventsResourceStore) CommitProtectedSubscription(_ context.Context, ticket resource.ProtectedSubscriptionTicket, record resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.tickets[ticket.ID]
	if !ok || !retained.UsedAt.IsZero() {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	committed, err := store.commit(record)
	if err != nil {
		return committed, err
	}
	retained.UsedAt, retained.RegistrationSHA256 = record.RegisteredAt, record.RegistrationSHA256
	store.tickets[ticket.ID] = retained
	return committed, nil
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
			KeyResolver: resourceKeys, Store: newEventsInboxStore(),
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
	return eventsServe(endpoint.EscapedPath(), mux)
}

// eventsInboxStore follows agentprovider.EventInboxStore, which assigns the
// subscription lookup's Resource and Agent comparisons and the use count to
// the host store. Those duties are therefore not graded for aauth-go.
type eventsInboxStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	accepted      map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	uses          map[string]int64
}

func newEventsInboxStore() *eventsInboxStore {
	return &eventsInboxStore{subscriptions: map[string]agentprovider.EventSubscription{}, accepted: map[events.DeliveryFingerprint]agentprovider.EventAcceptance{}, uses: map[string]int64{}}
}

func (store *eventsInboxStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.subscriptions[record.EventID]; ok && retained.TokenSHA256 != record.TokenSHA256 {
		return agentprovider.ErrEventDeliveryConflict
	}
	store.subscriptions[record.EventID] = record
	return nil
}

func (store *eventsInboxStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	subscription, ok := store.subscriptions[delivery.EventID]
	switch {
	case !ok:
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventSubscriptionNotFound
	case subscription.Resource != delivery.Resource:
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventResourceMismatch
	case subscription.Agent != delivery.Agent:
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventAgentMismatch
	}
	if accepted, ok := store.accepted[delivery.Fingerprint]; ok {
		accepted.Duplicate = true
		return accepted, nil
	}
	if subscription.MaxUses > 0 && store.uses[delivery.EventID] >= subscription.MaxUses {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventUsesExceeded
	}
	store.uses[delivery.EventID]++
	accepted := agentprovider.EventAcceptance{MaximumUses: subscription.MaxUses}
	if subscription.MaxUses > 0 {
		accepted.RemainingUses = subscription.MaxUses - store.uses[delivery.EventID]
	}
	store.accepted[delivery.Fingerprint] = accepted
	return accepted, nil
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
