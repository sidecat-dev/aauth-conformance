package main

// AAuth Events roles: the subscription and delivering Resource, the Agent
// Provider's event endpoint and an Agent host, served from aauth-go's native
// handlers. Names keys: "events_resource" and "agent_provider"; the Agent is
// aauth:agent@ followed by the Agent Provider's host. Host controls are under
// Names["control"], one path prefix per suite role. The in-memory stores
// follow the library's store contracts, as the conformance launchers' do.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

func init() { extensions = append(extensions, eventsRoles) }

const (
	eventsSubscriptionPath = "/events/subscribe"
	eventsTicketPath       = "/events/tickets/"
)

func eventsRoles(e env) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{}
	if issuer := e.c.Names["events_resource"]; issuer != "" {
		handler, err := eventsResource(e, issuer)
		if err != nil {
			return nil, err
		}
		handlers[issuer] = handler
	}
	if issuer := e.c.Names["agent_provider"]; issuer != "" {
		handler, err := eventsProvider(e, issuer)
		if err != nil {
			return nil, err
		}
		handlers[issuer] = handler
	}
	return handlers, nil
}

// eventsResource serves native public and protected registration, its
// metadata and JWKS, and the ticket and fire controls.
func eventsResource(e env, issuer string) (http.Handler, error) {
	key := e.key("go-events-resource")
	// Event delivery reaches only the Agent Providers this deployment trusts.
	admit := func(_ context.Context, endpoint string) error {
		for _, provider := range e.c.AgentProviders {
			if strings.HasPrefix(endpoint, provider+"/") {
				return nil
			}
		}
		return errors.New("event endpoint outside the trusted Agent Providers")
	}
	resolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{Client: e.client, Admit: admit})
	if err != nil {
		return nil, err
	}
	allow := func(context.Context, resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
		return resource.PublicSubscriptionDecision{}, nil
	}
	service, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer: issuer, SigningKey: key, KeyResolver: e.keys, Clock: e.clock,
		SubscriptionEndpoint: issuer + eventsSubscriptionPath,
		Store:                newEventsResourceStore(),
		RegisterPublic:       allow,
		Protected: &resource.ProtectedSubscriptionConfig{
			EndpointPrefix: issuer + eventsTicketPath, NewTicketID: eventsSequence("ticket-"),
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(context.Context, resource.ProtectedSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				return resource.PublicSubscriptionDecision{}, nil
			},
		},
		ResolveEventEndpoint: resolver,
		AdmitEventEndpoint:   admit,
		HTTPClient:           e.client,
	})
	if err != nil {
		return nil, err
	}
	public := key.PublicJWK()
	public.Kid = key.ID()
	mux := http.NewServeMux()
	mux.Handle(eventsSubscriptionPath, service.PublicSubscriptionHandler())
	mux.Handle(eventsTicketPath, service.ProtectedSubscriptionHandler())
	mux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		eventsReply(w, http.StatusOK, map[string]string{"issuer": issuer, "jwks_uri": issuer + "/.well-known/jwks.json"})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		eventsReply(w, http.StatusOK, map[string]any{"keys": []jose.JWK{public}})
	})
	// Protected Subscriptions step 2: a Resource issues a ticket while serving
	// a request verified with a person token; the control verifies the token
	// natively and passes its confirmation key.
	e.controls.HandleFunc("POST /events.subscription/__fixture/ticket", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			PersonToken string `json:"person_token"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		person, err := aauth.VerifyPersonToken(r.Context(), job.PersonToken, e.keys, e.clock)
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
	// Event Delivery: the native Resource prepares and delivers one event on
	// a registered subscription; the control reports the AP's status.
	e.controls.HandleFunc("POST /events.delivery/__fixture/fire", func(w http.ResponseWriter, r *http.Request) {
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
	return mux, nil
}

// eventsProvider serves the native Agent Provider (metadata, JWKS, event
// endpoint), the subscribe and pending controls for its one Agent, and that
// Agent's event check.
func eventsProvider(e env, issuer string) (http.Handler, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	agentID := "aauth:agent@" + u.Hostname()
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: issuer, SigningKey: e.key("go-ap"), Clock: e.clock, NewID: e.newID,
		Events: &agentprovider.EventsConfig{
			EventEndpoint: issuer + "/events", NewEventID: eventsSequence("evt-"),
			KeyResolver: e.keys, Store: newEventsInboxStore(),
		},
	})
	if err != nil {
		return nil, err
	}
	ownAgent := func(w http.ResponseWriter, name string) bool {
		if name != agentID {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": "this Agent Provider serves only " + agentID})
			return false
		}
		return true
	}
	// Subscribe token acquisition is AP-internal (Events, Protocol Overview):
	// the control stands for the Agent's request, naming its key.
	e.controls.HandleFunc("POST /events.agent-provider/__fixture/subscribe", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			MaxUses  int64    `json:"max_uses"`
			Agent    string   `json:"agent"`
			AgentJWK jose.JWK `json:"agent_jwk"`
			Resource string   `json:"resource"`
		}
		if !eventsControl(w, r, &job) || !ownAgent(w, job.Agent) {
			return
		}
		issued, err := server.IssueSubscribeToken(r.Context(), agentprovider.SubscribeRequest{
			Agent: job.Agent, Resource: job.Resource, ConfirmationKey: job.AgentJWK,
			Lifetime: 10 * time.Minute, MaxUses: job.MaxUses,
		})
		if err != nil {
			eventsReply(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]string{"token": issued.Compact})
	})
	// The AP-to-Agent read path (native PendingEvents).
	e.controls.HandleFunc("POST /events.agent-provider/__fixture/pending", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			Agent string `json:"agent"`
		}
		if !eventsControl(w, r, &job) || !ownAgent(w, job.Agent) {
			return
		}
		pending, err := server.PendingEvents(r.Context(), job.Agent)
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
	// The Agent's native event check. Its client is built on first use, since
	// verifying its agent token discovers this AP's keys over HTTPS.
	var once sync.Once
	var client *agent.Client
	var clientErr error
	e.controls.HandleFunc("POST /events.agent/__fixture/event", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			key := e.key("go-agent")
			token, err := server.Issue(aauth.AgentTokenRequest{Agent: agentID, PublicKey: key.PublicJWK(), Lifetime: 24 * time.Hour})
			if err != nil {
				clientErr = err
				return
			}
			client, clientErr = agent.New(context.Background(), agent.Config{
				Identifier: agentID, SigningKey: key, AgentToken: token, KeyResolver: e.keys,
				HTTPClient: e.client, Clock: e.clock, Events: &agent.EventsConfig{Store: eventsAgentStore{}},
			})
		})
		if clientErr != nil {
			eventsReply(w, http.StatusInternalServerError, map[string]string{"error": clientErr.Error()})
			return
		}
		var job struct {
			EventToken  string `json:"event_token"`
			Body        string `json:"body"`
			ContentType string `json:"content_type"`
		}
		if !eventsControl(w, r, &job) {
			return
		}
		if _, err := client.AcceptEvent(r.Context(), agent.EventDeliveryInput{EventToken: job.EventToken, Payload: []byte(job.Body), ContentType: job.ContentType}); err != nil {
			eventsReply(w, http.StatusOK, map[string]any{"accepted": false, "error": err.Error()})
			return
		}
		eventsReply(w, http.StatusOK, map[string]any{"accepted": true})
	})
	return server.Handler(), nil
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
	return func() string {
		return fmt.Sprintf("%s%d-", prefix, time.Now().Unix()) + strconv.FormatUint(next.Add(1), 10)
	}
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

// eventsInboxStore follows agentprovider.EventInboxStore and
// EventInboxReader, which assign the subscription's Resource and Agent
// comparisons, the use count and the retained bytes to the host store. Those
// duties are therefore not graded for aauth-go.
type eventsInboxStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	accepted      map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	uses          map[string]int64
	pending       map[string][]agentprovider.EventDelivery
}

func newEventsInboxStore() *eventsInboxStore {
	return &eventsInboxStore{subscriptions: map[string]agentprovider.EventSubscription{}, accepted: map[events.DeliveryFingerprint]agentprovider.EventAcceptance{}, uses: map[string]int64{}, pending: map[string][]agentprovider.EventDelivery{}}
}

func (store *eventsInboxStore) PendingEvents(_ context.Context, agent string) ([]agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]agentprovider.EventDelivery(nil), store.pending[agent]...), nil
}

func (store *eventsInboxStore) AcknowledgeEvent(context.Context, string, events.DeliveryFingerprint) error {
	return nil
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
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	store.pending[delivery.Agent] = append(store.pending[delivery.Agent], delivery)
	return accepted, nil
}

// eventsAgentStore returns a context for every eid. Context lookup (Agent
// Verification step 4) and deduplication (a SHOULD) are not graded here; the
// native AcceptEvent verifies the token, aud and body before calling it.
type eventsAgentStore struct{}

func (eventsAgentStore) BindContext(context.Context, agent.EventContext) error { return nil }
func (eventsAgentStore) AcceptEvent(_ context.Context, candidate agent.AcceptedEvent) (agent.EventAcceptance, error) {
	return agent.EventAcceptance{Context: agent.EventContext{EventID: candidate.EventID, Resource: candidate.Resource}}, nil
}
