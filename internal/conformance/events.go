package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Events roles grade draft-hardt-aauth-events at the pinned commit: the
// Resource registering subscribe tokens, the Agent Provider's event endpoint,
// and the Agent's event-token verification.
const (
	EventsSubscriptionRole = "events.subscription"
	EventsProviderRole     = "events.agent-provider"
	EventsAgentRole        = "events.agent"
	EventsDeliveryRole     = "events.delivery"
)

// EventsIdentity is one fixture server identity with a public test seed.
type EventsIdentity struct {
	Issuer string `json:"issuer"`
	Seed   string `json:"seed_hex"`
	Kid    string `json:"kid"`
	// Published holds a deployed server's keys; remote mode sets it.
	Published keySet `json:"-"`
}

func (id EventsIdentity) keys() keySet {
	if id.Published != nil {
		return id.Published
	}
	return fixtureKeys(id.Seed, id.Kid)
}

// EventsFixture is fixture.json extensions.events.
type EventsFixture struct {
	Resource         EventsIdentity `json:"resource"`
	OtherResource    EventsIdentity `json:"other_resource"`
	SubscriptionPath string         `json:"subscription_path"`
	TicketPath       string         `json:"ticket_path"`
	EventEndpoint    string         `json:"event_endpoint"`
	OtherAgent       string         `json:"other_agent"`
	OtherKeySeed     string         `json:"other_key_seed_hex"`
	// ProviderKeys holds a deployed Agent Provider's keys; remote mode sets
	// it. Otherwise the fixture AP seed signs subscribe tokens.
	ProviderKeys keySet `json:"-"`
	// AnyTicketPath accepts a ticket URL anywhere on the Resource's origin:
	// a deployed Resource chooses its own ticket path.
	AnyTicketPath bool `json:"-"`
}

func (e EventsFixture) providerKeys(f Fixture) keySet {
	if e.ProviderKeys != nil {
		return e.ProviderKeys
	}
	return fixtureKeys(f.APSeed, f.Kid)
}

// eventsControlURL is where a case posts a host control: the launcher's
// logical origin, or in remote mode the deployment's control.
func eventsControlURL(ctx context.Context, origin, path string) string {
	if remote := remoteFrom(ctx); remote != nil {
		return remote.ControlURL(path)
	}
	return origin + path
}

type eventsSubscriptionInput struct {
	Mutation string `json:"mutation"`
	Ticket   string `json:"ticket,omitempty"`
}
type eventsDeliveryInput struct {
	Mutation string `json:"mutation"`
	Body     bool   `json:"body"`
}
type eventsProviderInput struct {
	MaxUses    int64                 `json:"max_uses"`
	Deliveries []eventsDeliveryInput `json:"deliveries"`
	Pending    bool                  `json:"pending,omitempty"`
}
type eventsDeliveryRoleInput struct {
	MaxUses int64  `json:"max_uses"`
	Fires   []bool `json:"fires"`
}
type eventsAgentInput struct {
	Mutation string `json:"mutation"`
	Body     bool   `json:"body"`
}

var (
	eventsSubscriptionMutations = []string{"none", "expired", "wrong-aud", "wrong-typ", "wrong-dwk", "empty-eid", "cnf-mismatch", "bad-signature"}
	eventsTicketModes           = []string{"", "bound", "other-key", "reused"}
	eventsDeliveryMutations     = []string{"none", "body-mismatch", "missing-digest", "digest-without-body", "cnf", "expired", "wrong-typ", "uncovered-content-digest", "uncovered-content-type", "proof-key", "unknown-kid", "unknown-eid", "other-resource", "wrong-aud", "bad-signature"}
	eventsAgentMutations        = []string{"none", "aud-case", "aud-other", "expired", "body-mismatch", "missing-digest", "digest-without-body", "wrong-typ", "wrong-dwk", "bad-signature"}
)

func init() {
	RegisterRole(EventsSubscriptionRole, ExtensionRole{Validate: validateEventsSubscription, Run: runEventsSubscription})
	RegisterRole(EventsProviderRole, ExtensionRole{Kinds: []string{"events-subscribe-token", "events-pending"}, Validate: validateEventsProvider, Run: runEventsProvider})
	RegisterRole(EventsAgentRole, ExtensionRole{Kinds: []string{"events-accepted"}, Validate: validateEventsAgent, Run: runEventsAgent})
	RegisterRole(EventsDeliveryRole, ExtensionRole{Kinds: []string{"events-delivery"}, Validate: validateEventsDelivery, Run: runEventsDelivery})
}

func eventsFixture(f Fixture) (EventsFixture, error) {
	var e EventsFixture
	if err := DecodeExtension(f, "events", &e); err != nil {
		return e, err
	}
	for _, id := range []EventsIdentity{e.Resource, e.OtherResource} {
		u, err := url.Parse(id.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.Port() != "" || id.Kid == "" || !validSeed(id.Seed) {
			return e, fmt.Errorf("invalid events fixture identity %q", id.Issuer)
		}
	}
	endpoint, err := url.Parse(e.EventEndpoint)
	if err != nil || endpoint.Scheme != "https" || "https://"+endpoint.Host != f.Issuer || endpoint.Path == "" || endpoint.RawQuery != "" {
		return e, fmt.Errorf("events event_endpoint must be an HTTPS path on the fixture AP")
	}
	if !strings.HasPrefix(e.SubscriptionPath, "/") || !strings.HasPrefix(e.TicketPath, "/") || !strings.HasSuffix(e.TicketPath, "/") || e.OtherAgent == "" || e.OtherAgent == f.Subject || !validSeed(e.OtherKeySeed) {
		return e, fmt.Errorf("invalid events fixture paths, other agent or other key")
	}
	if e.Resource.Issuer == e.OtherResource.Issuer || e.Resource.Seed == e.OtherResource.Seed {
		return e, fmt.Errorf("events fixture resources must differ")
	}
	return e, nil
}

// eventsStages checks that every assertion names a stage the role observes
// and that each kind is graded only where the runner has its observation.
func eventsStages(s Scenario, stages []string, own map[string]string) error {
	for _, a := range s.Assertions {
		if !slices.Contains(stages, a.Stage) {
			return fmt.Errorf("%s/%s: stage %q is not observed in this scenario", s.ID, a.ID, a.Stage)
		}
		if stage, ok := own[a.Kind]; ok {
			var b any
			json.Unmarshal(a.Equals, &b)
			if _, isBool := b.(bool); !isBool || a.Stage != stage {
				return fmt.Errorf("%s/%s: %s needs a boolean at stage %s", s.ID, a.ID, a.Kind, stage)
			}
		}
	}
	return nil
}

func validateEventsSubscription(f Fixture, s Scenario) error {
	if _, err := eventsFixture(f); err != nil {
		return err
	}
	var in eventsSubscriptionInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains(eventsSubscriptionMutations, in.Mutation) || !slices.Contains(eventsTicketModes, in.Ticket) {
		return fmt.Errorf("%s: unsupported subscription mutation or ticket mode", s.ID)
	}
	if in.Ticket != "" && in.Mutation != "none" {
		return fmt.Errorf("%s: ticket scenarios use valid subscribe tokens", s.ID)
	}
	stages := []string{"registration"}
	if in.Ticket != "" {
		stages = append(stages, "ticket")
	}
	if in.Ticket == "reused" {
		stages = append(stages, "first")
	}
	return eventsStages(s, stages, nil)
}

func validateEventsProvider(f Fixture, s Scenario) error {
	if _, err := eventsFixture(f); err != nil {
		return err
	}
	var in eventsProviderInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if in.MaxUses < 0 || in.MaxUses > 8 || len(in.Deliveries) > 8 {
		return fmt.Errorf("%s: max_uses and deliveries are limited to 8", s.ID)
	}
	stages := []string{"metadata", "subscribe"}
	for i, d := range in.Deliveries {
		if !slices.Contains(eventsDeliveryMutations, d.Mutation) {
			return fmt.Errorf("%s: unsupported delivery mutation %q", s.ID, d.Mutation)
		}
		if d.Mutation == "digest-without-body" && d.Body || slices.Contains([]string{"body-mismatch", "missing-digest", "uncovered-content-digest", "uncovered-content-type"}, d.Mutation) && !d.Body {
			return fmt.Errorf("%s: delivery %d mutation %s contradicts body", s.ID, i+1, d.Mutation)
		}
		stages = append(stages, fmt.Sprintf("delivery-%d", i+1))
	}
	if in.Pending {
		stages = append(stages, "pending")
	}
	return eventsStages(s, stages, map[string]string{"events-subscribe-token": "subscribe", "events-pending": "pending"})
}

func validateEventsAgent(f Fixture, s Scenario) error {
	if _, err := eventsFixture(f); err != nil {
		return err
	}
	var in eventsAgentInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if !slices.Contains(eventsAgentMutations, in.Mutation) {
		return fmt.Errorf("%s: unsupported agent mutation", s.ID)
	}
	if in.Mutation == "digest-without-body" && in.Body || slices.Contains([]string{"body-mismatch", "missing-digest"}, in.Mutation) && !in.Body {
		return fmt.Errorf("%s: mutation %s contradicts body", s.ID, in.Mutation)
	}
	for _, a := range s.Assertions {
		if a.Kind != "events-accepted" {
			return fmt.Errorf("%s/%s: the Agent role grades only events-accepted", s.ID, a.ID)
		}
	}
	return eventsStages(s, []string{"event"}, map[string]string{"events-accepted": "event"})
}

func validateEventsDelivery(f Fixture, s Scenario) error {
	if _, err := eventsFixture(f); err != nil {
		return err
	}
	var in eventsDeliveryRoleInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if in.MaxUses < 0 || in.MaxUses > 8 || len(in.Fires) == 0 || len(in.Fires) > 8 {
		return fmt.Errorf("%s: one to eight fires and max_uses up to 8", s.ID)
	}
	stages := []string{"registration"}
	for i := range in.Fires {
		stages = append(stages, fmt.Sprintf("fire-%d", i+1), fmt.Sprintf("delivery-%d", i+1))
	}
	for _, a := range s.Assertions {
		if a.Kind == "events-delivery" && !slices.Contains(eventsDeliveryProperties, a.Member) {
			return fmt.Errorf("%s/%s: events-delivery member must be one of %v", s.ID, a.ID, eventsDeliveryProperties)
		}
		var b any
		json.Unmarshal(a.Equals, &b)
		if _, isBool := b.(bool); a.Kind == "events-delivery" && !isBool {
			return fmt.Errorf("%s/%s: events-delivery needs a boolean", s.ID, a.ID)
		}
		if a.Kind == "events-delivery" && !strings.HasPrefix(a.Stage, "delivery-") {
			return fmt.Errorf("%s/%s: events-delivery grades a delivery stage", s.ID, a.ID)
		}
		if a.Kind != "events-delivery" && strings.HasPrefix(a.Stage, "delivery-") {
			return fmt.Errorf("%s/%s: a captured delivery is graded only by events-delivery", s.ID, a.ID)
		}
	}
	return eventsStages(s, stages, map[string]string{})
}

// eventsLauncher is the bootstrap extension every Events launcher reads.
type eventsLauncher struct {
	Resource             *EventsIdentity      `json:"resource,omitempty"`
	SubscriptionPath     string               `json:"subscription_path,omitempty"`
	TicketPath           string               `json:"ticket_path,omitempty"`
	EventEndpoint        string               `json:"event_endpoint,omitempty"`
	APSeed               string               `json:"ap_seed_hex,omitempty"`
	APKid                string               `json:"ap_kid,omitempty"`
	TrustedResources     []AgentProviderTrust `json:"trusted_resources,omitempty"`
	PersonServers        []AgentProviderTrust `json:"trusted_person_servers,omitempty"`
	SubscriptionResource string               `json:"subscription_resource,omitempty"`
	AgentProviders       []AgentProviderTrust `json:"agent_providers,omitempty"`
	Agent                string               `json:"agent"`
	AgentToken           string               `json:"agent_token,omitempty"`
}

// eventsCase runs one scenario against one freshly started launcher.
type eventsCase func(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error)

func runEventsRole(ctx context.Context, s Suite, targets Targets, o Options, ap string, report Report, role string, resourcePath func(EventsFixture) string, launcher func(Fixture, EventsFixture, map[string]string) eventsLauncher, run eventsCase) Report {
	e, err := eventsFixture(s.Fixture)
	documents, stop, docsErr := startEventsDocuments(s.Fixture, e)
	if docsErr != nil && err == nil {
		err = docsErr
	}
	if stop != nil {
		defer stop()
	}
	for _, target := range targets.Implementations {
		result := Run{Target: target}
		for _, scenario := range s.Scenarios {
			c := Case{ID: scenario.ID}
			var stages map[string]*Response
			var own map[string]Result
			execution := ""
			switch {
			case target.Unavailable != "":
			case err != nil:
				execution = err.Error()
			default:
				config := Bootstrap{Version: 1, Role: role, Now: s.Fixture.Now, Issuer: s.Fixture.Issuer, Resource: resourcePath(e), APTransport: ap, AgentSeed: s.Fixture.AgentSeed, Subject: s.Fixture.Subject}
				extension := launcher(s.Fixture, e, documents)
				extension.Agent = s.Fixture.Subject
				config.Extension, _ = json.Marshal(extension)
				ready, stopAdapter, startError := startAdapter(ctx, target, config, o)
				if startError != nil {
					execution = startError.Error()
					break
				}
				var exchanges []PersonExchange
				var caseError error
				stages, exchanges, own, caseError = runEventsCaseSafely(ctx, s.Fixture, e, scenario, ready, o, run)
				stopAdapter()
				c.Exchanges = exchanges
				if caseError != nil {
					execution = caseError.Error()
				}
			}
			c.Error = execution
			for _, a := range scenario.Assertions {
				if target.Unavailable != "" {
					c.Results = append(c.Results, Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed", Detail: target.Unavailable})
					continue
				}
				c.Results = append(c.Results, Grade(a, target.Claims, execution, stages[a.Stage], func(a Assertion) Result {
					if r := own[a.ID]; r.State != "" {
						return r
					}
					return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "no observation for this assertion"}
				}))
			}
			result.Cases = append(result.Cases, c)
		}
		report.Runs = append(report.Runs, result)
	}
	return report
}

func runEventsCaseSafely(ctx context.Context, f Fixture, e EventsFixture, s Scenario, ready Ready, o Options, run eventsCase) (stages map[string]*Response, exchanges []PersonExchange, own map[string]Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("events case panicked: %v", recovered)
		}
	}()
	return run(ctx, f, e, s, ready, o)
}

func eventsExchange(ctx context.Context, request *requestRecord, ready Ready, o Options, stages map[string]*Response, exchanges *[]PersonExchange) error {
	response, err := Exchange(ctx, request.request, ready.URL, o.Timeout)
	exchange := PersonExchange{Stage: request.stage, Method: request.request.Method, URL: request.request.URL.String(), Headers: request.request.Header.Clone(), Body: request.body, SignatureBase: request.base}
	if err != nil {
		exchange.Error = err.Error()
		*exchanges = append(*exchanges, exchange)
		return fmt.Errorf("%s: %w", request.stage, err)
	}
	exchange.Response = &response
	*exchanges = append(*exchanges, exchange)
	stages[request.stage] = &response
	return nil
}
