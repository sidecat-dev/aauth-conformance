package conformance

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Remote drivers for the Events roles. The suite plays the parties the
// launchers' harness plays: the Agent Provider and the Agent for a deployed
// Resource, the subscribed Resources for a deployed Agent Provider, and the
// Resource for a deployed Agent host. Their documents are on the suite's
// listener; a deployed Resource delivers events to the suite's Agent
// Provider there.

func init() {
	parties := func(f Fixture) []harnessParty {
		e, err := eventsFixture(f)
		if err != nil {
			return nil
		}
		ap := party(f.Issuer, "aauth-agent.json", f.APSeed, f.Kid)
		ap.metadata = map[string]any{"event_endpoint": e.EventEndpoint}
		return []harnessParty{ap,
			party(e.Resource.Issuer, "aauth-resource.json", e.Resource.Seed, e.Resource.Kid),
			party(e.OtherResource.Issuer, "aauth-resource.json", e.OtherResource.Seed, e.OtherResource.Kid)}
	}
	registerRemote(EventsSubscriptionRole, remoteDriver{
		requires: []string{partyResource},
		parties:  parties,
		gap: func(s Scenario, r RemoteRole) string {
			var in eventsSubscriptionInput
			DecodeInput(s, &in)
			if in.Ticket == "" {
				return ""
			}
			return controlGap(r, "/__fixture/ticket")
		},
		fixture: remoteEventsClock,
		run:     remoteEventsCase(EventsSubscriptionRole, eventsSubscriptionCase),
	})
	registerRemote(EventsProviderRole, remoteDriver{
		requires: []string{partyProvider, partyAgent},
		discover: map[string]remoteDocument{partyProvider: {"aauth-agent.json", true}},
		parties:  parties,
		gap: func(s Scenario, r RemoteRole) string {
			var in eventsProviderInput
			DecodeInput(s, &in)
			if in.Pending {
				return controlGap(r, "/__fixture/subscribe", "/__fixture/pending")
			}
			return controlGap(r, "/__fixture/subscribe")
		},
		fixture: func(base Fixture, s Scenario, r *RemoteRun) Fixture {
			f := remoteEventsClock(base, s, r)
			f.Issuer, f.Subject = r.Role.AgentProvider, r.Role.Agent
			return f
		},
		run: remoteEventsCase(EventsProviderRole, eventsProviderCase),
	})
	registerRemote(EventsDeliveryRole, remoteDriver{
		requires: []string{partyResource},
		discover: map[string]remoteDocument{partyResource: {"aauth-resource.json", true}},
		parties:  parties,
		gap: func(_ Scenario, r RemoteRole) string {
			return controlGap(r, "/__fixture/fire")
		},
		fixture: remoteEventsClock,
		run:     remoteEventsCase(EventsDeliveryRole, nil),
	})
	registerRemote(EventsAgentRole, remoteDriver{
		requires: []string{partyAgent},
		parties:  parties,
		gap: func(_ Scenario, r RemoteRole) string {
			return controlGap(r, "/__fixture/event")
		},
		fixture: func(base Fixture, s Scenario, r *RemoteRun) Fixture {
			f := remoteEventsClock(base, s, r)
			f.Subject = r.Role.Agent
			return f
		},
		run: remoteEventsCase(EventsAgentRole, eventsAgentCase),
	})
}

// remoteEventsClock gives a case the current clock and the run's skew.
func remoteEventsClock(base Fixture, _ Scenario, r *RemoteRun) Fixture {
	f := base
	f.Now, f.Skew = time.Now().Unix(), r.Skew
	return f
}

// remoteEventsFixture rebases the Events fixture onto the deployment: a
// deployed Resource replaces the fixture Resource's identity and paths, and
// a deployed Agent Provider its event endpoint and keys.
func remoteEventsFixture(e EventsFixture, role string, r *RemoteRun) EventsFixture {
	switch role {
	case EventsSubscriptionRole, EventsDeliveryRole:
		u, _ := url.Parse(r.Role.Resource)
		e.Resource = EventsIdentity{Issuer: resourceIdentifier(r.Role.Resource), Kid: e.Resource.Kid, Published: r.Servers[partyResource].Keys}
		if e.Resource.Published == nil {
			e.Resource.Published = keySet{}
		}
		e.SubscriptionPath, e.AnyTicketPath = u.EscapedPath(), true
	case EventsProviderRole:
		provider := r.Servers[partyProvider]
		e.ProviderKeys = provider.Keys
		// The AP names its own event endpoint; deliveries go there.
		if endpoint := provider.Endpoint("event_endpoint"); endpoint != "" {
			e.EventEndpoint = endpoint
		}
	}
	return e
}

// remoteEventsCase runs one Events case against the deployment and grades
// it as runEventsRole does. A nil run is the delivery role, whose case needs
// the suite's Agent Provider inbox installed on the harness.
func remoteEventsCase(role string, run eventsCase) func(context.Context, Fixture, Scenario, Target, Options) Case {
	return func(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
		remote := remoteFrom(ctx)
		// The suite validated the fixture at load; the rebased identities
		// no longer share the fixture's origins, so it is decoded as is.
		var e EventsFixture
		err := DecodeExtension(f, "events", &e)
		if err == nil {
			if role == EventsProviderRole {
				s = rebaseProviderMetadata(s, e, remote)
			}
			e = remoteEventsFixture(e, role, remote)
		}
		if run == nil && err == nil {
			inbox := &eventsInbox{}
			stop := remote.Harness.Handle(e.EventEndpoint, http.HandlerFunc(inbox.receive))
			defer stop()
			run = eventsDeliveryCase(inbox, nil)
		}
		c := Case{ID: s.ID}
		var stages map[string]*Response
		var own map[string]Result
		execution := ""
		if err != nil {
			execution = err.Error()
		} else {
			var exchanges []PersonExchange
			var caseError error
			stages, exchanges, own, caseError = runEventsCaseSafely(ctx, f, e, s, Ready{}, o, run)
			c.Exchanges = exchanges
			if caseError != nil {
				execution = caseError.Error()
			}
		}
		c.Error = execution
		for _, a := range s.Assertions {
			c.Results = append(c.Results, Grade(a, t.Claims, execution, stages[a.Stage], func(a Assertion) Result {
				if r := own[a.ID]; r.State != "" {
					return r
				}
				return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: "no observation for this assertion"}
			}))
		}
		return c
	}
}

// rebaseProviderMetadata grades a deployed AP's metadata against its own
// identity: its issuer, and the event_endpoint it publishes when that is an
// HTTPS URL with no query or fragment. The fixture's endpoint is a launcher
// configuration a deployment does not share, so the suite checks the
// published value's form instead of its exact path.
func rebaseProviderMetadata(s Scenario, fixture EventsFixture, r *RemoteRun) Scenario {
	replace := map[string]string{}
	if endpoint := r.Servers[partyProvider].Endpoint("event_endpoint"); endpointURL(endpoint) {
		replace[fixture.EventEndpoint] = endpoint
	}
	return rebaseExpected(s, replace)
}
