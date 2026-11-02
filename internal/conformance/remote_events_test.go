package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Catches Events scenarios that need a host control being run, or failed,
// when the deployment names no control, and scenarios that need none being
// skipped.
func TestRemoteEventsGapsNameTheMissingControl(t *testing.T) {
	suite := loadSuite(t)
	counts := map[string][2]int{}
	for _, role := range []string{EventsSubscriptionRole, EventsProviderRole, EventsDeliveryRole, EventsAgentRole} {
		selected, _ := suite.ForRole(role)
		for _, s := range selected.Scenarios {
			gap := remoteDrivers[role].gap(s, RemoteRole{})
			if gap != "" && !strings.Contains(gap, "/__fixture/") {
				t.Fatalf("%s: reason %q names no control", s.ID, gap)
			}
			if remoteDrivers[role].gap(s, RemoteRole{Control: "https://control.example/x"}) != "" {
				t.Fatalf("%s: not run with a control", s.ID)
			}
			n := counts[role]
			if gap == "" {
				n[0]++
			} else {
				n[1]++
			}
			counts[role] = n
		}
	}
	want := map[string][2]int{EventsSubscriptionRole: {8, 3}, EventsProviderRole: {0, 17}, EventsDeliveryRole: {0, 1}, EventsAgentRole: {0, 11}}
	for role, n := range want {
		if counts[role] != n {
			t.Errorf("%s: run/gap %v, want %v", role, counts[role], n)
		}
	}
}

// Catches a rebased Events fixture that keeps the fixture Resource or event
// endpoint for the deployed server, or that grades the AP's event_endpoint
// against the launcher's fixed path.
func TestRemoteEventsFixtureRebasesDeployedServers(t *testing.T) {
	suite := loadSuite(t)
	var e EventsFixture
	if err := DecodeExtension(suite.Fixture, "events", &e); err != nil {
		t.Fatal(err)
	}
	r := &RemoteRun{Role: RemoteRole{Resource: "https://events.example/v1/subscribe"}, Servers: map[string]RemoteServer{
		partyResource: {Keys: keySet{"k": nil}},
		partyProvider: {Metadata: map[string]any{"event_endpoint": "https://ap.example/inbox"}, Keys: keySet{"a": nil}},
	}}
	sub := remoteEventsFixture(e, EventsDeliveryRole, r)
	if sub.Resource.Issuer != "https://events.example" || sub.SubscriptionPath != "/v1/subscribe" || !sub.AnyTicketPath || sub.Resource.keys()["k"] != nil || len(sub.Resource.keys()) != 1 {
		t.Fatalf("%+v", sub)
	}
	if !ticketUnder(sub, "https://events.example/t/abc") || ticketUnder(sub, "https://other.example/t/abc") || ticketUnder(sub, "https://events.example/t?x") {
		t.Fatal("ticket origin check")
	}
	if ticketUnder(e, e.Resource.Issuer+e.TicketPath+"a/b") || !ticketUnder(e, e.Resource.Issuer+e.TicketPath+"a") {
		t.Fatal("launcher ticket path check changed")
	}
	ap := remoteEventsFixture(e, EventsProviderRole, r)
	if ap.EventEndpoint != "https://ap.example/inbox" || len(ap.providerKeys(suite.Fixture)) != 1 || e.ProviderKeys != nil {
		t.Fatalf("%+v", ap)
	}
	selected, _ := suite.ForRole(EventsProviderRole)
	rebased := rebaseProviderMetadata(selected.Scenarios[0], e, r)
	if string(rebased.Assertions[1].Equals) != `"https://ap.example/inbox"` {
		t.Fatalf("%s", rebased.Assertions[1].Equals)
	}
	r.Servers[partyProvider] = RemoteServer{Metadata: map[string]any{"event_endpoint": "http://ap.example/inbox"}}
	if string(rebaseProviderMetadata(selected.Scenarios[0], e, r).Assertions[1].Equals) != `"https://ap.conformance.test/events"` {
		t.Fatal("a non-HTTPS event_endpoint was accepted as expected")
	}
}

// Catches the Agent role posting to the launcher's path instead of the
// deployment's control, or minting event tokens for the fixture Agent
// instead of the deployed one.
func TestRemoteEventsAgentUsesControlAndDeployedAgent(t *testing.T) {
	suite := loadSuite(t)
	var mu sync.Mutex
	paths, audiences := []string{}, []any{}
	network := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			EventToken string `json:"event_token"`
		}
		json.NewDecoder(r.Body).Decode(&job)
		mu.Lock()
		paths = append(paths, r.Host+r.URL.Path)
		audiences = append(audiences, unverifiedClaims(job.EventToken)["aud"])
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"accepted": false})
	}), "control.example")
	agent := "aauth:agent@ap.example"
	d := Deployment{Version: 1, ID: "impl", Revision: "v1", Roles: map[string]RemoteRole{EventsAgentRole: {Agent: agent, Control: "https://control.example/hooks"}}}
	reports, err := RunRemote(WithNetwork(context.Background(), network), suite, d, RemoteOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 11 || paths[0] != "control.example/hooks/__fixture/event" {
		t.Fatalf("%v", paths)
	}
	if audiences[0] != agent {
		t.Fatalf("event token aud %v", audiences[0])
	}
	for _, c := range reports[0].Runs[0].Cases {
		if c.Error != "" {
			t.Fatalf("%s: %s", c.ID, c.Error)
		}
	}
}

// Catches a delivery observation that needs the Resource's private seed,
// which a deployed Resource never shares, instead of its published keys.
func TestRemoteEventsDeliveryVerifiesByPublishedKeys(t *testing.T) {
	suite := loadSuite(t)
	f := suite.Fixture
	e, err := eventsFixture(f)
	if err != nil {
		t.Fatal(err)
	}
	record, err := eventsDelivery(f, e, eventsDeliveryInput{Mutation: "none", Body: true}, "evt-1", "jti-1", "delivery-1")
	if err != nil {
		t.Fatal(err)
	}
	captured := Captured{Method: record.request.Method, URL: record.request.URL.String(), Headers: record.request.Header.Clone(), Body: record.body}
	deployed := e
	deployed.Resource = EventsIdentity{Issuer: e.Resource.Issuer, Published: fixtureKeys(e.Resource.Seed, e.Resource.Kid)}
	o := observeEventsDelivery(f, deployed, captured, "evt-1")
	if !o.Properties["proof"] || !o.Properties["self-jwt"] || o.Error != "" {
		t.Fatalf("%+v", o)
	}
	deployed.Resource.Published = fixtureKeys(e.OtherKeySeed, e.Resource.Kid)
	if o := observeEventsDelivery(f, deployed, captured, "evt-1"); o.Properties["proof"] || o.Properties["self-jwt"] {
		t.Fatalf("verified under another published key: %+v", o)
	}
}
