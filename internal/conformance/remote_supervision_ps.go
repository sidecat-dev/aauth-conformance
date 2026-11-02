package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Remote mode for supervision.person-server: the deployment names its
// Person Server, which routes the suite's Agent to the supervision server
// the suite plays at the fixture's supervisor name. The suite is also the
// Agent, the Agent Provider and the Resource. Endpoints come from the
// Person Server's aauth-person.json, and its tokens and its signed requests
// to the supervisor are verified under the keys its jwks_uri publishes.
//
// A deployed Person Server keeps state across scenarios. It connects to the
// supervisor once, so a case that sees no connect grades the first connect
// of the run. Events and reports are graded only when they carry no sdi or
// one of the case's own supervision requests, so a late report of another
// case's act is not counted. The host control is told the held act's
// pending URL, so it answers for that act and no older one.

func init() {
	registerRemote(SupervisionPersonServerRole, remoteDriver{
		requires: []string{partyPerson},
		discover: map[string]remoteDocument{partyPerson: {"aauth-person.json", true}},
		parties: func(f Fixture) []harnessParty {
			ss, err := supervisionFixture(f)
			if err != nil {
				return nil
			}
			// The supervisor's documents are served per case by the harness
			// supervisor; the foreign supervisor is a trusted server whose
			// signature the Person Server must still refuse.
			return []harnessParty{{issuer: ss.Issuer}, party(ss.Foreign.Issuer, "aauth-supervisor.json", ss.Foreign.Seed, ss.Foreign.Kid)}
		},
		gap: func(s Scenario, r RemoteRole) string {
			var input SupervisionPSInput
			if DecodeInput(s, &input) != nil {
				return ""
			}
			if slices.Contains([]string{"ask", "server-error", "defer"}, input.Decision) {
				return controlGap(r, supervisionControlPath)
			}
			return ""
		},
		run: runRemoteSupervisionPSCase,
	})
}

// remotePSSupervisor is the harness supervisor of one role run, and the
// first connect the deployed Person Server made of it.
type remotePSSupervisor struct {
	mu      sync.Mutex
	harness *harnessSupervisor
	connect *SSRequest
}

func (r *RemoteRun) psSupervisor(f Fixture, ss SupervisionFixture) *remotePSSupervisor {
	if r.supervisor == nil {
		r.supervisor = &remotePSSupervisor{harness: &harnessSupervisor{fixture: f, ss: ss, pending: map[string]string{}}}
	}
	return r.supervisor
}

// remotePSDeliveryGap says why an event or report is not graded without a
// host control: a deployed Person Server delivers them when its host asks.
var remotePSDeliveryGap = "needs the host control " + supervisionControlPath + " to deliver queued events and reports, and the deployment names no control"

// remotePSConnectGap says why a connect is not graded when the run saw none.
const remotePSConnectGap = "the Person Server made no connect request in this run; it was connected to the suite's supervisor before it, so restart it to grade its connect"

func runRemoteSupervisionPSCase(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
	remote := remoteFrom(ctx)
	ss, err := supervisionFixture(f)
	if err != nil {
		return failedCase(s, t, err)
	}
	var input SupervisionPSInput
	if err := DecodeInput(s, &input); err != nil {
		return failedCase(s, t, err)
	}
	run := remote.psSupervisor(f, ss)
	run.mu.Lock()
	defer run.mu.Unlock()
	harness := run.harness
	harness.reset(input)
	harness.rebase(f)
	remove := remote.Harness.Handle(ss.Issuer+"/", harness)
	defer remove()
	reach := supervisionPSReach{mission: remote.Servers[partyPerson].Endpoint("mission_endpoint")}
	if !endpointURL(reach.mission) {
		reach.mission = f.Person.Issuer + "/mission"
	}
	control := remote.Role.Control != ""
	if control {
		reach.control = func(ctx context.Context, body, pending string) (Response, error) {
			var object map[string]any
			if err := json.Unmarshal([]byte(body), &object); err != nil {
				return Response{}, err
			}
			if pending != "" {
				object["pending"] = pending
			}
			raw, _ := json.Marshal(object)
			return remotePSControl(ctx, remote, raw, o.Timeout)
		}
	}
	var observed []SSRequest
	reach.graded = func(all []SSRequest) []SSRequest {
		observed = all
		return run.graded(all)
	}
	c := runSupervisionPSCase(ctx, f, ss, s, input, t, reach, o, nil, harness)
	if evidence, ok := c.Evidence.(map[string]any); ok {
		evidence["supervisor_requests_observed"] = observed
	}
	connected := run.connect != nil
	for i, a := range s.Assertions {
		if a.Stage != "deliver" || c.Results[i].State == "not_claimed" {
			continue
		}
		selector, _, _ := strings.Cut(a.Member, "/")
		reason := ""
		switch {
		case !control && (strings.HasPrefix(selector, "event:") || strings.HasPrefix(selector, "report:")):
			reason = remotePSDeliveryGap
		case !connected && strings.HasPrefix(selector, "connect"):
			reason = remotePSConnectGap
		}
		if reason != "" {
			c.Results[i] = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: reason}
		}
	}
	return c
}

// graded chooses what a case is graded on from what the supervisor
// observed during it: every request, less events and reports that name
// another case's sdi, with the run's first connect when the case made none.
func (r *remotePSSupervisor) graded(observed []SSRequest) []SSRequest {
	sdis := map[string]bool{}
	for _, request := range observed {
		if request.Kind == "decision" || request.Kind == "proposal" || strings.HasPrefix(request.Kind, "mission:") {
			object, _ := jsonObject(request.Request.Body)
			if sdi, _ := object["sdi"].(string); sdi != "" {
				sdis[sdi] = true
			}
		}
	}
	graded := []SSRequest{}
	connected := false
	for _, request := range observed {
		if strings.HasPrefix(request.Kind, "event:") || strings.HasPrefix(request.Kind, "report:") {
			object, _ := jsonObject(request.Request.Body)
			if sdi, _ := object["sdi"].(string); sdi != "" && !sdis[sdi] {
				continue
			}
		}
		if request.Kind == "connect" {
			connected = true
			if r.connect == nil {
				first := request
				r.connect = &first
			}
		}
		graded = append(graded, request)
	}
	if !connected && r.connect != nil {
		graded = append([]SSRequest{*r.connect}, graded...)
	}
	return graded
}

// remotePSControl posts a host-control body to the deployment's control.
// Its answer is evidence of host input, never protocol output.
func remotePSControl(ctx context.Context, remote *RemoteRun, body []byte, timeout time.Duration) (Response, error) {
	target := remote.ControlURL(supervisionControlPath)
	if target == "" {
		return Response{}, fmt.Errorf("the deployment names no control")
	}
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	return Exchange(ctx, request, "", timeout)
}
