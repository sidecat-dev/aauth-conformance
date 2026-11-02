package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Remote mode for supervision.server: the deployment names its supervision
// server; the suite is the Person Server that signs every request, and the
// second Person Server the server must refuse. Endpoints come from the
// server's aauth-supervisor.json, and its signed decisions are verified
// under the keys its jwks_uri publishes.

const supervisionControlPath = "/__fixture/supervision"

func init() {
	registerRemote(SupervisionServerRole, remoteDriver{
		requires: []string{partySupervision},
		discover: map[string]remoteDocument{partySupervision: {Name: "aauth-supervisor.json"}},
		parties: func(f Fixture) []harnessParty {
			ss, err := supervisionFixture(f)
			if err != nil {
				return nil
			}
			return []harnessParty{party(ss.OtherPS.Issuer, "aauth-person.json", ss.OtherPS.Seed, ss.OtherPS.Kid)}
		},
		gap: func(s Scenario, r RemoteRole) string {
			var input SupervisionServerInput
			if DecodeInput(s, &input) != nil {
				return ""
			}
			for _, step := range input.Steps {
				if len(step.Control) > 0 {
					return controlGap(r, supervisionControlPath)
				}
			}
			return ""
		},
		fixture: func(base Fixture, _ Scenario, r *RemoteRun) Fixture {
			f := base
			f.Now, f.Skew = time.Now().Unix(), r.Skew
			return f
		},
		run: runRemoteSupervisionCase,
	})
}

// remoteSupervisionFixture rebases the supervision fixture onto the
// deployed server: its issuer, endpoints and published keys.
func remoteSupervisionFixture(f Fixture, server RemoteServer) (SupervisionFixture, error) {
	ss, err := supervisionFixture(f)
	if err != nil {
		return ss, err
	}
	ss.Issuer, ss.Kid, ss.Seed = server.Issuer, "", ""
	ss.Published = server.Keys
	if ss.Published == nil {
		ss.Published = keySet{}
	}
	ss.Endpoints = map[string]string{}
	for _, name := range []string{"connect", "mission", "decision", "event"} {
		if endpoint := server.Endpoint(name + "_endpoint"); endpointURL(endpoint) {
			ss.Endpoints[name+"_endpoint"] = endpoint
		}
	}
	return ss, nil
}

func runRemoteSupervisionCase(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
	remote := remoteFrom(ctx)
	base, _ := supervisionFixture(f)
	server := remote.Servers[partySupervision]
	ss, err := remoteSupervisionFixture(f, server)
	if err != nil {
		return failedCase(s, t, err)
	}
	s = rebaseExpected(s, map[string]string{base.Issuer: server.Issuer})
	c := runSupervisionServerCase(ctx, f, ss, s, t, "", o, nil)
	if _, signs := server.Metadata["jwks_uri"]; !signs {
		// An SS without a jwks_uri is a plain JSON responder: the drafts
		// require signatures only of one that publishes keys.
		for i, a := range s.Assertions {
			if a.Kind == "ss-signed" && c.Results[i].State != "not_claimed" {
				c.Results[i] = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: "the supervision server publishes no jwks_uri, so it signs no decisions"}
			}
		}
	}
	return c
}

// remoteSupervisionControl posts a host-control body to the deployment's
// control. Its answer is evidence of host input, never protocol output.
func remoteSupervisionControl(ctx context.Context, remote *RemoteRun, body json.RawMessage, timeout time.Duration) (Response, error) {
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
