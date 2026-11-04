package main

// The supervision server, built with supervisionserver.New. It is served at
// Names["supervision_server"], signs its decisions with a key generated at
// start and discovers each Person Server's keys over HTTPS. Policy follows
// the remote-mode test profile: it connects the Person Servers listed in
// person_servers and refuses every other one whose signature verifies; it
// allows token and mission acts and the permission fixture.allow, denies
// fixture.deny, asks for fixture.ask and defers fixture.defer until the host
// control resolves it. Host controls are served at
// Names["control"]/supervision.server/__fixture/supervision: {"resolve":
// {"sdi", "verdict": "allow"}} settles a deferred decision, and
// {"rate_limit": true} turns the next request away for 30 seconds.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() { extensions = append(extensions, supervisionRole) }

func supervisionRole(e env) (map[string]http.Handler, error) {
	issuer := e.c.Names["supervision_server"]
	if issuer == "" {
		return nil, nil
	}
	key := e.key("go-ss")
	accepted := slices.Clone(e.c.PersonServers)
	var limitNext atomic.Bool
	server, err := supervisionserver.New(supervisionserver.Config{
		Issuer: issuer, Name: "aauth-go reference supervisor", SigningKey: &key,
		KeyResolver: e.keys, Clock: e.clock, Store: testutil.NewSupervisorStore(),
		RateLimit: func(context.Context, string) (time.Duration, error) {
			if limitNext.CompareAndSwap(true, false) {
				return 30 * time.Second, nil
			}
			return 0, nil
		},
		Connect: func(_ context.Context, request supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			return supervisionserver.ConnectResult{Accept: slices.Contains(accepted, request.PersonServer)}, nil
		},
		Decide: func(_ context.Context, request supervisionserver.DecisionRequest) (supervisionserver.DecisionResult, error) {
			decision := supervision.Decision{SDI: request.Request.SDI, Verdict: supervision.VerdictAllow}
			switch request.Request.Kind {
			case supervision.KindMissionProposal:
				decision.Mission = &supervision.MissionTerms{Description: request.Request.Description}
			case supervision.KindPermission:
				switch request.Request.Action {
				case "fixture.deny":
					decision = supervision.Decision{SDI: request.Request.SDI, Verdict: supervision.VerdictDeny, Reason: "Fixture denial."}
				case "fixture.ask":
					decision = supervision.Decision{SDI: request.Request.SDI, Verdict: supervision.VerdictAsk, Summary: "Fixture question for the person."}
				case "fixture.defer":
					return supervisionserver.DecisionResult{Defer: &supervisionserver.Deferral{}}, nil
				}
			}
			return supervisionserver.DecisionResult{Decision: &decision}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	e.controls.HandleFunc("POST /supervision.server/__fixture/supervision", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Resolve *struct {
				SDI     string `json:"sdi"`
				Verdict string `json:"verdict"`
			} `json:"resolve"`
			RateLimit bool `json:"rate_limit"`
		}
		answer := func(status int, value any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(value)
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body); err != nil {
			answer(http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		switch {
		case body.RateLimit:
			limitNext.Store(true)
			answer(http.StatusOK, map[string]bool{"rate_limited": true})
		case body.Resolve != nil && body.Resolve.Verdict == "allow":
			// The decision is pending under the one Person Server that
			// asked. Every accepted server is tried; one is enough.
			refusal := "no accepted Person Server"
			resolved := false
			for _, ps := range accepted {
				result := supervisionserver.DecisionResult{Decision: &supervision.Decision{SDI: body.Resolve.SDI, Verdict: supervision.VerdictAllow}}
				if err := server.ResolveDecision(r.Context(), ps, body.Resolve.SDI, result); err != nil {
					refusal = err.Error()
					continue
				}
				resolved = true
			}
			if !resolved {
				answer(http.StatusConflict, map[string]string{"error": refusal})
				return
			}
			answer(http.StatusOK, map[string]bool{"resolved": true})
		default:
			answer(http.StatusBadRequest, map[string]string{"error": "unknown host control"})
		}
	})
	return map[string]http.Handler{issuer: server.Handler()}, nil
}
