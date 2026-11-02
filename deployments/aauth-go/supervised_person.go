package main

// The supervised Person Server, built with personserver.NewPSAuthorization
// and its Supervision option. It is served at
// Names["supervised_person_server"] and routes every Agent to the
// supervision server at Names["supervisor"], which the suite plays, with the
// person's identifier there supervisorSubject. It discovers that server's
// keys over HTTPS and acts only on decisions signed by it. Its own policy
// never decides: a supervised Agent's acts are the supervisor's or the
// person's. Host controls are served at
// Names["control"]/supervision.person-server/__fixture/supervision:
// {"deliver": true} delivers queued events and reports, and {"resolve":
// "allow", "pending"} or {"advance": true, "pending"} answers for the
// person, or polls the supervisor, for the held act whose pending URL is
// "pending".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// supervisorSubject is the person's directed identifier at the supervisor,
// the fixture's.
const supervisorSubject = "ss-directed-person-1"

func init() { extensions = append(extensions, supervisedPersonRole) }

func supervisedPersonRole(e env) (map[string]http.Handler, error) {
	issuer, supervisorIssuer := e.c.Names["supervised_person_server"], e.c.Names["supervisor"]
	if issuer == "" || supervisorIssuer == "" {
		return nil, nil
	}
	supervisor := personserver.Supervisor{Issuer: supervisorIssuer, Subject: supervisorSubject}
	notCalled := errors.New("the Person Server does not decide for a supervised Agent")
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: issuer, SigningKey: e.key("go-supervised-ps"), KeyResolver: e.keys, Clock: e.clock, NewID: e.newID,
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: subject, Lifetime: personLifetime}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{}, notCalled
		},
		// Missions are enabled so a supervised Agent can propose one; the
		// supervisor approves it, never this policy.
		Missions: &personserver.MissionConfig{
			Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{}, notCalled
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(context.Context, personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				return supervisor, true, nil
			},
			Store: testutil.NewSupervisionStore(), HTTPClient: e.client,
			Admit: func(_ context.Context, endpoint string) error {
				if endpoint == supervisorIssuer || strings.HasPrefix(endpoint, supervisorIssuer+"/") {
					return nil
				}
				return fmt.Errorf("not the supervisor: %s", endpoint)
			},
		},
	})
	if err != nil {
		return nil, err
	}
	e.controls.HandleFunc("POST /supervision.person-server/__fixture/supervision", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Deliver bool   `json:"deliver"`
			Resolve string `json:"resolve"`
			Advance bool   `json:"advance"`
			Pending string `json:"pending"`
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
		ctx := r.Context()
		switch {
		case body.Deliver:
			delivered, err := sut.DeliverSupervisionEvents(ctx, supervisor)
			if err != nil {
				answer(http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			answer(http.StatusOK, map[string]int{"delivered": delivered})
		case body.Resolve == "allow" || body.Advance:
			pending, err := url.Parse(body.Pending)
			if err != nil || pending.Scheme+"://"+pending.Host != issuer || path.Dir(pending.Path) != "/pending" {
				answer(http.StatusBadRequest, map[string]string{"error": "pending must be a held act's URL on this server"})
				return
			}
			reference := path.Base(pending.Path)
			if body.Advance {
				err = sut.AdvanceSupervision(ctx, reference)
			} else {
				// The person answers without a reason, which the draft never requires.
				err = sut.ResolveSupervision(ctx, reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow})
			}
			if err != nil {
				answer(http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			answer(http.StatusOK, map[string]string{"reference": reference})
		default:
			answer(http.StatusBadRequest, map[string]string{"error": "unknown host control"})
		}
	})
	return map[string]http.Handler{issuer: sut.Handler()}, nil
}
