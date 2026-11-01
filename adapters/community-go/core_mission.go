package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
)

// The mission roles run the module's personserver.Server with its mission,
// permission and audit endpoints (mission.person-server), and the four-party
// bundle (mission.resource). The fixture person approves proposals as
// proposed, accepts updates and completions and grants permissions; the
// module approves immediately, so the approve and install controls change
// nothing.
func init() {
	launchers["mission.person-server"] = coreMissionServer
	launchers["mission.resource"] = coreFederated
}

type coreMissionControl struct {
	NowOffset *int64          `json:"now_offset"`
	ExpiresIn *int64          `json:"expires_in"`
	Approve   *string         `json:"approve"`
	Install   json.RawMessage `json:"install"`
}

func coreMissionServer(config bootstrap) error {
	var p corePersonConfig
	if err := json.Unmarshal(config.Raw, &p); err != nil {
		return err
	}
	key, err := coreSigner(p.PersonSeed)
	if err != nil {
		return err
	}
	agents, err := coreAgentProviderKeys(config)
	if err != nil {
		return err
	}
	resource, err := coreResourceJWK(p.ResourceJWK, p.ResourceKid)
	if err != nil {
		return err
	}
	self, err := aauth.NewJWK(key.Public())
	if err != nil {
		return err
	}
	self.Kid = p.PersonKid
	tokens := aauth.StaticResolver{coreOrigin(config.Resource): {Keys: []aauth.JWK{resource}}, p.PersonServer: {Keys: []aauth.JWK{self}}}
	var offset, expiresIn atomic.Int64
	clock := func() time.Time { return time.Unix(config.Now+offset.Load(), 0).UTC() }
	approver := personserver.MissionApproverFunc(func(_ context.Context, r *personserver.MissionRequest) (personserver.Decision, error) {
		grant := personserver.Grant{Person: p.PersonSubject}
		if r.Kind == personserver.KindMissionProposal {
			grant.Mission = &personserver.MissionGrant{}
			if seconds := expiresIn.Load(); seconds > 0 {
				grant.Mission.ExpiresAt = clock().Add(time.Duration(seconds) * time.Second)
			}
		}
		return personserver.Allow(grant), nil
	})
	server, err := personserver.New(personserver.Config{
		Issuer: p.PersonServer, Key: key, KeyID: p.PersonKid,
		SubjectKey:      []byte("conformance fixture subject derivation key, public"),
		Store:           personserver.NewMemoryStore(),
		Decider:         corePersonPolicy(p),
		MissionApprover: approver,
		PermissionDecider: personserver.PermissionDeciderFunc(func(context.Context, *personserver.PermissionRequest) (personserver.Decision, error) {
			return personserver.Allow(personserver.Grant{}), nil
		}),
		Audit:          true,
		AgentResolver:  agents,
		TokenResolver:  tokens,
		ServerResolver: tokens,
		Paths:          personserver.Paths{PersonToken: "/person", AuthToken: "/token"},
		PersonTokenTTL: time.Duration(p.PersonLifetime) * time.Second,
		AuthTokenTTL:   time.Duration(p.AuthLifetime) * time.Second,
		Now:            clock,
	})
	if err != nil {
		return err
	}
	target, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__fixture/mission" && r.Method == http.MethodPost && strings.EqualFold(r.Host, coreHost(p.PersonServer)) {
			var control coreMissionControl
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err := json.Unmarshal(body, &control); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if control.Approve != nil {
				http.Error(w, "no deferred proposal to approve", http.StatusConflict)
				return
			}
			if control.NowOffset != nil {
				if *control.NowOffset < -3600 || *control.NowOffset > 3600 {
					http.Error(w, "clock offset out of range", http.StatusBadRequest)
					return
				}
				offset.Store(*control.NowOffset)
			}
			if control.ExpiresIn != nil {
				expiresIn.Store(*control.ExpiresIn)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"installed_by_approval": len(control.Install) > 0})
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		server.ServeHTTP(w, r)
	})
	return coreServe(target.Path, handler)
}
