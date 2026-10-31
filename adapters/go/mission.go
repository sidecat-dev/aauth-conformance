package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// Compiled only into the mission roles' builds.
func init() {
	extensionLaunchers["mission.person-server"] = runMissionServer
	// The Resource slice runs the unchanged four-party native bundle.
	extensionLaunchers["mission.resource"] = runFederatedServers
}

// missionControl is the loopback host input. Approval policy, the person's
// acceptance and the clock are host decisions; protocol answers stay native.
type missionControl struct {
	NowOffset *int64          `json:"now_offset"`
	ExpiresIn *int64          `json:"expires_in"`
	Approve   *string         `json:"approve"`
	Install   json.RawMessage `json:"install"`
}

func runMissionServer(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	seed, err := hex.DecodeString(config.PersonSeed)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("Person Server seed must be 32-byte hex")
	}
	key, err := jose.NewEd25519SigningKey(config.PersonKid, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	origin, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	resourceIssuer := origin.Scheme + "://" + origin.Host
	keys[signaturekey.StaticKeyReference{Issuer: resourceIssuer, DiscoveryDocument: "aauth-resource.json", KeyID: config.ResourceKid}] = config.ResourceJWK
	keys[signaturekey.StaticKeyReference{Issuer: config.PersonServer, DiscoveryDocument: "aauth-person.json", KeyID: config.PersonKid}] = key.PublicJWK()
	var offset, expiresIn atomic.Int64
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now+offset.Load(), 0).UTC() })
	var sequence atomic.Uint64
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: config.PersonServer, SigningKey: key, KeyResolver: keys, Clock: clock,
		NewID:  func() string { return fmt.Sprintf("mission-%d", sequence.Add(1)) },
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: config.PersonSubject, Lifetime: time.Duration(config.PersonLifetime) * time.Second}, nil
		},
		Authorize: func(_ context.Context, input personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			for _, scope := range input.Scopes {
				permitted := false
				for _, allowed := range config.PermittedScopes {
					permitted = permitted || scope == allowed
				}
				if !permitted {
					return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
				}
			}
			return personserver.AuthorizationDecision{Scopes: append([]string(nil), input.Scopes...), Lifetime: time.Duration(config.AuthLifetime) * time.Second}, nil
		},
		// The fixture person approves the proposal as proposed, with the
		// expiry the host was told to set, and accepts updates and completions.
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				decision := personserver.MissionDecision{
					Description:       request.Proposal.Description,
					ApprovedResources: append([]string(nil), request.Proposal.Resources...),
				}
				if seconds := expiresIn.Load(); seconds > 0 {
					expires := clock.Now().Add(time.Duration(seconds) * time.Second)
					decision.ExpiresAt = &expires
				}
				return decision, nil
			},
			AcceptUpdate:                    func(context.Context, personserver.MissionUpdatePolicyRequest) error { return nil },
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error { return nil },
		},
		Permission: &personserver.PermissionConfig{
			Policy: func(context.Context, personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{Permission: aauth.PermissionGranted}}, nil
			},
		},
		Audit: &personserver.AuditConfig{},
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__fixture/mission" && r.Method == http.MethodPost {
			var control missionControl
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err := json.Unmarshal(body, &control); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if control.Approve != nil {
				// The native Person Server approves immediately through its
				// Approve policy; it never defers a proposal in this launcher.
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
			// The native approval already retains the mission for issuance,
			// so an install request changes nothing here.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"installed_by_approval": len(control.Install) > 0})
			return
		}
		// Incoming Host is signature evidence. Reconstruct only the HTTPS scheme.
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		sut.Handler().ServeHTTP(w, r)
	})
	// Only the announced physical origin is used; the path satisfies the
	// runner's readiness check.
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + origin.Path}); err != nil {
		return err
	}
	return (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
