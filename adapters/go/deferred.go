// Selected only by build-adapters -role authorization.deferred.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() {
	var stage atomic.Int32
	configureDeferredAS = func(config *accessserver.Config) {
		authorize := config.Authorize
		config.Deferred = &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Second}
		config.Authorize = func(ctx context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			grant, err := authorize(ctx, request)
			if err != nil {
				return grant, err
			}
			switch stage.Load() {
			case -1:
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			case 0:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{Payment: &accessserver.PaymentChallenge{Authenticate: `Payment id="fixture-bill", method="example"`}}}, nil
			case 1:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
			default:
				return grant, nil
			}
		}
	}
	configureDeferredPS = func(config *personserver.FederatedAuthorizationConfig) {
		config.Deferred = &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 30 * time.Second}
	}
	deferredHostControl = func(people *personserver.Server) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				http.Error(w, "POST required", 405)
				return
			}
			var command struct {
				Stage     int32  `json:"stage"`
				Reference string `json:"reference"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&command) != nil || command.Stage < -1 || command.Stage > 2 {
				http.Error(w, "invalid host control", 400)
				return
			}
			// This changes host policy only. The native AS still verifies, issues and
			// retains results; the native PS signs, polls and verifies delivery.
			stage.Store(command.Stage)
			if command.Reference != "" {
				if err := people.AdvanceFederation(r.Context(), command.Reference); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
			}
			w.WriteHeader(204)
		})
	}
}
