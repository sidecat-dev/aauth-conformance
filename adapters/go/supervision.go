package main

// Launchers for the supervision roles. The native supervisionserver.Server
// and the native supervised personserver.Server make every protocol
// decision; this file supplies fixed host policy, trusted fixture keys, a
// fixed clock, loopback transport and the host controls the draft leaves to
// the host (resolving a deferred decision, the person's answer, advancing a
// poll and delivering queued events).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() {
	extensionLaunchers["supervision.server"] = runSupervisionServer
	extensionLaunchers["supervision.person-server"] = runSupervisedPersonServer
}

type trustedKey struct {
	Issuer string          `json:"issuer"`
	Kid    string          `json:"kid"`
	JWK    json.RawMessage `json:"jwk"`
	Accept bool            `json:"accept"`
}

func (key trustedKey) decode() (jose.JWK, error) {
	var jwk jose.JWK
	if err := json.Unmarshal(key.JWK, &jwk); err != nil {
		return jwk, err
	}
	jwk.Kid = key.Kid
	return jwk, nil
}

func fixtureSigningKey(kid, seedHex string) (jose.SigningKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return jose.SigningKey{}, fmt.Errorf("fixture seed must be 32-byte hex")
	}
	return jose.NewEd25519SigningKey(kid, ed25519.NewKeyFromSeed(seed))
}

// serveLogical serves handler on a loopback listener with the logical HTTPS
// target reconstructed from the received Host, and routes the host-control
// path to control. It announces readyPath and serves until terminated.
func serveLogical(handler http.Handler, control http.HandlerFunc, readyPath string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__fixture/supervision" {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			control(w, r)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		handler.ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + readyPath}); err != nil {
		return err
	}
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

func writeControl(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

// runSupervisionServer launches a native supervision server. Its host policy
// is fixed: it connects the Person Servers marked accept and refuses the
// others; it allows person-token, auth-token and mission acts, and a
// permission named fixture.allow, denies fixture.deny, asks for fixture.ask
// and defers fixture.defer until a host control resolves it.
func runSupervisionServer(config bootstrap, _ signaturekey.StaticKeyResolver) error {
	var extension struct {
		Supervisor struct {
			Issuer string `json:"issuer"`
			Seed   string `json:"seed_hex"`
			Kid    string `json:"kid"`
		} `json:"supervisor"`
		PersonServers []trustedKey `json:"person_servers"`
	}
	if err := json.Unmarshal(config.Extension, &extension); err != nil {
		return err
	}
	key, err := fixtureSigningKey(extension.Supervisor.Kid, extension.Supervisor.Seed)
	if err != nil {
		return err
	}
	keys := signaturekey.StaticKeyResolver{}
	accepted := map[string]bool{}
	for _, ps := range extension.PersonServers {
		jwk, err := ps.decode()
		if err != nil {
			return err
		}
		keys[signaturekey.StaticKeyReference{Issuer: ps.Issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: ps.Kid}] = jwk
		accepted[ps.Issuer] = ps.Accept
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	server, err := supervisionserver.New(supervisionserver.Config{
		Issuer: extension.Supervisor.Issuer, Name: "Conformance supervisor", SigningKey: &key,
		KeyResolver: keys, Clock: clock, Store: testutil.NewSupervisorStore(),
		Connect: func(_ context.Context, request supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			return supervisionserver.ConnectResult{Accept: accepted[request.PersonServer]}, nil
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
		return err
	}
	control := func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Resolve *struct {
				SDI     string `json:"sdi"`
				Verdict string `json:"verdict"`
			} `json:"resolve"`
			RateLimit bool `json:"rate_limit"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body); err != nil {
			writeControl(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		switch {
		case body.RateLimit:
			writeControl(w, http.StatusNotImplemented, map[string]string{"not_offered": "aauth-go supervisionserver never answers rate_limited and exports no rate_limited response for a host to send"})
		case body.Resolve != nil && body.Resolve.Verdict == "allow":
			for _, ps := range extension.PersonServers {
				if !ps.Accept {
					continue
				}
				result := supervisionserver.DecisionResult{Decision: &supervision.Decision{SDI: body.Resolve.SDI, Verdict: supervision.VerdictAllow}}
				if err := server.ResolveDecision(r.Context(), ps.Issuer, body.Resolve.SDI, result); err != nil {
					writeControl(w, http.StatusConflict, map[string]string{"error": err.Error()})
					return
				}
			}
			writeControl(w, http.StatusOK, map[string]bool{"resolved": true})
		default:
			writeControl(w, http.StatusBadRequest, map[string]string{"error": "unknown host control"})
		}
	}
	return serveLogical(server.Handler(), control, "/.well-known/"+supervision.DiscoveryDocument)
}

// runSupervisedPersonServer launches the native three-party Person Server
// with supervision routing every Agent to the harness supervisor. Its own
// authorization policy is never consulted for a supervised Agent, so it
// refuses. Host controls answer for the person, advance a deferred
// decision once, and deliver queued events.
func runSupervisedPersonServer(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	var extension struct {
		Supervisor          string       `json:"supervisor"`
		SupervisorTransport string       `json:"supervisor_transport"`
		SupervisorSubject   string       `json:"supervisor_subject"`
		SupervisorKeys      []trustedKey `json:"supervisor_keys"`
		Resource            string       `json:"resource"`
	}
	if err := json.Unmarshal(config.Extension, &extension); err != nil {
		return err
	}
	key, err := fixtureSigningKey(config.PersonKid, config.PersonSeed)
	if err != nil {
		return err
	}
	keys[signaturekey.StaticKeyReference{Issuer: extension.Resource, DiscoveryDocument: "aauth-resource.json", KeyID: config.ResourceKid}] = config.ResourceJWK
	keys[signaturekey.StaticKeyReference{Issuer: config.PersonServer, DiscoveryDocument: "aauth-person.json", KeyID: config.PersonKid}] = key.PublicJWK()
	for _, supervisor := range extension.SupervisorKeys {
		jwk, err := supervisor.decode()
		if err != nil {
			return err
		}
		keys[signaturekey.StaticKeyReference{Issuer: supervisor.Issuer, DiscoveryDocument: supervision.DiscoveryDocument, KeyID: supervisor.Kid}] = jwk
	}
	physical, err := url.Parse(extension.SupervisorTransport)
	if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
		return fmt.Errorf("supervisor transport must be loopback HTTP")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(signed *http.Request) (*http.Response, error) {
		if signed.URL.Scheme+"://"+signed.URL.Host != extension.Supervisor {
			return nil, fmt.Errorf("unexpected supervisor destination %s", signed.URL.Host)
		}
		return transport.RoundTrip(mapPhysicalRequest(signed, physical))
	})}
	supervisor := personserver.Supervisor{Issuer: extension.Supervisor, Subject: extension.SupervisorSubject}
	notCalled := errors.New("the Person Server does not decide for a supervised Agent")
	var sequence atomic.Uint64
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: config.PersonServer, SigningKey: key, KeyResolver: keys,
		Clock:  aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }),
		NewID:  func() string { return fmt.Sprintf("fixture-%d", sequence.Add(1)) },
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: config.PersonSubject, Lifetime: time.Duration(config.PersonLifetime) * time.Second}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{}, notCalled
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(context.Context, personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				return supervisor, true, nil
			},
			Store: testutil.NewSupervisionStore(), HTTPClient: client,
			Admit: func(_ context.Context, endpoint string) error {
				if endpoint == extension.Supervisor || strings.HasPrefix(endpoint, extension.Supervisor+"/") {
					return nil
				}
				return fmt.Errorf("supervisor egress outside the fixture: %s", endpoint)
			},
		},
	})
	if err != nil {
		return err
	}
	control := func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Resolve string `json:"resolve"`
			Advance bool   `json:"advance"`
			Deliver bool   `json:"deliver"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body); err != nil {
			writeControl(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx := r.Context()
		switch {
		case body.Deliver:
			delivered, err := sut.DeliverSupervisionEvents(ctx, supervisor)
			if err != nil {
				writeControl(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeControl(w, http.StatusOK, map[string]int{"delivered": delivered})
		case body.Resolve == "allow" || body.Advance:
			reviews, err := sut.PendingSupervision(ctx, 16)
			if err != nil {
				writeControl(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			var failures []string
			for _, review := range reviews {
				if body.Advance {
					err = sut.AdvanceSupervision(ctx, review.Reference)
				} else {
					// The person answers without a reason, which the draft never requires.
					err = sut.ResolveSupervision(ctx, review.Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow})
				}
				if err == nil {
					writeControl(w, http.StatusOK, map[string]string{"reference": review.Reference})
					return
				}
				failures = append(failures, err.Error())
			}
			writeControl(w, http.StatusConflict, map[string]any{"error": "no held act accepted the host call", "attempts": failures})
		default:
			writeControl(w, http.StatusBadRequest, map[string]string{"error": "unknown host control"})
		}
	}
	return serveLogical(sut.Handler(), control, "/person")
}
