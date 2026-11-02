package main

// Bootstrap roles: the native hosted Agent Provider (enrollment, two-key and
// single-key refresh, sub-agent issuance), the native self-hosted Agent
// Provider and the native bootstrap Agent. This file supplies host policy,
// fixed clocks, fixture keys and the suite's routes; every proof, token and
// enrollment decision belongs to aauth-go, and so does the in-memory
// enrollment store (testutil.NewEnrollmentStore).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func init() {
	providerLaunchers["bootstrap.agent-provider"] = runBootstrapProvider
	providerLaunchers["bootstrap.self-hosted"] = runBootstrapSelfHosted
	extensionLaunchers["bootstrap.agent"] = runBootstrapAgent
}

// bootstrapExtension is the bootstrap extension object of ADAPTERS.md,
// "Bootstrap roles".
type bootstrapExtension struct {
	APSeed               string `json:"ap_seed_hex"`
	APKid                string `json:"ap_kid"`
	EnrollmentPath       string `json:"enrollment_path"`
	RefreshPath          string `json:"refresh_path"`
	SingleKeyRefreshPath string `json:"single_key_refresh_path"`
	SubagentPath         string `json:"subagent_path"`
	IssuePath            string `json:"issue_path"`
	AgentLifetime        int64  `json:"agent_lifetime"`
	PersonServer         string `json:"person_server"`
}

func bootstrapConfig(config bootstrap) (bootstrapExtension, aauth.Clock, error) {
	var extension bootstrapExtension
	if err := json.Unmarshal(config.Extension, &extension); err != nil {
		return extension, nil, fmt.Errorf("bootstrap extension: %w", err)
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() })
	return extension, clock, nil
}

// bootstrapProvider is the native Agent Provider under the fixture AP
// identity and key.
func bootstrapProvider(config bootstrap, extension bootstrapExtension, clock aauth.Clock, newID func() string) (*agentprovider.Server, jose.SigningKey, error) {
	seed, err := hex.DecodeString(extension.APSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, jose.SigningKey{}, errors.New("bootstrap AP seed must be 32-byte hex")
	}
	key, err := jose.NewEd25519SigningKey(extension.APKid, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, jose.SigningKey{}, err
	}
	provider, err := agentprovider.New(agentprovider.Config{Issuer: config.Issuer, SigningKey: key, Clock: clock, NewID: newID})
	return provider, key, err
}

func bootstrapIDs(prefix string) func() string {
	var ids atomic.Uint64
	return func() string { return fmt.Sprintf("%s-%d", prefix, ids.Add(1)) }
}

// runBootstrapProvider serves the hosted AP. Host policy approves every
// enrollment whatever its evidence and names each durable key its own
// top-level Agent; refresh approves the requested Person Server with the
// fixture lifetime; sub-agent policy (bootstrapSubagentNames) approves
// sub-agents of a top-level Agent and chooses their discriminators.
func runBootstrapProvider(config bootstrap) error {
	extension, clock, err := bootstrapConfig(config)
	if err != nil {
		return err
	}
	provider, _, err := bootstrapProvider(config, extension, clock, bootstrapIDs("bootstrap-agent-token"))
	if err != nil {
		return err
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil {
		return err
	}
	lifetime := time.Duration(extension.AgentLifetime) * time.Second
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider,
		Store:    testutil.NewEnrollmentStore(clock),
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			// One Agent per install: the local part derives from the durable
			// key's thumbprint URI, so it is stable for that key and no other.
			digest := sha256.Sum256([]byte(request.Identity))
			return agentprovider.EnrollmentDecision{Agent: "aauth:install-" + hex.EncodeToString(digest[:6]) + "@" + issuer.Hostname()}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{PersonServer: request.RequestedPersonServer, Lifetime: lifetime}, nil
		},
	})
	if err != nil {
		return err
	}
	names := &bootstrapSubagentNames{lifetime: lifetime, used: map[string]map[string]bool{}}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", provider.Handler())
	mux.Handle(extension.EnrollmentPath, service.EnrollmentHandler())
	mux.Handle(extension.RefreshPath, service.RefreshHandler())
	mux.Handle(extension.SingleKeyRefreshPath, service.SingleKeyRefreshHandler())
	mux.Handle(extension.SubagentPath, provider.SubagentHandler(names.decide))
	return bootstrapServe("/.well-known/aauth-agent.json", mux)
}

// bootstrapSubagentNames is the hosted AP's sub-agent policy. It keeps the
// parent's discriminator unless the parent offered none or it is already in
// use for that parent, and then chooses its own (Bootstrap, Sub-Agents Under
// a Hosted AP, step 4). It records which parent was issued each name.
type bootstrapSubagentNames struct {
	lifetime time.Duration
	mu       sync.Mutex
	used     map[string]map[string]bool
	next     int
}

func (names *bootstrapSubagentNames) decide(_ context.Context, request agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
	names.mu.Lock()
	defer names.mu.Unlock()
	used := names.used[request.Parent.Subject]
	if used == nil {
		used = map[string]bool{}
		names.used[request.Parent.Subject] = used
	}
	discriminator := request.Discriminator
	for discriminator == "" || used[discriminator] {
		names.next++
		discriminator = fmt.Sprintf("sub%d", names.next)
	}
	used[discriminator] = true
	return agentprovider.SubagentDecision{Discriminator: discriminator, Lifetime: names.lifetime}, nil
}

// runBootstrapSelfHosted serves the self-hosted AP's metadata and JWKS and
// the token-issuing process behind the issue control. A top-level issue whose
// key is the published AP key is the single-key self-hosted Agent; any other
// key is one of several agents the operator runs; a parent token asks for a
// sub-agent, and the native call decides whether the parent may have one.
func runBootstrapSelfHosted(config bootstrap) error {
	extension, clock, err := bootstrapConfig(config)
	if err != nil {
		return err
	}
	newID := bootstrapIDs("self-hosted-agent-token")
	provider, apKey, err := bootstrapProvider(config, extension, clock, newID)
	if err != nil {
		return err
	}
	lifetime := time.Duration(extension.AgentLifetime) * time.Second
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", provider.Handler())
	mux.HandleFunc("POST "+extension.IssuePath, func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			Agent         string   `json:"agent"`
			JWK           jose.JWK `json:"jwk"`
			PersonServer  string   `json:"ps"`
			ParentToken   string   `json:"parent_token"`
			Discriminator string   `json:"discriminator"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&job); err != nil {
			bootstrapRefuse(w, http.StatusBadRequest, err)
			return
		}
		var token string
		var err error
		switch {
		case job.ParentToken != "":
			token, err = provider.IssueSubagent(r.Context(), job.ParentToken, agentprovider.SubagentTokenRequest{
				Discriminator: job.Discriminator, PublicKey: job.JWK, Lifetime: lifetime,
			})
		case job.JWK.Equal(apKey.PublicJWK()):
			var agentProvider *agentprovider.SelfHostedAgent
			agentProvider, err = agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
				Issuer: config.Issuer, Agent: job.Agent, SigningKey: apKey, Clock: clock, NewID: newID,
			})
			if err == nil {
				token, err = agentProvider.Issue(agentprovider.SelfHostedAgentTokenRequest{PersonServer: job.PersonServer, Lifetime: lifetime})
			}
		default:
			token, err = provider.Issue(r.Context(), aauth.AgentTokenRequest{
				Agent: job.Agent, PersonServer: job.PersonServer, PublicKey: job.JWK, Lifetime: lifetime,
			})
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, agentprovider.ErrInvalidSubagentParent) {
				status = http.StatusForbidden
			}
			bootstrapRefuse(w, status, err)
			return
		}
		bootstrapAnswer(w, http.StatusOK, map[string]string{"agent_token": token})
	})
	return bootstrapServe("/.well-known/aauth-agent.json", mux)
}

// bootstrapAgentState is what the native Agent holds between control jobs:
// its assigned identifier and its current Agent token and ephemeral key.
type bootstrapAgentState struct {
	mu    sync.Mutex
	agent string
	token string
	key   jose.SigningKey
}

// runBootstrapAgent drives the native bootstrap Agent. It generates its own
// durable key and a fresh ephemeral key for every refresh; agent.
// BootstrapClient enrolls and refreshes, and agent.Client requests sub-agent
// tokens and calls Resources with the current token. A BootstrapClient posts
// a single-key refresh to its one refresh endpoint, so a second client with
// the same durable key serves the single-key path. aauth-go has no
// refresh-margin decision, so the renew operation is not offered (see
// cmd/build-adapters/bootstrap.go).
func runBootstrapAgent(config bootstrap, keys signaturekey.StaticKeyResolver) error {
	extension, clock, err := bootstrapConfig(config)
	if err != nil {
		return err
	}
	apTransport, err := loopbackTransport(config.APTransport)
	if err != nil {
		return err
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil {
		return err
	}
	durable, err := bootstrapGeneratedKey("durable")
	if err != nil {
		return err
	}
	routes := func(extra map[string]*url.URL) *http.Client {
		physical := map[string]*url.URL{issuer.Host: apTransport}
		for host, target := range extra {
			physical[host] = target
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		return &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(signed *http.Request) (*http.Response, error) {
			target := physical[signed.URL.Host]
			if target == nil {
				return nil, fmt.Errorf("no fixture transport for %s", signed.URL.Host)
			}
			return transport.RoundTrip(mapPhysicalRequest(signed, target))
		})}
	}
	client, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      config.Issuer,
		EnrollmentEndpoint: config.Issuer + extension.EnrollmentPath,
		RefreshEndpoint:    config.Issuer + extension.RefreshPath,
		DurableKey:         durable,
		KeyResolver:        keys,
		HTTPClient:         routes(nil),
		Clock:              clock,
	})
	if err != nil {
		return err
	}
	singleKey, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      config.Issuer,
		EnrollmentEndpoint: config.Issuer + extension.EnrollmentPath,
		RefreshEndpoint:    config.Issuer + extension.SingleKeyRefreshPath,
		DurableKey:         durable,
		KeyResolver:        keys,
		HTTPClient:         routes(nil),
		Clock:              clock,
	})
	if err != nil {
		return err
	}
	state := &bootstrapAgentState{}
	// current is an authenticated Agent client for the latest Agent token.
	current := func(ctx context.Context, extra map[string]*url.URL) (*agent.Client, error) {
		state.mu.Lock()
		identifier, token, key := state.agent, state.token, state.key
		state.mu.Unlock()
		if token == "" {
			return nil, errors.New("no Agent token yet: refresh first")
		}
		return agent.New(ctx, agent.Config{Identifier: identifier, SigningKey: key, AgentToken: token, KeyResolver: keys, HTTPClient: routes(extra), Clock: clock})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /control", func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			Operation     string   `json:"operation"`
			JWK           jose.JWK `json:"jwk"`
			Discriminator string   `json:"discriminator"`
			Method        string   `json:"method"`
			URL           string   `json:"url"`
			Transport     string   `json:"transport"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&job); err != nil {
			bootstrapRefuse(w, http.StatusBadRequest, err)
			return
		}
		ctx := r.Context()
		answer := map[string]any{"operation": job.Operation}
		switch job.Operation {
		case "enroll":
			enrolled, err := client.Enroll(ctx, json.RawMessage(`{}`))
			if err != nil {
				bootstrapRefuse(w, http.StatusUnprocessableEntity, err)
				return
			}
			state.mu.Lock()
			state.agent = enrolled.Agent
			state.mu.Unlock()
			answer["agent"] = enrolled.Agent
		case "refresh":
			state.mu.Lock()
			identifier := state.agent
			state.mu.Unlock()
			ephemeral, err := bootstrapGeneratedKey("ephemeral")
			if err == nil {
				var jti string
				jti, err = bootstrapRandom()
				now := clock.Now()
				var refreshed agent.RefreshAgentTokenResult
				if err == nil {
					refreshed, err = client.Refresh(ctx, agent.RefreshAgentTokenInput{
						Agent: identifier, PersonServer: extension.PersonServer, Evidence: json.RawMessage(`{}`),
						SigningKey: ephemeral, DelegationJTI: jti, DelegationIssuedAt: now, DelegationExpiresAt: now.Add(5 * time.Minute),
					})
				}
				if err == nil {
					state.mu.Lock()
					state.token, state.key = refreshed.AgentToken, ephemeral
					state.mu.Unlock()
				}
			}
			if err != nil {
				bootstrapRefuse(w, http.StatusUnprocessableEntity, err)
				return
			}
		case "single-key":
			state.mu.Lock()
			identifier := state.agent
			state.mu.Unlock()
			refreshed, err := singleKey.RefreshSingleKey(ctx, agent.SingleKeyRefreshAgentTokenInput{
				Agent: identifier, PersonServer: extension.PersonServer, Evidence: json.RawMessage(`{}`),
			})
			if err != nil {
				bootstrapRefuse(w, http.StatusUnprocessableEntity, err)
				return
			}
			state.mu.Lock()
			state.token, state.key = refreshed.AgentToken, durable
			state.mu.Unlock()
		case "subagent":
			parent, err := current(ctx, nil)
			var child string
			if err == nil {
				child, err = parent.RequestSubagentToken(ctx, agent.SubagentTokenRequest{
					Endpoint: config.Issuer + extension.SubagentPath, PublicKey: job.JWK, Discriminator: job.Discriminator,
				})
			}
			if err != nil {
				bootstrapRefuse(w, http.StatusUnprocessableEntity, err)
				return
			}
			answer["agent_token"] = child
		case "call":
			target, err := url.Parse(job.URL)
			var transport *url.URL
			if err == nil {
				transport, err = loopbackTransport(job.Transport)
			}
			var caller *agent.Client
			if err == nil {
				caller, err = current(ctx, map[string]*url.URL{target.Host: transport})
			}
			var request *http.Request
			if err == nil {
				request, err = http.NewRequestWithContext(ctx, job.Method, job.URL, nil)
			}
			var response *http.Response
			if err == nil {
				response, err = caller.CallAsAgentWithComponents(ctx, request, nil)
			}
			if err != nil {
				bootstrapRefuse(w, http.StatusUnprocessableEntity, err)
				return
			}
			io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
			response.Body.Close()
			answer["status"] = response.StatusCode
		default:
			bootstrapRefuse(w, http.StatusBadRequest, fmt.Errorf("unknown operation %q", job.Operation))
			return
		}
		bootstrapAnswer(w, http.StatusOK, answer)
	})
	return bootstrapServe("/control", mux)
}

// bootstrapGeneratedKey is a new Ed25519 key the Agent generates where it runs.
func bootstrapGeneratedKey(kid string) (jose.SigningKey, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(kid, private)
}

func bootstrapRandom() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func bootstrapAnswer(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func bootstrapRefuse(w http.ResponseWriter, status int, err error) {
	bootstrapAnswer(w, status, map[string]string{"error": err.Error()})
}

// bootstrapServe announces path on a loopback listener and serves handler
// with the logical Host the runner sends.
func bootstrapServe(path string, handler http.Handler) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme, r.URL.Host = "https", r.Host
		handler.ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path}); err != nil {
		return err
	}
	return (&http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
