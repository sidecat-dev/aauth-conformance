package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// The Resource role guards one route with the module's ResourceGuard at
// agent-identity level. The guard decides every challenge and refusal.
func init() { launchers["resource.agent-identity"] = coreResource }

func coreResource(config bootstrap) error {
	keys, err := coreAgentProviderKeys(config)
	if err != nil {
		return err
	}
	target, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
		Resource: target.Scheme + "://" + target.Host,
		Verify:   aauth.TokenVerifyOptions{Resolver: keys, Signature: aauth.RequestVerifyOptions{Now: coreClock(config)}},
	})
	if err != nil {
		return err
	}
	protected := guard.Require(aauth.Access{Level: aauth.AccessAgent}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := aauth.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "missing verified caller", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": caller.Agent})
	}))
	return coreServe(target.Path, coreLogical(protected, target.Path))
}

// coreAgentProviderKeys admits the fixture AP's published JWKS for its issuer.
// The module's own JWKS type decodes the document; the fixture's metadata
// must name exactly that issuer and JWKS URL.
func coreAgentProviderKeys(config bootstrap) (aauth.StaticResolver, error) {
	metadata, err := fetchAP(config.APTransport, "/.well-known/aauth-agent.json")
	if err != nil {
		return nil, err
	}
	var document struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(metadata, &document); err != nil {
		return nil, err
	}
	if document.Issuer != config.Issuer || document.JWKS != config.Issuer+"/.well-known/jwks.json" {
		return nil, fmt.Errorf("AP metadata differs from fixture")
	}
	raw, err := fetchAP(config.APTransport, "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	var jwks aauth.JWKS
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return nil, err
	}
	return aauth.StaticResolver{config.Issuer: jwks}, nil
}

// coreClock is the fixture's fixed verifier clock.
func coreClock(config bootstrap) func() time.Time {
	return func() time.Time { return time.Unix(config.Now, 0).UTC() }
}

// coreSigner returns the Ed25519 key for a public fixture seed.
func coreSigner(seedHex string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("fixture seed must be 32-byte hex")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// coreLogical restores the logical HTTPS target the runner signed for; only
// the physical loopback origin differs. Signed bytes are not changed.
func coreLogical(next http.Handler, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path != "" && r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		next.ServeHTTP(w, r)
	})
}

// coreServe announces a loopback URL with the configured path and serves.
func coreServe(path string, handler http.Handler) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + path}); err != nil {
		return err
	}
	return (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
