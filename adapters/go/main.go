// This launcher supplies host configuration; all AAuth verification is the SUT's.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
func run() error {
	var config struct {
		Version     int    `json:"version"`
		Now         int64  `json:"now"`
		Issuer      string `json:"issuer"`
		Resource    string `json:"resource"`
		APTransport string `json:"ap_transport"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		return err
	}
	if config.Version != 1 {
		return fmt.Errorf("bootstrap version must be 1")
	}
	origin, err := url.Parse(config.Resource)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("unexpected AP redirect") }}
	fetch := func(path string, v any) error {
		r, err := client.Get(config.APTransport + path)
		if err != nil {
			return err
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("AP HTTP %d", r.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			return err
		}
		if len(b) > 65536 {
			return fmt.Errorf("AP document too large")
		}
		return json.Unmarshal(b, v)
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if err = fetch("/.well-known/aauth-agent.json", &metadata); err != nil {
		return err
	}
	if metadata.Issuer != config.Issuer || metadata.JWKS != config.Issuer+"/.well-known/jwks.json" {
		return fmt.Errorf("AP metadata differs from fixture")
	}
	var jwks struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err = fetch("/.well-known/jwks.json", &jwks); err != nil {
		return err
	}
	keys := signaturekey.StaticKeyResolver{}
	for _, key := range jwks.Keys {
		keys[signaturekey.StaticKeyReference{Issuer: config.Issuer, DiscoveryDocument: "aauth-agent.json", KeyID: key.Kid}] = key
	}
	sut, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: origin.Scheme + "://" + origin.Host, KeyResolver: keys, Clock: aauth.ClockFunc(func() time.Time { return time.Unix(config.Now, 0).UTC() }),
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified principal", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"sub": principal.Agent})
		}),
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != origin.Path {
			http.NotFound(w, r)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		sut.Handler().ServeHTTP(w, r)
	})
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + origin.Path}); err != nil {
		return err
	}
	return (&http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
