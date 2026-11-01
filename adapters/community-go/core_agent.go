package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// The Agent role signs each control job with the module's own signer:
// AttachSignatureKey presents the AP-issued token and SignRequest covers the
// request. The module signs with the wall clock; it has no clock input.
func init() { launchers["agent.signing"] = coreAgent }

func coreAgent(config bootstrap) error {
	key, err := coreSigner(config.AgentSeed)
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var job struct {
			Method    string            `json:"method"`
			URL       string            `json:"url"`
			Headers   map[string]string `json:"headers"`
			Token     string            `json:"token"`
			Transport string            `json:"transport"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&job); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		physical, err := url.Parse(job.Transport)
		if err != nil || physical.Scheme != "http" || !net.ParseIP(physical.Hostname()).IsLoopback() {
			http.Error(w, "loopback transport required", 400)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), job.Method, job.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for name, value := range job.Headers {
			request.Header.Set(name, value)
		}
		aauth.AttachSignatureKey(request, job.Token)
		if err := aauth.SignRequest(request, key, ""); err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		if request.Body != nil && request.Body != http.NoBody {
			http.Error(w, "the signer added a body to a bodyless request", 422)
			return
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(coreMapPhysical(request, physical))
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer response.Body.Close()
		if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 65537)); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"status": response.StatusCode})
	})
	return coreServe("/control", http.TimeoutHandler(handler, 10*time.Second, fmt.Sprintf("%s control timeout", "agent")))
}

// coreMapPhysical substitutes only the socket destination and keeps the
// signed Host, path, query and headers.
func coreMapPhysical(signed *http.Request, physical *url.URL) *http.Request {
	mapped := signed.Clone(signed.Context())
	target := *signed.URL
	target.Scheme = physical.Scheme
	target.Host = physical.Host
	if mapped.Host == "" {
		mapped.Host = signed.URL.Host
	}
	mapped.URL = &target
	return mapped
}
