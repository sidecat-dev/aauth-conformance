// This launcher supplies host configuration around the community
// github.com/aauth-dev/aauth-go module; AAuth signing and verification are its own.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// bootstrap is the runner's stdin object. Role files read the members they need;
// Raw keeps the whole object for role-specific members.
type bootstrap struct {
	Version     int             `json:"version"`
	Role        string          `json:"role"`
	Now         int64           `json:"now"`
	Issuer      string          `json:"issuer"`
	Resource    string          `json:"resource"`
	APTransport string          `json:"ap_transport"`
	Subject     string          `json:"subject"`
	AgentSeed   string          `json:"agent_seed_hex"`
	Extension   json.RawMessage `json:"extension"`
	Raw         json.RawMessage `json:"-"`
}

// launchers holds one entry per role this launcher offers; each role file
// registers itself. A role without an entry is refused at startup.
var launchers = map[string]func(bootstrap) error{}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return err
	}
	var config bootstrap
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	config.Raw = raw
	if config.Version != 1 {
		return fmt.Errorf("bootstrap version must be 1")
	}
	role := config.Role
	if role == "" {
		role = "resource.agent-identity"
	}
	launch, ok := launchers[role]
	if !ok {
		return fmt.Errorf("the community launcher offers no %s role", role)
	}
	return launch(config)
}

// fetchAP reads one fixture Agent Provider document from its loopback transport.
// It is test transport, not a discovery client.
func fetchAP(transport, path string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("unexpected AP redirect") }}
	r, err := client.Get(transport + path)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("AP HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, fmt.Errorf("AP document too large")
	}
	return b, nil
}
