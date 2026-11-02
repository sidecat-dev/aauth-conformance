package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Network is how remote mode reaches servers by their HTTPS names: the
// certificate roots it trusts and, like curl's --resolve, fixed addresses for
// "host:port" names. Without Resolve, names resolve through DNS.
type Network struct {
	Roots   *x509.CertPool
	Resolve map[string]string
}

type networkKey struct{}

// WithNetwork returns a context whose exchanges with an empty transport use n.
func WithNetwork(ctx context.Context, n *Network) context.Context {
	return context.WithValue(ctx, networkKey{}, n)
}

func networkFrom(ctx context.Context) *Network {
	n, _ := ctx.Value(networkKey{}).(*Network)
	if n == nil {
		return &Network{}
	}
	return n
}

func (n *Network) transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{RootCAs: n.Roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if fixed, ok := n.Resolve[address]; ok {
				address = fixed
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

// harnessParty is a party the suite plays whose keys a deployed server must
// discover: its metadata and JWKS are served under its own HTTPS name.
type harnessParty struct {
	issuer, document, seed, kid string
}

// harnessParties lists the fixture's Agent Provider, Resource and Person
// Server. They keep their fixture names in remote mode, so a deployment
// reaches them by routing those names to the suite's listener.
func harnessParties(f Fixture) []harnessParty {
	parties := []harnessParty{{f.Issuer, "aauth-agent.json", f.APSeed, f.Kid}}
	if p := f.Person; p != nil {
		parties = append(parties,
			harnessParty{f.Origin, "aauth-resource.json", p.ResourceSeed, p.ResourceKid},
			harnessParty{p.Issuer, "aauth-person.json", p.Seed, p.Kid})
	}
	return parties
}

// HarnessDocuments returns each harness party's metadata and JWKS by URL,
// for a deployment that pins its trust instead of discovering it.
func HarnessDocuments(f Fixture) map[string][]byte {
	documents := map[string][]byte{}
	for _, party := range harnessParties(f) {
		key := publicJWK(party.seed)
		key["kid"] = party.kid
		documents[party.issuer+"/.well-known/"+party.document], _ = json.Marshal(map[string]any{"issuer": party.issuer, "jwks_uri": party.issuer + "/.well-known/jwks.json"})
		documents[party.issuer+"/.well-known/jwks.json"], _ = json.Marshal(map[string]any{"keys": []any{key}})
	}
	return documents
}

// HarnessHandler serves HarnessDocuments, choosing the party by Host.
func HarnessHandler(f Fixture) http.Handler {
	documents := HarnessDocuments(f)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := documents["https://"+r.Host+r.URL.Path]
		if !ok || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
	})
}

// publishedKeys discovers a deployed server's Ed25519 signing keys: its
// metadata at issuer/.well-known/document, then the JWKS that names. It
// returns the metadata document's string members too.
func publishedKeys(ctx context.Context, issuer, document string, timeout time.Duration) (keySet, map[string]string, error) {
	var raw map[string]any
	if err := fetchJSON(ctx, issuer+"/.well-known/"+document, timeout, &raw); err != nil {
		return nil, nil, err
	}
	metadata := map[string]string{}
	for name, value := range raw {
		if text, ok := value.(string); ok {
			metadata[name] = text
		}
	}
	if metadata["issuer"] != issuer || metadata["jwks_uri"] == "" {
		return nil, nil, fmt.Errorf("%s/.well-known/%s: issuer must be %s and jwks_uri present", issuer, document, issuer)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := fetchJSON(ctx, metadata["jwks_uri"], timeout, &jwks); err != nil {
		return nil, nil, err
	}
	keys := keySet{}
	for _, key := range jwks.Keys {
		kid, _ := key["kid"].(string)
		x, _ := key["x"].(string)
		material, err := base64.RawURLEncoding.Strict().DecodeString(x)
		if key["kty"] == "OKP" && key["crv"] == "Ed25519" && kid != "" && err == nil && len(material) == ed25519.PublicKeySize {
			keys[kid] = ed25519.PublicKey(material)
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("%s publishes no Ed25519 key with a kid", metadata["jwks_uri"])
	}
	return keys, metadata, nil
}

func fetchJSON(ctx context.Context, target string, timeout time.Duration, v any) error {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := Exchange(ctx, request, "", timeout)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", target, response.Status)
	}
	if err := json.Unmarshal(response.Body, v); err != nil {
		return fmt.Errorf("GET %s: %w", target, err)
	}
	return nil
}
