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

// publishedKeys discovers a deployed server's Ed25519 and ES256 signing
// keys: its metadata at issuer/.well-known/document, then the JWKS that
// names. It returns the metadata document too. With optional set, metadata
// without a jwks_uri answers no keys instead of an error.
func publishedKeys(ctx context.Context, issuer, document string, timeout time.Duration, optional ...bool) (keySet, map[string]any, error) {
	var metadata map[string]any
	if err := fetchJSON(ctx, issuer+"/.well-known/"+document, timeout, &metadata); err != nil {
		return nil, nil, err
	}
	uri, _ := metadata["jwks_uri"].(string)
	if metadata["issuer"] != issuer {
		return nil, nil, fmt.Errorf("%s/.well-known/%s: issuer must be %s", issuer, document, issuer)
	}
	if uri == "" {
		if len(optional) > 0 && optional[0] {
			return nil, metadata, nil
		}
		return nil, nil, fmt.Errorf("%s/.well-known/%s: jwks_uri must be present", issuer, document)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := fetchJSON(ctx, uri, timeout, &jwks); err != nil {
		return nil, nil, err
	}
	keys := keySet{}
	for _, key := range jwks.Keys {
		kid, _ := key["kid"].(string)
		if public := signingJWK(key); kid != "" && public != nil {
			keys[kid] = public
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("%s publishes no Ed25519 or ES256 key with a kid", uri)
	}
	return keys, metadata, nil
}

// signingJWK returns the public members of a published Ed25519 or P-256 key,
// with its alg, or nil for any other key. A key that names an alg must name
// the one its type and curve fix.
func signingJWK(key map[string]any) map[string]any {
	member := func(name string, size int) (string, bool) {
		value, _ := key[name].(string)
		material, err := base64.RawURLEncoding.Strict().DecodeString(value)
		return value, err == nil && len(material) == size
	}
	if _, private := key["d"]; private {
		return nil
	}
	var public map[string]any
	switch {
	case key["kty"] == "OKP" && key["crv"] == "Ed25519":
		if x, ok := member("x", ed25519.PublicKeySize); ok {
			public = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "Ed25519"}
		}
	case key["kty"] == "EC" && key["crv"] == "P-256":
		x, okX := member("x", 32)
		y, okY := member("y", 32)
		if okX && okY {
			public = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y, "alg": "ES256"}
		}
	}
	if alg, named := key["alg"]; public == nil || named && alg != public["alg"] {
		return nil
	}
	return public
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
