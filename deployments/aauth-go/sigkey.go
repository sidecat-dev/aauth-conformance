package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// The Signature-Key verifier: an agent-identity Resource at /verify that
// also accepts the further schemes aauth-go's Resource offers (hwk, jkt-jwt,
// jwks_uri and jwks) with Ed25519, ES256, ES384, RS256 and PS256 keys. It
// discovers the Agent Provider's and signers' keys with the shared resolver,
// which admits only the configured parties. It answers a verified request
// with the scheme and the verified identity, as the launcher does.
//
// Name: names.sigkey_verifier, the verifier's issuer.
// /.well-known/aauth-resource.json is the library document and is unsigned.
// The library omits jwks_uri for this role.
func init() {
	extensions = append(extensions, func(e env) (map[string]http.Handler, error) {
		issuer := e.c.Names["sigkey_verifier"]
		if issuer == "" {
			return nil, nil
		}
		jwks, ok := e.keys.(signaturekey.JWKSKeyResolver)
		if !ok {
			return nil, fmt.Errorf("the key resolver cannot resolve jwks keys")
		}
		echo := func(w http.ResponseWriter, value map[string]string) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(value)
		}
		verifier, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
			Issuer: issuer, KeyResolver: e.keys, Clock: e.clock,
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				agent, ok := resource.AgentPrincipalFromContext(r.Context())
				if !ok {
					http.Error(w, "missing verified principal", http.StatusInternalServerError)
					return
				}
				echo(w, map[string]string{"scheme": "jwt", "sub": agent.Agent})
			}),
			FurtherSchemes: &resource.FurtherSchemesConfig{
				Schemes:    []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJKTJWT, signaturekey.SchemeJWKSURI, signaturekey.SchemeJWKS},
				Algorithms: []string{"Ed25519", "ES256", "ES384", "RS256", "PS256"},
				JWKS:       jwks,
				Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					signer, ok := resource.SignerFromContext(r.Context())
					if !ok {
						http.Error(w, "missing verified signer", http.StatusInternalServerError)
						return
					}
					echo(w, map[string]string{"scheme": string(signer.Scheme), "signer": signer.Signer, "alg": signer.PublicKey.Alg})
				}),
			},
		})
		if err != nil {
			return nil, err
		}
		handler := verifier.Handler()
		return map[string]http.Handler{issuer: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/aauth-resource.json", "/verify":
				handler.ServeHTTP(w, r)
			default:
				http.NotFound(w, r)
			}
		})}, nil
	})
}
