package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// The vectors launcher calls one native function per community vector kind and
// reports the native result. It decides nothing itself.
func init() {
	extensionLaunchers["vectors.library"] = func(bootstrap, signaturekey.StaticKeyResolver) error {
		return vectorServe(vectorHandle)
	}
}

type vectorInput struct {
	Kind                string            `json:"kind"`
	Input               string            `json:"input"`
	JWK                 json.RawMessage   `json:"jwk"`
	Document            string            `json:"document"`
	JSON                string            `json:"json"`
	Header              string            `json:"header"`
	Label               string            `json:"label"`
	Now                 int64             `json:"now"`
	Request             vectorHTTPRequest `json:"request"`
	Typ                 string            `json:"typ"`
	Token               string            `json:"token"`
	Issuer              string            `json:"issuer"`
	DWK                 string            `json:"dwk"`
	Kid                 string            `json:"kid"`
	JWKS                string            `json:"jwks"`
	Key                 json.RawMessage   `json:"key"`
	Window              int64             `json:"window"`
	RequiredComponents  []string          `json:"required_components"`
	RequireBodyCoverage bool              `json:"require_body_coverage"`
}
type vectorHTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// vectorNotOffered marks a vector kind this library has no public function for.
type vectorNotOffered string

func vectorServe(handle func(vectorInput) (map[string]any, error)) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "url": "http://" + listener.Addr().String() + "/vector"}); err != nil {
		return err
	}
	return (&http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in vectorInput
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := handle(in)
		status := http.StatusOK
		var unoffered vectorNotOffered
		if errors.As(err, &unoffered) {
			status, result = http.StatusNotImplemented, map[string]any{"not_offered": string(unoffered)}
		} else if err != nil {
			status, result = http.StatusUnprocessableEntity, map[string]any{"error": err.Error()}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(result)
	})}).Serve(listener)
}

func (reason vectorNotOffered) Error() string { return string(reason) }

// vectorRefusal reports a native refusal with its Signature-Error code when
// the library gives one.
func vectorRefusal(err error) map[string]any {
	result := map[string]any{"accepted": false, "error": err.Error()}
	var failure *signaturekey.Error
	if errors.As(err, &failure) {
		result["code"] = string(failure.Code)
	}
	return result
}

func vectorClock(now int64) aauth.ClockFunc {
	return func() time.Time { return time.Unix(now, 0).UTC() }
}

func vectorHandle(in vectorInput) (map[string]any, error) {
	switch in.Kind {
	case "agent-identifier":
		if err := aauth.ValidateAgentIdentifier(in.Input); err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true}, nil
	case "server-identifier":
		if err := aauth.ValidateServerIdentifier(in.Input); err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true}, nil
	case "jwk-thumbprint":
		var key jose.JWK
		if err := json.Unmarshal(in.JWK, &key); err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		thumbprint, err := key.RFC7638Thumbprint()
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true, "thumbprint": thumbprint}, nil
	case "metadata":
		// The document is decoded as if fetched from the issuer it names.
		var issuer struct {
			Issuer string `json:"issuer"`
		}
		json.Unmarshal([]byte(in.JSON), &issuer)
		exact := []byte(in.JSON)
		var err error
		switch in.Document {
		case "aauth-agent.json":
			_, err = aauth.DecodeAgentProviderMetadata(exact, issuer.Issuer)
		case "aauth-person.json":
			_, err = aauth.DecodePersonServerMetadata(exact, issuer.Issuer)
		case "aauth-access.json":
			_, err = aauth.DecodeAccessServerMetadata(exact, issuer.Issuer)
		case "aauth-resource.json":
			_, err = aauth.DecodeResourceMetadata(exact, issuer.Issuer)
		default:
			return nil, vectorNotOffered("aauth-go has no decoder for " + in.Document)
		}
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true}, nil
	case "signature-error":
		parsed, err := signaturekey.ParseError(in.Header)
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		result := map[string]any{"accepted": true, "code": string(parsed.Code)}
		if parsed.RequiredInput != nil {
			result["required_input"] = parsed.RequiredInput
		}
		return result, nil
	case "requirement":
		return vectorRequirement(in.Header), nil
	case "signature-key":
		return vectorSignatureKey(in)
	case "jwt":
		return vectorJWT(in)
	case "http-signature":
		return vectorHTTPSignature(in)
	}
	return nil, errors.New("unknown vector kind " + in.Kind)
}

func vectorRequirement(header string) map[string]any {
	values := []string{header}
	requirement, err := aauth.ParseRequirement(values)
	if err != nil {
		return map[string]any{"accepted": false, "error": err.Error()}
	}
	result := map[string]any{"accepted": true, "requirement": string(requirement)}
	switch requirement {
	case aauth.RequirementAuthToken:
		parsed, err := aauth.ParseAuthTokenRequirement(values)
		if err != nil {
			return map[string]any{"accepted": false, "requirement": string(requirement), "error": err.Error()}
		}
		result["resource_token"] = parsed.ResourceToken
	case aauth.RequirementInteraction:
		parsed, err := aauth.ParseInteractionRequirement(values)
		if err != nil {
			return map[string]any{"accepted": false, "requirement": string(requirement), "error": err.Error()}
		}
		result["url"], result["interaction_code"] = parsed.URL, parsed.Code
	}
	return result
}

func vectorBuildRequest(spec vectorHTTPRequest) (*http.Request, error) {
	var body io.Reader
	if spec.Body != "" {
		body = strings.NewReader(spec.Body)
	}
	request, err := http.NewRequest(spec.Method, spec.URL, body)
	if err != nil {
		return nil, err
	}
	for name, value := range spec.Headers {
		request.Header.Set(name, value)
	}
	return request, nil
}

// vectorSignatureKey prepares the request under Go's default AAuth agent
// profile (jwt only) for the selected label; no key is verified.
func vectorSignatureKey(in vectorInput) (map[string]any, error) {
	request, err := vectorBuildRequest(in.Request)
	if err != nil {
		return nil, err
	}
	result := map[string]any{}
	if credential, err := signaturekey.ParseCredentialForLabel(request.Header.Values("Signature-Key"), in.Label); err == nil {
		result["scheme"] = string(credential.Scheme())
	}
	prepared, err := signaturekey.PrepareRequest(request, vectorClock(in.Now), signaturekey.VerifyOptions{SignatureLabel: in.Label})
	if err != nil {
		for k, v := range vectorRefusal(err) {
			result[k] = v
		}
		return result, nil
	}
	result["accepted"] = true
	if token, ok := prepared.Credential().JWT(); ok {
		result["jwt"] = token
	}
	return result, nil
}

func vectorJWT(in vectorInput) (map[string]any, error) {
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.Unmarshal([]byte(in.JWKS), &set); err != nil {
		return map[string]any{"accepted": false, "stage": "trust", "error": err.Error()}, nil
	}
	resolver := signaturekey.StaticKeyResolver{}
	for _, key := range set.Keys {
		resolver[signaturekey.StaticKeyReference{Issuer: in.Issuer, DiscoveryDocument: in.DWK, KeyID: key.Kid}] = key
	}
	ctx, clock := context.Background(), vectorClock(in.Now)
	var err error
	switch in.Typ {
	case aauth.AgentTokenType:
		_, err = aauth.VerifyAgentToken(ctx, in.Token, resolver, clock)
	case aauth.PersonTokenType:
		_, err = aauth.VerifyPersonToken(ctx, in.Token, resolver, clock)
	case aauth.ResourceTokenType:
		_, err = aauth.VerifyResourceToken(ctx, in.Token, resolver, clock)
	case aauth.AuthTokenType:
		_, err = aauth.VerifyAuthToken(ctx, in.Token, resolver, clock)
	default:
		return nil, vectorNotOffered("no verifier for typ " + in.Typ)
	}
	if err != nil {
		return vectorRefusal(err), nil
	}
	return map[string]any{"accepted": true}, nil
}

// vectorHTTPSignature verifies the request with the vector's public key under
// the AAuth agent profile, the given clock, window and required components.
func vectorHTTPSignature(in vectorInput) (map[string]any, error) {
	request, err := vectorBuildRequest(in.Request)
	if err != nil {
		return nil, err
	}
	var key jose.JWK
	if err := json.Unmarshal(in.Key, &key); err != nil {
		return map[string]any{"accepted": false, "stage": "key", "error": err.Error()}, nil
	}
	required := append([]string(nil), in.RequiredComponents...)
	if in.RequireBodyCoverage && len(in.Request.Body) > 0 {
		required = append(required, "content-digest", "content-type")
	}
	prepared, err := signaturekey.PrepareRequest(request, vectorClock(in.Now), signaturekey.VerifyOptions{
		SignatureLabel: in.Label, SignatureWindow: time.Duration(in.Window) * time.Second, RequiredComponents: required,
	})
	if err != nil {
		return vectorRefusal(err), nil
	}
	if _, err := prepared.Verify(key); err != nil {
		return vectorRefusal(err), nil
	}
	return map[string]any{"accepted": true}, nil
}
