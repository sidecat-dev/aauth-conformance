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

	aauth "github.com/aauth-dev/aauth-go"
)

// The vectors launcher calls one exported function of the community module per
// vector kind and reports its result. It decides nothing itself.
func init() { launchers["vectors.library"] = func(bootstrap) error { return vectorServe() } }

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
	Audience            string            `json:"audience"`
	Issuer              string            `json:"issuer"`
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

// vectorNotOffered marks a vector kind the module exports no function for.
type vectorNotOffered string

func (reason vectorNotOffered) Error() string { return string(reason) }

func vectorServe() error {
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
		result, err := vectorHandle(in)
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

// vectorRefusal reports a refusal with its Signature-Error code when the
// module classifies the error.
func vectorRefusal(err error) map[string]any {
	result := map[string]any{"accepted": false, "error": err.Error()}
	if failure, ok := aauth.SignatureErrorFor(err); ok {
		result["code"] = failure.Code
	}
	return result
}

func vectorClock(now int64) aauth.RequestVerifyOptions {
	at := time.Unix(now, 0)
	return aauth.RequestVerifyOptions{Now: func() time.Time { return at }}
}

func vectorHandle(in vectorInput) (map[string]any, error) {
	switch in.Kind {
	case "agent-identifier":
		id, err := aauth.ParseAgentIdentifier(in.Input)
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true, "name": id.Name, "discriminator": id.Discriminator, "domain": id.Domain}, nil
	case "server-identifier":
		if err := aauth.ValidateServerIdentifier(in.Input); err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true}, nil
	case "jwk-thumbprint":
		var key aauth.JWK
		if err := json.Unmarshal(in.JWK, &key); err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		return map[string]any{"accepted": true, "thumbprint": key.Thumbprint()}, nil
	case "metadata":
		return vectorMetadata(in)
	case "signature-error":
		parsed, err := aauth.ParseSignatureError(in.Header)
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		result := map[string]any{"accepted": true, "code": parsed.Code}
		if parsed.RequiredInput != nil {
			result["required_input"] = parsed.RequiredInput
		}
		return result, nil
	case "requirement":
		parsed, err := aauth.ParseRequirement(in.Header)
		if err != nil {
			return map[string]any{"accepted": false, "error": err.Error()}, nil
		}
		result := map[string]any{"accepted": true, "requirement": parsed.Requirement}
		if parsed.ResourceToken != "" {
			result["resource_token"] = parsed.ResourceToken
		}
		if parsed.URL != "" || parsed.Code != "" {
			result["url"], result["interaction_code"] = parsed.URL, parsed.Code
		}
		return result, nil
	case "signature-key":
		request, err := vectorBuildRequest(in.Request)
		if err != nil {
			return nil, err
		}
		result := map[string]any{}
		if member, err := aauth.ParseSignatureKeyMember(request, in.Label); err == nil {
			result["scheme"] = member.Scheme
		}
		token, err := aauth.ParseSignatureKey(request)
		if err != nil {
			for k, v := range vectorRefusal(err) {
				result[k] = v
			}
			return result, nil
		}
		result["accepted"], result["jwt"] = true, token
		return result, nil
	case "jwt":
		return vectorJWT(in)
	case "http-signature":
		return vectorHTTPSignature(in)
	}
	return nil, errors.New("unknown vector kind " + in.Kind)
}

// vectorMetadata decodes a document into the module's type for it and runs
// its Validate, the module's check for the role's REQUIRED members.
func vectorMetadata(in vectorInput) (map[string]any, error) {
	var document interface{ Validate() error }
	switch in.Document {
	case aauth.WellKnownAgent:
		document = &aauth.AgentProviderMetadata{}
	case aauth.WellKnownPerson:
		document = &aauth.PersonServerMetadata{}
	case aauth.WellKnownAccess:
		document = &aauth.AccessServerMetadata{}
	case aauth.WellKnownResource:
		document = &aauth.ResourceMetadata{}
	default:
		return nil, vectorNotOffered("no metadata type for " + in.Document)
	}
	if err := json.Unmarshal([]byte(in.JSON), document); err != nil {
		return map[string]any{"accepted": false, "error": err.Error()}, nil
	}
	if err := document.Validate(); err != nil {
		return map[string]any{"accepted": false, "error": err.Error()}, nil
	}
	return map[string]any{"accepted": true}, nil
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

// vectorJWT verifies the token for its typ with the vector's issuer key pinned.
// The agent-token lifetime ceiling is the module's policy option; it is lifted
// for these long-lived vector tokens, as the module's own vector test does.
func vectorJWT(in vectorInput) (map[string]any, error) {
	var set aauth.JWKS
	if err := json.Unmarshal([]byte(in.JWKS), &set); err != nil {
		return map[string]any{"accepted": false, "stage": "trust", "error": err.Error()}, nil
	}
	resolver := aauth.StaticResolver{in.Issuer: set}
	ctx, clock := context.Background(), vectorClock(in.Now)
	options := aauth.TokenVerifyOptions{Resolver: resolver, Signature: clock}
	var err error
	switch in.Typ {
	case aauth.TypAgent:
		_, err = aauth.VerifyAgentToken(ctx, in.Token, aauth.VerifyAgentTokenOptions{Resolver: resolver, RequireProviderClaims: true, Signature: clock, MaxLifetime: 100 * 365 * 24 * time.Hour})
	case aauth.TypAuth:
		_, err = aauth.VerifyAuthToken(ctx, in.Token, in.Audience, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: options})
	case aauth.TypPerson:
		_, err = aauth.VerifyPersonToken(ctx, in.Token, in.Audience, options)
	case aauth.TypResource:
		return nil, vectorNotOffered("the module exports no standalone resource-token verifier: VerifyResourceToken and VerifyResourceChallenge require the presented token and agent context")
	default:
		return nil, vectorNotOffered("no verifier for typ " + in.Typ)
	}
	if err != nil {
		return vectorRefusal(err), nil
	}
	return map[string]any{"accepted": true}, nil
}

func vectorHTTPSignature(in vectorInput) (map[string]any, error) {
	request, err := vectorBuildRequest(in.Request)
	if err != nil {
		return nil, err
	}
	var key aauth.JWK
	if err := json.Unmarshal(in.Key, &key); err != nil {
		return map[string]any{"accepted": false, "stage": "key", "error": err.Error()}, nil
	}
	public, err := key.PublicKey()
	if err != nil {
		return map[string]any{"accepted": false, "stage": "key", "error": err.Error()}, nil
	}
	options := vectorClock(in.Now)
	options.Window = time.Duration(in.Window) * time.Second
	options.RequiredComponents = in.RequiredComponents
	options.RequireBodyCoverage = in.RequireBodyCoverage
	if err := aauth.VerifyRequestWithOptions(request, public, options); err != nil {
		return vectorRefusal(err), nil
	}
	return map[string]any{"accepted": true}, nil
}
