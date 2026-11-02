package conformance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// bootstrapAPConfig is the launcher bootstrap for the two roles whose SUT is
// an AP: the fixture AP identity and key, and the routes this suite fixes.
func bootstrapAPConfig(f Fixture, b BootstrapFixture, role string) Bootstrap {
	config := Bootstrap{Version: 1, Role: role, Now: f.Now, Issuer: f.Issuer, Resource: f.Issuer + "/.well-known/aauth-agent.json"}
	launcher := bootstrapLauncher{APSeed: f.APSeed, APKid: f.Kid, AgentLifetime: b.AgentLifetime}
	if role == BootstrapSelfHostedRole {
		launcher.IssuePath = b.IssuePath
	} else {
		launcher.EnrollmentPath, launcher.RefreshPath, launcher.SingleKeyRefreshPath, launcher.SubagentPath = b.EnrollmentPath, b.RefreshPath, b.SingleKeyRefreshPath, b.SubagentPath
	}
	config.Extension, _ = json.Marshal(launcher)
	return config
}

func runBootstrapProvider(ctx context.Context, s Suite, targets Targets, o Options, _ string, report Report) Report {
	return runBootstrapRole(ctx, s, targets, o, report, func(f Fixture, b BootstrapFixture, scenario Scenario) (bootstrapCase, error) {
		return bootstrapCase{
			config: func() Bootstrap { return bootstrapAPConfig(f, b, BootstrapProviderRole) },
			run: func(ctx context.Context, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
				return bootstrapProviderCase(ctx, f, b, scenario, ready, o)
			},
		}, nil
	})
}

// hwkRequest is a POST signed under hwk by seed, covering the JSON body.
func hwkRequest(f Fixture, stage, seed, target string, body []byte) (*requestRecord, error) {
	return signEventsRequest(f, stage, seed, http.MethodPost, target, sigkeyMember("sig", "hwk", sigkeyHWKParams(publicJWK(seed))...), body, eventsCovered(true))
}

// namingJWT is the jkt-jwt delegation from the durable key to the ephemeral
// key (Bootstrap Two-Key Refresh step 2; Signature-Key, JKT JWT). The
// mutation breaks one property the AP must verify.
func namingJWT(f Fixture, durable, ephemeral, other, jti, mutation string) string {
	header := map[string]any{"typ": "jkt-s256+jwt", "alg": "Ed25519", "jwk": publicJWK(durable)}
	claims := map[string]any{"iss": "urn:jkt:sha-256:" + thumbprint(durable), "iat": f.Now, "exp": f.Now + 300, "jti": jti, "cnf": map[string]any{"jwk": publicJWK(ephemeral)}}
	switch mutation {
	case "jkt-iss":
		claims["iss"] = "urn:jkt:sha-256:" + thumbprint(other)
	case "jkt-typ":
		header["typ"] = "JWT"
	case "jkt-expired":
		claims["iat"], claims["exp"] = f.Now-600, f.Now-300
	}
	compact := mintJOSE(durable, header, claims)
	if mutation == "jkt-signature" {
		compact = flipSignature(compact)
	}
	return compact
}

// flipSignature changes one byte of a compact JWS signature.
func flipSignature(compact string) string {
	parts := strings.Split(compact, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
	raw[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// refreshRequest is a two-key refresh: the naming JWT under jkt-jwt and an
// HTTP signature by signer (the ephemeral key, unless a mutation changes it).
func refreshRequest(f Fixture, b BootstrapFixture, stage, naming, signer string) (*requestRecord, error) {
	body, _ := json.Marshal(map[string]string{"ps": f.Person.Issuer})
	return signEventsRequest(f, stage, signer, http.MethodPost, f.Issuer+b.RefreshPath, `sig=jkt-jwt;jwt="`+naming+`"`, body, eventsCovered(true))
}

// subagentRequest is a parent's sub-agent request (Bootstrap Sub-Agents Under
// a Hosted AP, step 2): its agent token under jwt, signed by its key, with
// the sub-agent's public key and an optional discriminator in the body.
func subagentRequest(f Fixture, b BootstrapFixture, stage, parentToken, parentSeed, childSeed, discriminator string) (*requestRecord, error) {
	member := map[string]any{"jwk": publicJWK(childSeed)}
	if discriminator != "" {
		member["discriminator"] = discriminator
	}
	body, _ := json.Marshal(member)
	return signEventsRequest(f, stage, parentSeed, http.MethodPost, f.Issuer+b.SubagentPath, `sig=jwt;jwt="`+parentToken+`"`, body, eventsCovered(true))
}

// bootstrapProviderCase runs one hosted-AP flow. Prerequisite stages that
// fail (no parent token for a sub-agent request) are execution errors, so a
// refusal never passes on an AP that issued nothing.
func bootstrapProviderCase(ctx context.Context, f Fixture, b BootstrapFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
	var in bootstrapProviderInput
	DecodeInput(s, &in)
	stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
	keys := fixtureKeys(f.APSeed, f.Kid)
	seed := b.Seeds
	send := func(record *requestRecord, err error) (*Response, error) {
		if err != nil {
			return nil, err
		}
		if err := eventsExchange(ctx, record, ready, o, stages, &exchanges); err != nil {
			return nil, err
		}
		return stages[record.stage], nil
	}
	enroll := func(stage, durable string) error {
		_, err := send(hwkRequest(f, stage, durable, f.Issuer+b.EnrollmentPath, []byte(`{}`)))
		return err
	}
	// refresh sends a two-key refresh and grades the token it returns.
	refresh := func(stage, durable, ephemeral, mutation string, earlier []string) (tokenObservation, error) {
		signer := ephemeral
		if mutation == "proof-key" {
			signer = seed["second_ephemeral"]
		}
		r, err := send(refreshRequest(f, b, stage, namingJWT(f, durable, ephemeral, seed["other_durable"], s.ID+"-"+stage, mutation), signer))
		if err != nil {
			return tokenObservation{}, err
		}
		gradeNoToken(s, stage, r, own)
		token, detail := issuedToken(r)
		reason := ""
		if detail != nil {
			reason = detail.Error()
		}
		observed := observeAgentToken(f, token, tokenExpectation{issuer: f.Issuer, keys: keys, key: seedPublic(ephemeral), ps: f.Person.Issuer, earlier: earlier})
		gradeToken(s, stage, observed, reason, own)
		return observed, nil
	}
	switch in.Flow {
	case "refresh", "rotate", "installs":
		if err := enroll("enroll", seed["durable"]); err != nil {
			return stages, exchanges, own, err
		}
		durable := seed["durable"]
		if in.Mutation == "unenrolled" {
			durable = seed["other_durable"]
		}
		first, err := refresh("refresh", durable, seed["ephemeral"], in.Mutation, nil)
		if err != nil {
			return stages, exchanges, own, err
		}
		if in.Flow == "rotate" {
			second, err := refresh("refresh-2", seed["durable"], seed["second_ephemeral"], "none", nil)
			if err != nil {
				return stages, exchanges, own, err
			}
			second.Properties["same-subject"] = first.subject() != "" && second.subject() == first.subject()
			gradeToken(s, "refresh-2", second, "", own)
		}
		if in.Flow == "installs" {
			if err := enroll("enroll-other", seed["other_durable"]); err != nil {
				return stages, exchanges, own, err
			}
			other, err := refresh("refresh-other", seed["other_durable"], seed["second_ephemeral"], "none", nil)
			if err != nil {
				return stages, exchanges, own, err
			}
			other.Properties["new-subject"] = first.subject() != "" && other.subject() != "" && other.subject() != first.subject()
			gradeToken(s, "refresh-other", other, "", own)
		}
	case "single-key":
		if err := enroll("enroll", seed["durable"]); err != nil {
			return stages, exchanges, own, err
		}
		body, _ := json.Marshal(map[string]string{"ps": f.Person.Issuer})
		r, err := send(hwkRequest(f, "refresh", seed["durable"], f.Issuer+b.SingleKeyRefreshPath, body))
		if err != nil {
			return stages, exchanges, own, err
		}
		token, detail := issuedToken(r)
		reason := ""
		if detail != nil {
			reason = detail.Error()
		}
		observed := observeAgentToken(f, token, tokenExpectation{issuer: f.Issuer, keys: keys, key: seedPublic(seed["durable"]), ps: f.Person.Issuer})
		gradeToken(s, "refresh", observed, reason, own)
	case "subagent":
		var parent string
		parentSeed := seed["ephemeral"]
		switch in.Mutation {
		case "foreign-parent":
			local, _, _ := splitAgentIdentifier(f.Subject)
			parent = mintJOSE(b.ForeignAP.Seed, map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": b.ForeignAP.Kid}, map[string]any{
				"iss": b.ForeignAP.Issuer, "dwk": "aauth-agent.json", "sub": "aauth:" + local + "@" + hostOf(b.ForeignAP.Issuer), "ps": f.Person.Issuer,
				"jti": s.ID + "-parent", "iat": f.Now, "exp": f.Now + b.AgentLifetime, "cnf": map[string]any{"jwk": publicJWK(parentSeed)}})
		case "expired-parent":
			parent = mintJOSE(f.APSeed, map[string]any{"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": f.Kid}, map[string]any{
				"iss": f.Issuer, "dwk": "aauth-agent.json", "sub": f.Subject, "ps": f.Person.Issuer,
				"jti": s.ID + "-parent", "iat": f.Now - 2*b.AgentLifetime, "exp": f.Now - b.AgentLifetime, "cnf": map[string]any{"jwk": publicJWK(parentSeed)}})
		default:
			if err := enroll("enroll", seed["durable"]); err != nil {
				return stages, exchanges, own, err
			}
			observed, err := refresh("refresh", seed["durable"], parentSeed, "none", nil)
			if err != nil {
				return stages, exchanges, own, err
			}
			if !observed.Properties["signature"] {
				return stages, exchanges, own, fmt.Errorf("refresh issued no verifiable parent agent token: %s", strings.Join(observed.Problems, "; "))
			}
			parent = observed.Token
		}
		discriminator := b.Discriminator
		if in.Mutation == "no-discriminator" {
			discriminator = ""
		}
		if in.Mutation == "nested" {
			r, err := send(subagentRequest(f, b, "subagent-1", parent, parentSeed, seed["subagent"], discriminator))
			if err != nil {
				return stages, exchanges, own, err
			}
			child, detail := issuedToken(r)
			if detail != nil {
				return stages, exchanges, own, fmt.Errorf("subagent-1 issued no sub-agent token to nest under: %v", detail)
			}
			gradeToken(s, "subagent-1", observeAgentToken(f, child, tokenExpectation{issuer: f.Issuer, keys: keys, key: seedPublic(seed["subagent"]), parent: unverifiedClaims(parent), discriminator: discriminator}), "", own)
			parent, parentSeed, discriminator = child, seed["subagent"], "nested"
		}
		child := seed["subagent"]
		if in.Mutation == "nested" {
			child = seed["second_ephemeral"]
		}
		r, err := send(subagentRequest(f, b, "subagent", parent, parentSeed, child, discriminator))
		if err != nil {
			return stages, exchanges, own, err
		}
		gradeNoToken(s, "subagent", r, own)
		token, detail := issuedToken(r)
		reason := ""
		if detail != nil {
			reason = detail.Error()
		}
		gradeToken(s, "subagent", observeAgentToken(f, token, tokenExpectation{issuer: f.Issuer, keys: keys, key: seedPublic(child), parent: unverifiedClaims(parent), discriminator: discriminator}), reason, own)
	}
	return stages, exchanges, own, nil
}

func runBootstrapSelf(ctx context.Context, s Suite, targets Targets, o Options, _ string, report Report) Report {
	return runBootstrapRole(ctx, s, targets, o, report, func(f Fixture, b BootstrapFixture, scenario Scenario) (bootstrapCase, error) {
		return bootstrapCase{
			config: func() Bootstrap { return bootstrapAPConfig(f, b, BootstrapSelfHostedRole) },
			run: func(ctx context.Context, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
				return bootstrapSelfCase(ctx, f, b, scenario, ready, o)
			},
		}, nil
	})
}

// bootstrapSelfCase asks the self-hosted AP's token-issuing process for each
// token through the host control, then reads its metadata and JWKS.
func bootstrapSelfCase(ctx context.Context, f Fixture, b BootstrapFixture, s Scenario, ready Ready, o Options) (map[string]*Response, []PersonExchange, map[string]Result, error) {
	var in bootstrapSelfInput
	DecodeInput(s, &in)
	stages, exchanges, own := map[string]*Response{}, []PersonExchange{}, map[string]Result{}
	keys := fixtureKeys(f.APSeed, f.Kid)
	tokens := make([]string, len(in.Issues))
	topLevel := []string{}
	agentKeys := []string{}
	for i, issue := range in.Issues {
		stage := fmt.Sprintf("issue-%d", i+1)
		key := publicJWK(f.APSeed)
		public := seedPublic(f.APSeed)
		if issue.Key != "ap" {
			key, public = publicJWK(b.Seeds[issue.Key]), seedPublic(b.Seeds[issue.Key])
			agentKeys = append(agentKeys, key["x"].(string))
		}
		body := map[string]any{"jwk": key}
		expect := tokenExpectation{issuer: f.Issuer, keys: keys, key: public}
		if issue.Parent == 0 {
			body["agent"] = "aauth:" + issue.Agent + "@" + hostOf(f.Issuer)
			body["ps"] = f.Person.Issuer
			expect.ps, expect.earlier = f.Person.Issuer, topLevel
		} else {
			parent := tokens[issue.Parent-1]
			if parent == "" {
				return stages, exchanges, own, fmt.Errorf("%s: issue-%d issued no parent token", stage, issue.Parent)
			}
			body["parent_token"], body["discriminator"] = parent, issue.Discriminator
			expect.parent, expect.discriminator = unverifiedClaims(parent), issue.Discriminator
		}
		control, err := controlRequest(stage, f.Issuer+b.IssuePath, body)
		if err != nil {
			return stages, exchanges, own, err
		}
		if err := eventsExchange(ctx, control, ready, o, stages, &exchanges); err != nil {
			return stages, exchanges, own, err
		}
		gradeNoToken(s, stage, stages[stage], own)
		token, detail := issuedToken(stages[stage])
		reason := ""
		if detail != nil {
			reason = detail.Error()
		}
		observed := observeAgentToken(f, token, expect)
		gradeToken(s, stage, observed, reason, own)
		if observed.Properties["signature"] {
			tokens[i] = token
			if issue.Parent == 0 {
				topLevel = append(topLevel, observed.subject())
			}
		}
	}
	if !in.Metadata {
		return stages, exchanges, own, nil
	}
	metadata, _ := http.NewRequest(http.MethodGet, f.Issuer+"/.well-known/aauth-agent.json", nil)
	if err := eventsExchange(ctx, &requestRecord{stage: "metadata", request: metadata}, ready, o, stages, &exchanges); err != nil {
		return stages, exchanges, own, err
	}
	var document map[string]any
	json.Unmarshal(stages["metadata"].Body, &document)
	jwksURI, _ := document["jwks_uri"].(string)
	u, err := url.Parse(jwksURI)
	if err != nil || u.Scheme != "https" || u.Host != hostOf(f.Issuer) {
		return stages, exchanges, own, fmt.Errorf("metadata jwks_uri %q is not an HTTPS URL on the AP's origin, which this fixture reaches", jwksURI)
	}
	jwks, _ := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err := eventsExchange(ctx, &requestRecord{stage: "jwks", request: jwks}, ready, o, stages, &exchanges); err != nil {
		return stages, exchanges, own, err
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	json.Unmarshal(stages["jwks"].Body, &set)
	apKey, agentKeyPublished := false, false
	ap := publicJWK(f.APSeed)["x"]
	for _, key := range set.Keys {
		if key["kid"] == f.Kid && key["x"] == ap && key["kty"] == "OKP" && key["crv"] == "Ed25519" && key["alg"] == "Ed25519" {
			apKey = true
		}
		for _, x := range agentKeys {
			agentKeyPublished = agentKeyPublished || key["x"] == x
		}
	}
	properties := map[string]bool{"ap-key": apKey && document["issuer"] == f.Issuer && stages["jwks"].Status == http.StatusOK, "agent-keys-absent": !agentKeyPublished && stages["jwks"].Status == http.StatusOK}
	for _, a := range s.Assertions {
		if a.Kind == "bootstrap-jwks" {
			result := CompareResult(a, properties[a.Member], "")
			result.Actual = set.Keys
			own[a.ID] = result
		}
	}
	return stages, exchanges, own, nil
}
