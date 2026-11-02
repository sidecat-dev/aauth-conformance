package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Remote mode for sigkey.verifier. The deployment names its verifier
// Resource as resource. The suite is the Agent, the Agent Provider, the
// jwks_uri and self-jwt signer, and the host of the direct JWKS URL, and it
// serves their documents for the whole run.
//
// A launcher is started afresh for each case, but a deployed verifier keeps
// what it discovered. The cases that vary a party's key set (a mixed or a
// post-quantum-only set) therefore use a party of their own: the fixture
// Agent Provider or signer under a name with the variant added to its first
// label, such as ap-mixed.conformance.test. Every other case discovers the
// same documents, so a cached copy is the copy the case expects.
func init() {
	registerRemote(SigkeyVerifierRole, remoteDriver{
		requires: []string{partyResource},
		parties:  sigkeyRemoteParties,
		fixture: func(base Fixture, _ Scenario, r *RemoteRun) Fixture {
			f := base
			f.Now, f.Skew = time.Now().Unix(), r.Skew
			return f
		},
		run: runRemoteSigkeyCase,
	})
}

// sigkeyVariants are the key-set variants a verifier case may name.
var sigkeyVariants = []string{"mixed", "pq-only"}

// sigkeyVariantIssuer names the party that publishes a variant key set: the
// fixture issuer with the variant added to its first label.
func sigkeyVariantIssuer(issuer, variant string) string {
	u, err := url.Parse(issuer)
	if err != nil || variant == "" {
		return issuer
	}
	first, rest, _ := strings.Cut(u.Host, ".")
	return "https://" + first + "-" + variant + "." + rest
}

// sigkeyVariantKeys is a variant key set: the classical key and, for mixed,
// the post-quantum key beside it, or the post-quantum key alone. Without
// ML-DSA-44 support the set holds no post-quantum key; such a case reports
// the missing support as an execution error, as a launcher run does.
func sigkeyVariantKeys(classical sigkeyKey, kid, pqKid string, pq sigkeyKey, pqErr error, variant string) keySet {
	keys := keySet{}
	if variant == "mixed" {
		keys[kid] = classical.public
	}
	if pqErr == nil {
		keys[pqKid] = pq.public
	}
	return keys
}

// sigkeyRemoteParties are the signer, the direct JWKS host and the variant
// Agent Providers and signers. The fixture Agent Provider is a core party.
func sigkeyRemoteParties(f Fixture) []harnessParty {
	k, err := sigkeyFixture(f)
	if err != nil {
		return nil
	}
	jwks, _ := url.Parse(k.JWKSURL)
	parties := []harnessParty{
		party(k.Signer.Issuer, k.Signer.DWK, k.Signer.Seed, k.Signer.Kid),
		{issuer: "https://" + jwks.Host},
	}
	pq, pqErr := sigkeyMLDSA44(k.PQSeed)
	for _, variant := range sigkeyVariants {
		parties = append(parties,
			harnessParty{issuer: sigkeyVariantIssuer(f.Issuer, variant), document: "aauth-agent.json",
				keys: sigkeyVariantKeys(sigkeyEd25519(f.APSeed), f.Kid, k.APPQKid, pq, pqErr, variant)},
			harnessParty{issuer: sigkeyVariantIssuer(k.Signer.Issuer, variant), document: k.Signer.DWK,
				keys: sigkeyVariantKeys(sigkeyEd25519(k.Signer.Seed), k.Signer.Kid, k.PQKid, pq, pqErr, variant)})
	}
	return parties
}

// sigkeyRemoteFixture rebases one case onto the deployment: the deployed
// verifier, and the variant party for a case that names a key set.
func sigkeyRemoteFixture(f Fixture, k SigkeyFixture, in sigkeyVerifierInput, verifier string) (Fixture, SigkeyFixture) {
	k.Verifier = verifier
	switch {
	case in.JWKS != "" && in.Scheme == "jwt":
		f.Issuer = sigkeyVariantIssuer(f.Issuer, in.JWKS)
		local, _, _ := strings.Cut(f.Subject, "@")
		f.Subject = local + "@" + strings.TrimPrefix(f.Issuer, "https://")
	case in.JWKS != "" && in.Scheme == "jwks_uri":
		k.Signer.Issuer = sigkeyVariantIssuer(k.Signer.Issuer, in.JWKS)
	}
	return f, k
}

func runRemoteSigkeyCase(ctx context.Context, f Fixture, s Scenario, t Target, o Options) Case {
	c := Case{ID: s.ID}
	offered := sigkeyOffered(s, t)
	var response *Response
	execution := ""
	if offered {
		response, execution = remoteSigkeyExchange(ctx, f, s, o, &c)
	}
	return sigkeyGrade(c, s, t, offered, response, execution)
}

func remoteSigkeyExchange(ctx context.Context, f Fixture, s Scenario, o Options, c *Case) (*Response, string) {
	remote := remoteFrom(ctx)
	k, err := sigkeyFixture(f)
	if err != nil {
		return nil, err.Error()
	}
	if remote == nil || remote.Harness == nil {
		return nil, "remote mode needs the suite's harness"
	}
	var in sigkeyVerifierInput
	DecodeInput(s, &in)
	if in.JWKS != "" {
		if _, err := sigkeyMLDSA44(k.PQSeed); err != nil {
			return nil, err.Error()
		}
	}
	f, k = sigkeyRemoteFixture(f, k, in, remote.Role.Resource)
	// The direct JWKS URL is a path, not a metadata document, so the case
	// serves it itself; its content is the same for every case.
	key := sigkeyCloneJWK(sigkeyEd25519(k.Signer.Seed).public, "kid", k.Signer.Kid)
	set, _ := json.Marshal(map[string]any{"keys": []any{key}})
	defer remote.Harness.Handle(k.JWKSURL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(set)))
		w.Write(set)
	}))()
	record, err := sigkeyVerifierRequest(f, k, s)
	if err != nil {
		return nil, err.Error()
	}
	c.Method, c.URL, c.Headers, c.SignatureBase, c.RequestBody = record.request.Method, record.request.URL.String(), record.request.Header.Clone(), record.base, record.body
	response, err := Exchange(ctx, record.request, "", o.Timeout)
	if err != nil {
		return nil, err.Error()
	}
	return &response, ""
}
