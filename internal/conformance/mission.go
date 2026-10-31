package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// Mission roles exercise the Protocol draft's Mission section. The harness
// plays the Agent Provider, the owning Agent, a second Agent and the Resource;
// the native Person Server owns every mission decision and response.
const MissionServerRole = "mission.person-server"
const MissionResourceRole = "mission.resource"

// MissionFixture is fixture.json extensions.missions.
type MissionFixture struct {
	OtherSeed    string `json:"other_agent_seed_hex"`
	OtherSubject string `json:"other_agent_subject"`
	Description  string `json:"description"`
}

// MissionInput is a mission scenario's input.
type MissionInput struct {
	Flow      string `json:"flow"`
	ExpiresIn int64  `json:"expires_in,omitempty"`
}

// Each flow names the stages it observes, in exchange order.
var missionFlows = map[string][]string{
	"approval":          {"metadata", "proposal", "approval", "read"},
	"person-token":      {"approval", "person"},
	"unknown-mission":   {"approval", "unknown"},
	"malformed-mission": {"approval", "malformed"},
	"other-agent":       {"approval", "other"},
	"action-missing":    {"approval", "action"},
	"action-unknown":    {"approval", "action"},
	"not-owned":         {"approval", "not-owned", "unknown"},
	"update":            {"approval", "action", "person"},
	"completion":        {"approval", "action", "after-update", "after-completion", "after-person"},
	"completion-token":  {"approval", "person", "before-token", "action", "after-token"},
	"expiry":            {"approval", "person", "after-person", "after-update"},
	"governance":        {"approval", "before-permission", "before-audit", "action", "after-permission", "after-audit"},
}

// The stage each role-specific kind observes; "" means any refusal stage.
var missionKindStages = map[string][]string{
	"mission-endpoint-url":  {"metadata"},
	"mission-s256":          {"approval"},
	"mission-encoded":       {"approval"},
	"mission-blob":          {"approval"},
	"mission-served":        {"read"},
	"mission-person-token":  {"person"},
	"mission-person-exp":    {"person"},
	"mission-equivalent":    {"not-owned"},
	"mission-no-token":      {"unknown", "malformed", "other", "after-person", "after-token"},
	"mission-resource-copy": {"challenge"},
}

func init() {
	kinds := []string{}
	for kind := range missionKindStages {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	RegisterRole(MissionServerRole, ExtensionRole{Kinds: kinds, Validate: validateMissionScenario, Run: runMissionServers})
	RegisterRole(MissionResourceRole, ExtensionRole{Kinds: kinds, Validate: validateMissionScenario, Run: runMissionResources})
}

func validateMissionScenario(f Fixture, s Scenario) error {
	var in MissionInput
	if err := DecodeInput(s, &in); err != nil {
		return err
	}
	if f.Person == nil || f.Access == nil {
		return fmt.Errorf("%s: mission roles need the person_server and access_server fixtures", s.ID)
	}
	var mf MissionFixture
	if err := DecodeExtension(f, "missions", &mf); err != nil {
		return err
	}
	if !validSeed(mf.OtherSeed) || mf.OtherSeed == f.AgentSeed || !strings.HasPrefix(mf.OtherSubject, "aauth:") || mf.OtherSubject == f.Subject || mf.Description == "" {
		return fmt.Errorf("invalid missions fixture")
	}
	stages, ok := missionFlows[in.Flow]
	if s.Role == MissionResourceRole {
		stages, ok = []string{"challenge"}, in.Flow == "resource-copy"
	}
	if !ok {
		return fmt.Errorf("%s: unsupported mission flow %q for %s", s.ID, in.Flow, s.Role)
	}
	if (in.Flow == "expiry") != (in.ExpiresIn > 0) || in.ExpiresIn > 50 {
		return fmt.Errorf("%s: expires_in (1..50 seconds) belongs to the expiry flow only", s.ID)
	}
	if s.Token.IATOffset != 0 || s.Token.EXPOffset != 0 {
		return fmt.Errorf("%s: mission Agent tokens are prescribed by the driver", s.ID)
	}
	for _, a := range s.Assertions {
		if !slices.Contains(stages, a.Stage) {
			return fmt.Errorf("%s/%s: stage %q is not observed by flow %s", s.ID, a.ID, a.Stage, in.Flow)
		}
		if allowed, own := missionKindStages[a.Kind]; own {
			var b any
			json.Unmarshal(a.Equals, &b)
			if _, isBool := b.(bool); !isBool || !slices.Contains(allowed, a.Stage) {
				return fmt.Errorf("%s/%s: %s needs a boolean and one of stages %v", s.ID, a.ID, a.Kind, allowed)
			}
		}
	}
	return nil
}

// missionApproval is the harness's independent reading of an approval response.
type missionApproval struct {
	S256    string         `json:"s256"`
	Encoded string         `json:"mission"`
	Bytes   []byte         `json:"-"`
	Blob    map[string]any `json:"blob,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func readMissionApproval(r Response) missionApproval {
	var body struct {
		S256    *string `json:"s256"`
		Mission *string `json:"mission"`
	}
	var a missionApproval
	if r.Status != 200 || json.Unmarshal(r.Body, &body) != nil || body.S256 == nil || body.Mission == nil {
		a.Error = fmt.Sprintf("approval is not a 200 JSON object with s256 and mission (HTTP %d)", r.Status)
		return a
	}
	a.S256, a.Encoded = *body.S256, *body.Mission
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(a.Encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != a.Encoded {
		a.Error = "mission is not unpadded base64url"
		return a
	}
	a.Bytes = decoded
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	if err := decoder.Decode(&a.Blob); err != nil || decoder.More() {
		a.Blob = nil
		a.Error = "mission does not decode to one JSON object"
	}
	return a
}

func missionDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// expiresAt returns the blob's expires_at as Unix seconds, if it carries one.
func (a missionApproval) expiresAt() (int64, bool) {
	text, ok := a.Blob["expires_at"].(string)
	if !ok {
		return 0, false
	}
	at, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return 0, false
	}
	return at.Unix(), true
}

type missionDriver struct {
	ctx      context.Context
	f        Fixture
	p        PersonFixture
	mf       MissionFixture
	s        Scenario
	in       MissionInput
	physical string
	timeout  time.Duration
	c        *Case
	clock    int64
	// responses holds the native response observed at each stage, and at
	// the host clock in force when it was observed.
	responses map[string]Response
	at        map[string]int64
	approval  missionApproval
	endpoints map[string]string
	skipped   string
}

func (d *missionDriver) agentToken(seed, subject, id string) (string, error) {
	return mintJWT(d.f.APSeed, d.f.Kid, "aa-agent+jwt", map[string]any{
		"iss": d.f.Issuer, "dwk": "aauth-agent.json", "sub": subject, "jti": d.s.ID + "-" + id,
		"iat": d.f.Now - 10, "exp": d.f.Now + 600, "ps": d.p.Issuer,
		"cnf": map[string]any{"jwk": publicJWK(seed)},
	})
}

func (d *missionDriver) exchange(stage string, request *http.Request, base string) (Response, error) {
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	entry := PersonExchange{Stage: stage, Method: request.Method, URL: request.URL.String(), Headers: request.Header.Clone(), Body: body, SignatureBase: base}
	response, err := Exchange(d.ctx, request, d.physical, d.timeout)
	if err != nil {
		entry.Error = err.Error()
	} else {
		entry.Response = &response
		if stage != "control" {
			d.responses[stage] = response
			d.at[stage] = d.clock
		}
	}
	d.c.Exchanges = append(d.c.Exchanges, entry)
	return response, err
}

// signed sends one request signed by the fixture Agent key seed under the
// jwt scheme. A JSON body is covered with Content-Type and Content-Digest.
func (d *missionDriver) signed(stage, seed, token, method, target string, body any) (Response, error) {
	var encoded []byte
	if body != nil {
		var err error
		if encoded, err = json.Marshal(body); err != nil {
			return Response{}, err
		}
	}
	request, base, err := signedFixtureRequest(d.f, seed, method, target, `sig=jwt;jwt="`+token+`"`, encoded)
	if err != nil {
		return Response{}, err
	}
	return d.exchange(stage, request, base)
}

// control applies a host input: policy, approval, clock or record installation.
// A control response is never a protocol observation.
func (d *missionDriver) control(body map[string]any) error {
	encoded, _ := json.Marshal(body)
	request, err := http.NewRequest("POST", d.p.Issuer+"/__fixture/mission", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := d.exchange("control", request, "")
	if err != nil {
		return err
	}
	if response.Status != 200 {
		return fmt.Errorf("host control %s returned HTTP %d: %s", encoded, response.Status, response.Body)
	}
	if offset, ok := body["now_offset"].(int64); ok {
		d.clock = d.f.Now + offset
	}
	return nil
}

func (d *missionDriver) endpoint(name string) (string, error) {
	value := d.endpoints[name]
	u, err := url.Parse(value)
	if value == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("Person Server metadata names no usable %s", name)
	}
	return value, nil
}

func (d *missionDriver) run() error {
	metadataRequest, _ := http.NewRequest("GET", d.p.Issuer+"/.well-known/aauth-person.json", nil)
	metadata, err := d.exchange("metadata", metadataRequest, "")
	if err != nil {
		return err
	}
	var document map[string]any
	if json.Unmarshal(metadata.Body, &document) != nil {
		return fmt.Errorf("Person Server metadata is not JSON (HTTP %d)", metadata.Status)
	}
	d.endpoints = map[string]string{}
	for _, name := range []string{"mission_endpoint", "person_token_endpoint", "auth_token_endpoint", "permission_endpoint", "audit_endpoint"} {
		d.endpoints[name], _ = document[name].(string)
	}
	missionEndpoint, err := d.endpoint("mission_endpoint")
	if err != nil {
		return err
	}
	owner, err := d.agentToken(d.f.AgentSeed, d.f.Subject, "owner")
	if err != nil {
		return err
	}
	if d.in.ExpiresIn > 0 {
		if err := d.control(map[string]any{"expires_in": d.in.ExpiresIn}); err != nil {
			return err
		}
	}
	proposal, err := d.signed("proposal", d.f.AgentSeed, owner, "POST", missionEndpoint, map[string]any{
		"description": d.mf.Description, "resources": []string{d.f.Origin},
	})
	if err != nil {
		return err
	}
	switch proposal.Status {
	case 200:
		d.responses["approval"] = proposal
	case 202:
		base, _ := url.Parse(missionEndpoint)
		location, err := base.Parse(proposal.Header.Get("Location"))
		if err != nil || proposal.Header.Get("Location") == "" || location.Scheme+"://"+location.Host != d.p.Issuer {
			return fmt.Errorf("deferred mission proposal has no same-origin Location")
		}
		// The person's approval is a host input; the Agent then polls for it.
		if err := d.control(map[string]any{"approve": location.String()}); err != nil {
			return err
		}
		if _, err := d.signed("approval", d.f.AgentSeed, owner, "GET", location.String(), nil); err != nil {
			return err
		}
	default:
		return fmt.Errorf("mission proposal returned HTTP %d", proposal.Status)
	}
	d.approval = readMissionApproval(d.responses["approval"])
	if d.approval.Error != "" {
		return fmt.Errorf("cannot advance from the approval: %s", d.approval.Error)
	}
	// The host records the person's approval for issuance. A library whose
	// native approval already retains it answers without changing state.
	if err := d.control(map[string]any{"install": map[string]any{"s256": d.approval.S256, "agent": d.f.Subject}}); err != nil {
		return err
	}
	missionURL := missionEndpoint + "/" + d.approval.S256
	other, err := d.agentToken(d.mf.OtherSeed, d.mf.OtherSubject, "other")
	if err != nil {
		return err
	}
	person := func(stage, seed, token, mission string) (Response, error) {
		target, err := d.endpoint("person_token_endpoint")
		if err != nil {
			return Response{}, err
		}
		return d.signed(stage, seed, token, "POST", target, map[string]any{"resource": d.f.Origin, "mission_s256": mission})
	}
	unknown := missionDigest([]byte("conformance unknown mission " + d.s.ID))
	update := map[string]any{"action": "update", "description": "The March totals need the late credit notes."}
	completion := map[string]any{"action": "completion", "summary": "Reconciled the March invoices and reported the totals."}
	switch d.in.Flow {
	case "approval":
		_, err = d.signed("read", d.f.AgentSeed, owner, "GET", missionURL, nil)
	case "person-token":
		_, err = person("person", d.f.AgentSeed, owner, d.approval.S256)
	case "unknown-mission":
		_, err = person("unknown", d.f.AgentSeed, owner, unknown)
	case "malformed-mission":
		_, err = person("malformed", d.f.AgentSeed, owner, "not-a-mission-digest")
	case "other-agent":
		_, err = person("other", d.mf.OtherSeed, other, d.approval.S256)
	case "action-missing":
		_, err = d.signed("action", d.f.AgentSeed, owner, "POST", missionURL, map[string]any{"description": "The work changed."})
	case "action-unknown":
		_, err = d.signed("action", d.f.AgentSeed, owner, "POST", missionURL, map[string]any{"action": "pause", "description": "The work changed."})
	case "not-owned":
		if _, err = d.signed("not-owned", d.mf.OtherSeed, other, "POST", missionURL, update); err == nil {
			_, err = d.signed("unknown", d.mf.OtherSeed, other, "POST", missionEndpoint+"/"+unknown, update)
		}
	case "update":
		if _, err = d.signed("action", d.f.AgentSeed, owner, "POST", missionURL, update); err == nil {
			_, err = person("person", d.f.AgentSeed, owner, d.approval.S256)
		}
	case "completion":
		var personURL string
		if personURL, err = d.endpoint("person_token_endpoint"); err == nil {
			err = d.steps(owner, []missionStep{
				{"action", missionURL, completion}, {"after-update", missionURL, update},
				{"after-completion", missionURL, completion},
				{"after-person", personURL, map[string]any{"resource": d.f.Origin, "mission_s256": d.approval.S256}},
			})
		}
	case "completion-token":
		err = d.completionToken(owner, missionURL, completion, person)
	case "expiry":
		err = d.expiry(owner, missionURL, update, person)
	case "governance":
		err = d.governance(owner, missionURL, completion)
	}
	return err
}

// resourceToken mints the fixture Resource's challenge for a presented
// mission-bound person token, as the Resource would issue it.
func (d *missionDriver) resourceToken(claims map[string]any, id string) (string, error) {
	return mintJWT(d.p.ResourceSeed, d.p.ResourceKid, "aa-resource+jwt", map[string]any{
		"iss": d.f.Origin, "dwk": "aauth-resource.json", "aud": d.p.Issuer, "ps": d.p.Issuer,
		"sub": claims["sub"], "presented_jti": claims["jti"], "agent_jkt": thumbprint(d.f.AgentSeed),
		"jti": d.s.ID + "-" + id, "iat": d.f.Now - 1, "exp": d.f.Now + 120, "scope": "read",
		"mission_s256": d.approval.S256,
	})
}

func (d *missionDriver) completionToken(owner, missionURL string, completion map[string]any, person func(string, string, string, string) (Response, error)) error {
	response, err := person("person", d.f.AgentSeed, owner, d.approval.S256)
	if err != nil {
		return err
	}
	presented, claims, err := d.personToken(response, d.clock)
	if err != nil {
		return fmt.Errorf("cannot build a Resource token without a mission-bound person token: %w", err)
	}
	target, err := d.endpoint("auth_token_endpoint")
	if err != nil {
		return err
	}
	for _, step := range []struct{ stage, id string }{{"before-token", "resource-1"}, {"action", ""}, {"after-token", "resource-2"}} {
		if step.stage == "action" {
			if _, err := d.signed("action", d.f.AgentSeed, owner, "POST", missionURL, completion); err != nil {
				return err
			}
			continue
		}
		resource, err := d.resourceToken(claims, step.id)
		if err != nil {
			return err
		}
		if _, err := d.signed(step.stage, d.f.AgentSeed, owner, "POST", target, map[string]any{"resource_token": resource, "presented_token": presented}); err != nil {
			return err
		}
	}
	return nil
}

func (d *missionDriver) expiry(owner, missionURL string, update map[string]any, person func(string, string, string, string) (Response, error)) error {
	expires, ok := d.approval.expiresAt()
	if !ok {
		d.skipped = "the approved mission carries no expires_at: the host approval policy asked for one but the native approval did not set it"
		return nil
	}
	if _, err := person("person", d.f.AgentSeed, owner, d.approval.S256); err != nil {
		return err
	}
	if err := d.control(map[string]any{"now_offset": expires - d.f.Now + 1}); err != nil {
		return err
	}
	if _, err := person("after-person", d.f.AgentSeed, owner, d.approval.S256); err != nil {
		return err
	}
	_, err := d.signed("after-update", d.f.AgentSeed, owner, "POST", missionURL, update)
	return err
}

func (d *missionDriver) governance(owner, missionURL string, completion map[string]any) error {
	permission, err := d.endpoint("permission_endpoint")
	if err != nil {
		return err
	}
	audit, err := d.endpoint("audit_endpoint")
	if err != nil {
		return err
	}
	permit := map[string]any{"action": "SendSummary", "description": "Send the totals to the person.", "mission_s256": d.approval.S256}
	record := map[string]any{"action": "WebSearch", "description": "Looked up the March credit notes.", "mission_s256": d.approval.S256}
	return d.steps(owner, []missionStep{
		{"before-permission", permission, permit}, {"before-audit", audit, record}, {"action", missionURL, completion},
		{"after-permission", permission, permit}, {"after-audit", audit, record},
	})
}

// missionStep is one owner-signed JSON POST observed at stage.
type missionStep struct {
	stage, target string
	body          map[string]any
}

func (d *missionDriver) steps(owner string, steps []missionStep) error {
	for _, step := range steps {
		if _, err := d.signed(step.stage, d.f.AgentSeed, owner, "POST", step.target, step.body); err != nil {
			return err
		}
	}
	return nil
}

// personToken independently verifies a native person-token response
// observed when the host clock read at.
func (d *missionDriver) personToken(r Response, at int64) (string, map[string]any, error) {
	compact, err := responseToken(r, "person_token")
	if err != nil {
		return "", nil, err
	}
	_, claims, err := verifyJWT(compact, d.p.Seed, d.p.Kid, "aa-person+jwt")
	if err != nil {
		return "", nil, err
	}
	key, _ := claims["cnf"].(map[string]any)
	jwk, _ := key["jwk"].(map[string]any)
	exp, _ := claims["exp"].(float64)
	switch {
	case claims["iss"] != d.p.Issuer:
		return "", nil, fmt.Errorf("person token iss is not this Person Server")
	case !audienceNames(claims["aud"], d.f.Origin):
		return "", nil, fmt.Errorf("person token aud does not name the Resource")
	case jwk == nil || jwk["x"] != publicJWK(d.f.AgentSeed)["x"]:
		return "", nil, fmt.Errorf("person token is not bound to the requesting Agent's key")
	case int64(exp) <= at:
		return "", nil, fmt.Errorf("person token is already expired")
	}
	return compact, claims, nil
}

func audienceNames(aud any, want string) bool {
	switch value := aud.(type) {
	case string:
		return value == want
	case []any:
		return len(value) == 1 && value[0] == want
	}
	return false
}

func noCredentialMember(r Response) bool {
	var body map[string]json.RawMessage
	if json.Unmarshal(r.Body, &body) != nil {
		return true
	}
	_, person := body["person_token"]
	_, auth := body["auth_token"]
	return !person && !auth
}

func (d *missionDriver) check(a Assertion) Result {
	r := d.responses[a.Stage]
	switch a.Kind {
	case "mission-endpoint-url":
		u, err := url.Parse(d.endpoints["mission_endpoint"])
		ok := err == nil && u.Scheme == "https" && u.Host != "" && u.RawQuery == "" && !u.ForceQuery && !strings.Contains(d.endpoints["mission_endpoint"], "#")
		return CompareResult(a, ok, d.endpoints["mission_endpoint"])
	case "mission-s256":
		return CompareResult(a, d.approval.Bytes != nil && missionDigest(d.approval.Bytes) == d.approval.S256, d.approval.Error)
	case "mission-encoded":
		return CompareResult(a, d.approval.Bytes != nil, d.approval.Error)
	case "mission-blob":
		description, _ := d.approval.Blob["description"].(string)
		approved, _ := d.approval.Blob["approved_at"].(string)
		_, timeErr := time.Parse(time.RFC3339, approved)
		ok := d.approval.Blob["agent"] == d.f.Subject && timeErr == nil && description != ""
		return CompareResult(a, ok, fmt.Sprintf("agent %v, approved_at %q, description present %v", d.approval.Blob["agent"], approved, description != ""))
	case "mission-served":
		var body struct {
			Mission *string `json:"mission"`
		}
		if r.Status != 200 || json.Unmarshal(r.Body, &body) != nil || body.Mission == nil {
			return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: fmt.Sprintf("the PS does not expose the mission to its owner at its URL (HTTP %d)", r.Status)}
		}
		return CompareResult(a, *body.Mission == d.approval.Encoded, "mission bytes served later differ from the approval")
	case "mission-person-token":
		_, claims, err := d.personToken(r, d.at[a.Stage])
		if err != nil {
			return CompareResult(a, false, err.Error())
		}
		return CompareResult(a, claims["mission_s256"] == d.approval.S256, fmt.Sprintf("mission_s256 %v", claims["mission_s256"]))
	case "mission-person-exp":
		expires, ok := d.approval.expiresAt()
		if !ok {
			return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: "the approved mission carries no expires_at"}
		}
		_, claims, err := d.personToken(r, d.at[a.Stage])
		if err != nil {
			return CompareResult(a, false, err.Error())
		}
		exp, _ := claims["exp"].(float64)
		return CompareResult(a, int64(exp) <= expires, fmt.Sprintf("person token exp %d, mission expires_at %d", int64(exp), expires))
	case "mission-no-token":
		return CompareResult(a, noCredentialMember(r), "")
	case "mission-equivalent":
		same, detail := equivalentResponses(d.responses["not-owned"], d.responses["unknown"])
		return CompareResult(a, same, detail)
	case "mission-resource-copy":
		resource, err := challengedResourceToken(r)
		if err != nil {
			return CompareResult(a, false, err.Error())
		}
		_, claims, err := verifyJWT(resource, d.p.ResourceSeed, d.p.ResourceKid, "aa-resource+jwt")
		if err != nil {
			return CompareResult(a, false, err.Error())
		}
		return CompareResult(a, claims["mission_s256"] == d.approval.S256, fmt.Sprintf("resource token mission_s256 %v", claims["mission_s256"]))
	}
	return Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail", Detail: "unknown mission assertion"}
}

// equivalentResponses compares status, body bytes and the set of header
// names, leaving out Date, which the server clock sets.
func equivalentResponses(a, b Response) (bool, string) {
	names := func(r Response) []string {
		list := []string{}
		for name := range r.Header {
			if !strings.EqualFold(name, "Date") {
				list = append(list, http.CanonicalHeaderKey(name))
			}
		}
		sort.Strings(list)
		return list
	}
	switch {
	case a.Status != b.Status:
		return false, fmt.Sprintf("status %d versus %d", a.Status, b.Status)
	case !bytes.Equal(a.Body, b.Body):
		return false, fmt.Sprintf("body %q versus %q", a.Body, b.Body)
	case !slices.Equal(names(a), names(b)):
		return false, fmt.Sprintf("headers %v versus %v", names(a), names(b))
	}
	return true, ""
}

func (d *missionDriver) grade(target Target, executionError string) {
	for _, a := range d.s.Assertions {
		response, observed := d.responses[a.Stage]
		var result Result
		switch {
		case !slices.Contains(target.Claims, a.Clause):
			result = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_claimed"}
		case !observed && d.skipped != "" && executionError == "":
			result = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "not_exercised", Detail: d.skipped}
		case !observed:
			detail := executionError
			if detail == "" {
				detail = "stage " + a.Stage + " was not reached"
			}
			result = Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "error", Detail: detail}
		default:
			result = Grade(a, target.Claims, "", &response, d.check)
		}
		d.c.Results = append(d.c.Results, result)
	}
}

func missionBootstrap(f Fixture, role, ap string) Bootstrap {
	p, a := *f.Person, *f.Access
	return Bootstrap{
		Version: 1, Role: role, Now: f.Now, Issuer: f.Issuer, Resource: f.Origin + f.Path, APTransport: ap,
		PersonServer: p.Issuer, PersonSeed: p.Seed, PersonKid: p.Kid, PersonSubject: p.Subject,
		PersonLifetime: p.Lifetime, AuthLifetime: p.AuthLifetime, PermittedScopes: p.PermittedScopes,
		ResourceKid: p.ResourceKid, ResourceJWK: publicJWK(p.ResourceSeed), ResourceSeed: p.ResourceSeed,
		AccessServer: a.Issuer, AccessSeed: a.Seed, AccessKid: a.Kid,
	}
}

// Each scenario starts a fresh native bundle, so termination, clock changes
// and retained missions never cross scenarios.
func runMissionCases(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report, prepare func(*Bootstrap) func(), drive func(*missionDriver) error) Report {
	var mf MissionFixture
	DecodeExtension(s.Fixture, "missions", &mf)
	for _, target := range targets.Implementations {
		run := Run{Target: target}
		for _, scenario := range s.Scenarios {
			c := Case{ID: scenario.ID}
			var in MissionInput
			DecodeInput(scenario, &in)
			d := &missionDriver{ctx: ctx, f: s.Fixture, p: *s.Fixture.Person, mf: mf, s: scenario, in: in, timeout: options.Timeout, c: &c, clock: s.Fixture.Now, responses: map[string]Response{}, at: map[string]int64{}}
			config := missionBootstrap(s.Fixture, scenario.Role, ap)
			cleanup := prepare(&config)
			ready, stop, err := startAdapter(ctx, target, config, options)
			if err == nil {
				d.physical = ready.URL
				err = drive(d)
				stop()
			}
			cleanup()
			executionError := ""
			if err != nil {
				executionError = err.Error()
				c.Error = executionError
			}
			c.Evidence = map[string]any{"flow": in.Flow, "approval": d.approval, "not_exercised": d.skipped}
			d.grade(target, executionError)
			run.Cases = append(run.Cases, c)
		}
		report.Runs = append(report.Runs, run)
	}
	return report
}

func runMissionServers(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	return runMissionCases(ctx, s, targets, options, ap, report, func(*Bootstrap) func() { return func() {} }, (*missionDriver).run)
}

// The Resource role runs the four-party native bundle. No Access Server
// exchange happens, so its federation transport refuses everything.
func runMissionResources(ctx context.Context, s Suite, targets Targets, options Options, ap string, report Report) Report {
	prepare := func(config *Bootstrap) func() {
		refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no Access Server exchange in this slice", http.StatusBadGateway)
		}))
		config.FederationTransport = refuse.URL
		return refuse.Close
	}
	return runMissionCases(ctx, s, targets, options, ap, report, prepare, (*missionDriver).resourceCopy)
}

// resourceCopy presents a harness-issued person token that names a mission
// and reads the native Resource's challenge for it.
func (d *missionDriver) resourceCopy() error {
	d.approval = missionApproval{S256: missionDigest([]byte("conformance Resource mission " + d.s.ID))}
	person, err := mintJWT(d.p.Seed, d.p.Kid, "aa-person+jwt", map[string]any{
		"iss": d.p.Issuer, "dwk": "aauth-person.json", "aud": d.f.Origin, "sub": d.p.Subject,
		"jti": "harness-" + d.s.ID, "cnf": map[string]any{"jwk": publicJWK(d.f.AgentSeed)},
		"iat": d.f.Now, "exp": d.f.Now + d.p.Lifetime, "mission_s256": d.approval.S256,
	})
	if err != nil {
		return err
	}
	_, err = d.signed("challenge", d.f.AgentSeed, person, "GET", d.f.Origin+d.f.Path, nil)
	return err
}
