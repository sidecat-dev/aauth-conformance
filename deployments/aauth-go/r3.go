// R3 roles for remote mode: an R3 Resource of each topology, a three-party
// Person Server issuing R3 Auth tokens, and a four-party Person Server and
// Access Server issuing them together. Names come from the roles file
// (deployments/roles/r3.json):
//
//	r3_resource                 four-party R3 Resource; its Access Server is suite_access_server
//	r3_direct_resource          three-party R3 Resource; its Person Servers are person_servers
//	r3_person_server            three-party Person Server issuing R3 Auth tokens
//	r3_federated_person_server  four-party Person Server federating with r3_access_server
//	r3_access_server            Access Server issuing four-party R3 Auth tokens
//
// Policy follows the remote mode test profile: the person directed-person-1,
// the read scope, the MCP tools records.read, records.export and
// records.delete, of which records.read and records.export are granted.
// GET /r3.resource/__fixture/r3/executions on the control origin reports
// how often each tool executed, across both Resources.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

var (
	r3Tools     = []string{"records.read", "records.export", "records.delete"}
	r3Grantable = []string{"records.read", "records.export"}
)

func init() { extensions = append(extensions, r3Roles) }

func r3Roles(e env) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{}
	names := e.c.Names
	executions := &r3Executions{counts: map[string]int{}}
	for _, topology := range []string{"four-party", "three-party"} {
		name := names["r3_resource"]
		if topology == "three-party" {
			name = names["r3_direct_resource"]
		}
		if name == "" {
			continue
		}
		handler, err := r3Resource(e, name, topology, executions)
		if err != nil {
			return nil, err
		}
		handlers[name] = handler
	}
	if names["r3_resource"] != "" || names["r3_direct_resource"] != "" {
		e.controls.HandleFunc("GET /r3.resource/__fixture/r3/executions", func(w http.ResponseWriter, _ *http.Request) { executions.serve(w) })
	}
	if name := names["r3_person_server"]; name != "" {
		handler, err := r3Issuer(e, name)
		if err != nil {
			return nil, err
		}
		handlers[name] = handler
	}
	if names["r3_federated_person_server"] != "" && names["r3_access_server"] != "" {
		person, access, err := r3FederatedIssuer(e, names["r3_federated_person_server"], names["r3_access_server"])
		if err != nil {
			return nil, err
		}
		handlers[names["r3_federated_person_server"]], handlers[names["r3_access_server"]] = person, access
	}
	return handlers, nil
}

// r3Admit admits R3 document fetches from the suite's Resources only.
func r3Admit(e env) func(context.Context, string) error {
	return func(_ context.Context, endpoint string) error {
		for _, origin := range e.c.Resources {
			if strings.HasPrefix(endpoint, origin+"/r3/") {
				return nil
			}
		}
		return fmt.Errorf("R3 document endpoint is not admitted")
	}
}

func r3Tool(operation r3.Operation) string {
	var value struct {
		Tool string `json:"tool"`
	}
	json.Unmarshal(operation.JSON(), &value)
	return value.Tool
}

func r3Chosen(document r3.Document) []r3.Operation {
	var chosen []r3.Operation
	for _, operation := range document.OperationSet().Operations() {
		if slices.Contains(r3Grantable, r3Tool(operation)) {
			chosen = append(chosen, operation)
		}
	}
	return chosen
}

func r3ReadOnly(scopes []string) bool {
	return !slices.ContainsFunc(scopes, func(s string) bool { return s != "read" })
}

func r3Resource(e env, issuer, topology string, executions *r3Executions) (http.Handler, error) {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return nil, err
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return nil, err
	}
	tools := []map[string]any{}
	for _, tool := range r3Tools {
		tools = append(tools, map[string]any{"name": tool, "inputSchema": map[string]any{"type": "object"}})
	}
	toolsJSON, _ := json.Marshal(map[string]any{"tools": tools})
	definition, err := mcp.ParseDefinition(issuer+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage(toolsJSON)))
	if err != nil {
		return nil, err
	}
	display, err := r3.NewDisplay("Use fixture records", "Records may be exported", "Record contents", "Exported copies cannot be recalled")
	if err != nil {
		return nil, err
	}
	operations := map[string]r3.Operation{}
	for _, tool := range r3Tools {
		named, err := mcp.NewOperation(tool)
		if err != nil {
			return nil, err
		}
		if operations[tool], err = named.ToR3(); err != nil {
			return nil, err
		}
	}
	settings := &resource.R3Config{
		Registry: registry, Definitions: definitions,
		Vocabularies: []resource.R3VocabularyConfig{{
			Definition: definition,
			DisplayForOperations: func(context.Context, r3.OperationSet, *string) (*r3.Display, error) {
				return &display, nil
			},
		}},
		Documents: testutil.NewR3DocumentStore(),
		HTTP: resource.R3HTTPAdapter{
			OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				operation, ok := operations[strings.TrimPrefix(request.URL.Path, "/op/")]
				return operation, ok && strings.HasPrefix(request.URL.Path, "/op/"), nil
			},
			PresentParameters: func(request *http.Request, _ r3.Operation) (map[string]r3.PresentedParameter, error) {
				record, err := r3Record(request)
				if err != nil {
					return nil, err
				}
				presented, err := r3.NewPresentedInlineParameter(record)
				return map[string]r3.PresentedParameter{"record": presented}, err
			},
		},
	}
	if topology == "four-party" {
		settings.PerCall = &resource.R3PerCallConfig{
			DescribeCall: func(_ context.Context, invocation r3.Invocation, _ *string) (resource.R3CallDescription, error) {
				record, ok := invocation.PresentedParameters()["record"].InlineJSON()
				if !ok {
					return resource.R3CallDescription{}, fmt.Errorf("record parameter is required")
				}
				parameter, err := r3.NewInlineParameter(record)
				if err != nil {
					return resource.R3CallDescription{}, err
				}
				parameters, err := r3.NewParameters(map[string]r3.Parameter{"record": parameter})
				if err != nil {
					return resource.R3CallDescription{}, err
				}
				shown, err := r3.NewDisplay("Delete fixture record "+string(record), "The record is removed", "", "Deletion cannot be undone")
				if err != nil {
					return resource.R3CallDescription{}, err
				}
				detail, err := r3.NewProposalDisplay(shown, "## Action\nDelete a fixture record")
				if err != nil {
					return resource.R3CallDescription{}, err
				}
				return resource.R3CallDescription{Parameters: parameters, Display: &detail}, nil
			},
			Proposals: &r3ProposalStore{records: map[string]resource.R3ProposalRecord{}},
			Retries:   &r3RetryStore{records: map[string]*r3RetryEntry{}},
		}
	}
	descriptions := map[string]string{"read": "Fixture scope read"}
	resolvePerson := func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
		if !slices.Contains(e.c.PersonServers, identity.Issuer) || identity.Subject != subject {
			return fmt.Errorf("unrecognized fixture person")
		}
		return nil
	}
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "native Resource did not supply a verified principal", 500)
			return
		}
		tool := strings.TrimPrefix(r.URL.Path, "/op/")
		executions.add(tool)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"operation": tool, "sub": principal.Subject})
	})
	var server *resource.Server
	if topology == "three-party" {
		server, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: issuer, SigningKey: e.key("go-r3-direct-resource"), KeyResolver: e.keys, Clock: e.clock, NewID: e.newID,
			ScopeDescriptions: descriptions, RequiredScopes: func(*http.Request) []string { return nil },
			ResolvePerson: resolvePerson, Protected: protected, R3: settings,
		})
	} else {
		server, err = resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: issuer, AccessServer: e.c.Names["suite_access_server"], SigningKey: e.key("go-r3-resource"), KeyResolver: e.keys,
			Clock: e.clock, NewID: e.newID, ScopeDescriptions: descriptions,
			RequiredScopes: func(*http.Request) []string { return nil },
			ResolvePerson:  resolvePerson, Protected: protected, R3: settings,
			MaxRetainedRequestBodyBytes: 64 << 10, MaxRetainedResponseBodyBytes: 64 << 10, MaxRetainedHeaderBytes: 16 << 10,
		})
	}
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}

func r3Issuer(e env, issuer string) (http.Handler, error) {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return nil, err
	}
	sut, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: issuer, SigningKey: e.key("go-r3-ps"), KeyResolver: e.keys, Clock: e.clock, NewID: e.newID,
		Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: subject, Lifetime: personLifetime}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if !r3ReadOnly(request.Scopes) {
				return personserver.AuthorizationDecision{}, personserver.ErrAccessDenied
			}
			return personserver.AuthorizationDecision{Scopes: slices.Clone(request.Scopes), Lifetime: authLifetime}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: e.client, Admit: r3Admit(e),
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				if !r3ReadOnly(request.Scopes) {
					return personserver.DirectR3Decision{}, personserver.ErrAccessDenied
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), r3Chosen(document)...)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				grant, err := r3.NewGrant(granted, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{Scopes: slices.Clone(request.Scopes), Lifetime: authLifetime, Grant: grant}, nil
			},
			Issuances: testutil.NewR3IssuanceStore(),
		},
	})
	if err != nil {
		return nil, err
	}
	return sut.Handler(), nil
}

func r3FederatedIssuer(e env, personIssuer, accessIssuer string) (http.Handler, http.Handler, error) {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return nil, nil, err
	}
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessIssuer, SigningKey: e.key("go-r3-as"), KeyResolver: e.keys, Clock: e.clock, NewID: e.newID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personIssuer {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if !r3ReadOnly(request.Scopes) {
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			}
			return accessserver.Decision{Scopes: slices.Clone(request.Scopes), Lifetime: authLifetime}, nil
		},
		R3: &accessserver.R3Config{
			Registry: registry, HTTPClient: e.client, Admit: r3Admit(e),
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				if !r3ReadOnly(request.Scopes) {
					return accessserver.R3DocumentDecision{}, accessserver.ErrAccessDenied
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), r3Chosen(document)...)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				none, err := r3.NewGrantedOperations(mcp.Vocabulary())
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				authorization, err := r3.NewAuthorization(granted, none, document)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				return accessserver.R3DocumentDecision{Scopes: slices.Clone(request.Scopes), Lifetime: authLifetime, Authorization: &authorization}, nil
			},
			Issuances: testutil.NewR3IssuanceStore(),
		},
	})
	if err != nil {
		return nil, nil, err
	}
	person, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personIssuer, SigningKey: e.key("go-r3-federated-ps"), KeyResolver: e.keys, Clock: e.clock, NewID: e.newID,
		Tokens: testutil.NewMissionStore(), HTTPClient: e.client,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessIssuer {
				return "", fmt.Errorf("no federation with %s", issuer)
			}
			return issuer + "/token", nil
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: subject, Lifetime: personLifetime}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		R3: &personserver.R3Config{
			Registry: registry, Admit: r3Admit(e),
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error {
				return nil
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return person.Handler(), access.Handler(), nil
}

// r3Executions is the application's own count of executed calls per tool,
// read by the suite through a host control.
type r3Executions struct {
	mu     sync.Mutex
	counts map[string]int
}

func (e *r3Executions) add(tool string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counts[tool]++
}
func (e *r3Executions) serve(w http.ResponseWriter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(e.counts)
}

// r3Record is the call's concrete parameter: its body's record value.
func r3Record(request *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 65536))
	if err != nil {
		return nil, err
	}
	var call struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal(body, &call); err != nil || len(call.Record) == 0 {
		return nil, fmt.Errorf("call body needs a record")
	}
	return call.Record, nil
}

// In-memory proposal custody: every URI is created once and loaded as an
// independent copy, as the R3ProposalStore contract requires.
type r3ProposalStore struct {
	mu      sync.Mutex
	records map[string]resource.R3ProposalRecord
}

func (store *r3ProposalStore) Commit(_ context.Context, record resource.R3ProposalRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.records[record.Reference.URI()]; ok {
		return resource.ErrR3ProposalConflict
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	store.records[record.Reference.URI()] = record
	return nil
}
func (store *r3ProposalStore) Load(_ context.Context, uri string) (resource.R3ProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3ProposalRecord{}, resource.ErrR3ProposalNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

// In-memory baseline-retry custody: the first claim by a token gets one
// fenced execution; the same token later replays the retained response.
type r3RetryEntry struct {
	invocation resource.R3RetryInvocation
	state      string
	token      resource.R3RetryAuthToken
	fence      string
	response   resource.HeldResponse
}
type r3RetryStore struct {
	mu      sync.Mutex
	records map[string]*r3RetryEntry
	fences  int
}

func r3CloneInvocation(invocation resource.R3RetryInvocation) resource.R3RetryInvocation {
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	return invocation
}
func r3CloneResponse(response resource.HeldResponse) resource.HeldResponse {
	response.Header = response.Header.Clone()
	response.Trailer = response.Trailer.Clone()
	response.Body = append([]byte(nil), response.Body...)
	return response
}
func (store *r3RetryStore) Prepare(_ context.Context, invocation resource.R3RetryInvocation) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	invocation = r3CloneInvocation(invocation)
	if retained, ok := store.records[invocation.Reference.URI()]; ok {
		if !reflect.DeepEqual(retained.invocation, invocation) {
			return resource.ErrR3RetryConflict
		}
		return nil
	}
	store.records[invocation.Reference.URI()] = &r3RetryEntry{invocation: invocation, state: "pending"}
	return nil
}
func (store *r3RetryStore) Load(_ context.Context, reference r3.Reference) (resource.R3RetryInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[reference.URI()]
	if !ok {
		return resource.R3RetryInvocation{}, resource.ErrR3RetryNotFound
	}
	return r3CloneInvocation(entry.invocation), nil
}
func (store *r3RetryStore) Claim(_ context.Context, reference r3.Reference, token resource.R3RetryAuthToken) (resource.R3RetryClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[reference.URI()]
	if !ok {
		return resource.R3RetryClaim{}, resource.ErrR3RetryNotFound
	}
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			entry.state = "expired"
			return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
		}
		store.fences++
		entry.state, entry.token, entry.fence = "executing", token, fmt.Sprintf("r3-fence-%d", store.fences)
		return resource.NewHeldExecution(resource.HeldExecution{InvocationID: reference.URI(), Fence: entry.fence}), nil
	case "complete":
		if entry.token.SHA256 != token.SHA256 {
			return resource.R3RetryClaim{}, resource.ErrR3RetryTokenMismatch
		}
		return resource.NewHeldReplay(r3CloneResponse(entry.response)), nil
	case "expired":
		return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
	default:
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	}
}
func (store *r3RetryStore) Retain(_ context.Context, execution resource.R3RetryExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return resource.HeldResponse{}, resource.ErrR3RetryCompletionStale
	}
	entry.state, entry.response = "complete", r3CloneResponse(response)
	return r3CloneResponse(entry.response), nil
}
