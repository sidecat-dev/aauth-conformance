# Launcher protocol, version 1

A launcher supplies host configuration and transport around one implementation's
native Resource, Agent or Person Server API, or a native PS/AS/Resource bundle.
The optional bootstrap `role` defaults to
`resource.agent-identity`; `agent.signing` selects the outbound signer contract
below.

## Resource role

A Resource launcher must not read scenarios/expectations, verify signatures outside
the SUT or synthesize refusal responses. Included launchers pass all AAuth decisions
to the SUT. Success emits JSON `{"sub":"<verified subject>"}` from its verified principal.

The runner sends one object on stdin, then closes stdin:

```json
{"version":1,"now":1800000000,"issuer":"https://ap.conformance.test","resource":"https://resource.conformance.test/whoami","ap_transport":"http://127.0.0.1:54321"}
```

The launcher must:

1. Read the bootstrap and configure the fixed verifier clock.
2. Fetch `/.well-known/aauth-agent.json` and `/.well-known/jwks.json` from AP
   transport. The fixture supplies Content-Length framing. Logical discovery
   identifiers stay HTTPS; physical loopback HTTP and trusted keys are explicit
   test host configuration, not discovery-security claims.
3. Give the Resource those public keys, logical HTTPS target and an allow policy.
   Metadata framing/configuration checks are allowed; signature/JWT verification
   belongs entirely to the SUT.
4. Bind an ephemeral loopback socket; print and flush one stdout object:
   `{"version":1,"url":"http://127.0.0.1:54322/whoami"}`. Send logs to stderr and
   remain alive until terminated by the runner.
5. Preserve received method, Host, path and signature fields. Reconstruct HTTPS
   scheme for the test mapping; pass actual body bytes to the SUT. Return its
   refusal status/headers/body unchanged. Success uses the common echo handler.

Readiness defaults to ten seconds; each exchange to five. Only literal loopback
IP HTTP readiness URLs with the configured path and no query are accepted.
Only the physical origin is substituted; signed path/query bytes are preserved. The runner stops its direct child and AP
on completion, interrupt, timeout and startup failure. Grandchildren from arbitrary
wrapper scripts are not managed; use a direct launcher process.

The Go adapter uses `resource.NewAgentIdentity`, `ClockFunc`, `StaticKeyResolver`
and `AgentPrincipalFromContext`. Rust uses `AgentProviderKeys::from_documents`,
`AgentIdentityResource`, `authorize` and `Decision::into_result`. No scenario ID
or expected result is present in either launcher's bootstrap.

`build-adapters` copies launcher sources to ignored build directories and uses
local source paths. It records source HEAD (`+dirty` for tracked changes), retains
module/lock files in build output and copies the Rust pinned toolchain. It edits
no SUT source or manifest. Outputs are test launchers, not production services
or releases. TLS and general discovery tests need a separate slice and clauses.

Child exit codes after the final exchange are not assessed. Remaining child
processes are terminated; this slice reports startup and HTTP execution errors.

### The endpoint that requires a Person token

The bootstrap also names the fixture Person Server (`person_server`,
`person_kid` and its public `person_jwk`) and `person_resource`, the logical
URL of a second endpoint on the same origin (`fixture.person_path`). A
launcher whose implementation serves on the person's identity serves that
endpoint on the same listener: an unsigned request or one signed with an
Agent token is answered by the SUT with `requirement=person-token`, and a
request signed with a fixture Person token for this origin succeeds with
`{"sub":"<person's directed subject>"}`. These scenarios grade the
out-of-slice `core.person-token-required`, claimed only by an implementation
listed in `cmd/build-adapters/adopted.go`. Rust uses `PersonIdentityResource`,
`authorize` and `PersonDecision::into_result`, with the Person Server's keys
from `TrustedIssuerKeys::from_documents`. Go uses `resource.NewPersonIdentity`
and `PersonPrincipalFromContext`, with the Person Server's key in a
`StaticKeyResolver`.

## Agent signing role

The stdin bootstrap adds `role: "agent.signing"`, `agent_seed_hex` (the public
fixture's 32-byte Ed25519 seed) and `subject`. Clock, issuer, logical Resource
and AP transport retain the meanings above. Announce readiness at the exact
loopback path `/control` instead of the Resource path. The Agent may use the
fixture's admitted AP keys; the harness does not claim discovery admission or
client verification from these valid-token-only cases.

For each case the harness POSTs this control JSON:

```json
{"method":"GET","url":"https://resource.conformance.test/whoami","headers":{},"token":"<AP-issued Agent JWT>","transport":"http://127.0.0.1:54323"}
```

The launcher constructs an empty-body request from method, logical URL and
headers, configures the SUT Agent with the supplied token/key/clock, and invokes
its native signer or Agent client. It sends that actual signed request to the
physical transport address, preserving logical Host, path/query and all signed
header values. It must not format proof headers, calculate a signature base,
sign outside the SUT, or repair the SUT's signed output. In this bodyless
profile Rust explicitly rejects a nonempty post-signing body; it must never
silently discard one. That rejection is a control execution error. Adapter input
limits and loopback checks are transport configuration.

Return HTTP 200 with `{"status":<receiving Resource HTTP status>}` after sending;
return a non-200 response when construction/signing/transport fails. The harness
grades the actual received request, not that status promise. No captured request
is an execution error even if the control endpoint returns 200. A non-200 control
response is independently an execution error. The receiving harness checks the
bodyless proof/token/coverage and responds 200 or 401. Repeated bytes are accepted;
replay storage is outside this profile.

The Go launcher uses `agent.New` and `CallAsAgentWithComponents(..., nil)` with
admitted fixture AP keys and a fixed `ClockFunc`. Its host RoundTripper substitutes
only physical scheme/host after signing. The SUT manages query/Authorization
coverage automatically; Go's additional-component argument accepts HTTP field
names and must not be given `@query`. No metadata request is needed for this
explicit profile.

For the person-endpoint scenario the Agent token names the fixture Person
Server in `ps`, and the control JSON adds `person_token_endpoint`,
the fixture Person Server's logical `person_token_endpoint`, and
`person_transport`, its loopback address. The harness Person Server publishes
`/.well-known/aauth-person.json` with the four members Person Server Metadata
requires, and the harness Resource publishes `/.well-known/aauth-resource.json`
with its issuer; a metadata fetch is kept as an exchange and not graded. In a
scenario with `"resource_metadata_unpublished": true` in its `request`, such as
`agent-person-flow-unpublished-metadata`, the harness Resource publishes none,
as Core lets a Resource do (Resource Metadata, line 2101), and answers that
fetch `404`; the flow is graded the same way, under the clause
`agent.resource-metadata-unpublished`. The
harness Resource answers a valid
Agent-token request with `401` and `requirement=person-token`; the harness
Person Server answers a valid Person token request with `200`
`{"person_token":...,"expires_in":...}`; the harness Resource accepts a retry
presenting exactly that token. `wire-person-request` grades the Person token
request: one signed POST with the job's Agent token, covering
`content-type` and `content-digest` by the actual body's digest, whose JSON
`resource` is the Resource's origin. `wire-person-token` grades one retry to
the job's method and URL that presents the issued Person token under a valid
signature by the Agent key. Every request is kept as a case exchange. A
launcher that sends only the first request gets both assertions failed when
it claims `agent.person-flow` and recorded otherwise. Its control response,
200 or not, is evidence only: an Agent that stops short of the flow, such as
one that refuses to fetch the fixture's Person Server metadata, is graded by
what reached the harness, not counted as an execution error. Rust uses `Requirement::from_headers`, `Agent::person_request`,
`Agent::verify_person_delivery` and `Agent::with_token`; the launcher only
moves bytes between them. Go uses `aauth.ParsePersonTokenRequirement`,
`agent.Client.PersonToken`, which reads the Person Server's metadata, and
`agent.Client.Begin`, which reads the Resource's; its host transport routes
each logical origin to its loopback address.

Rust uses `Agent::new` and `Agent::sign`, then a small host TCP transport serializes
the signed `http::Request`. Rust's Agent API supplies signing rather than an HTTP
client; this adapter does not imply feature parity with Go's client orchestration.
Both launchers are compiled against the chosen checkout, including the Agent and
JOSE crates for Rust. Generated Go launcher modules disable VCS executable
stamping; selected SUT HEAD/dirty state is recorded in the target manifest.

## Person Server direct authorization role

`role: "person-server.direct"` selects a native Person Server that issues Person
and direct Auth tokens. Bootstrap keeps existing `now`, AP `issuer`, `resource`
and `ap_transport`, and adds:

```json
{
  "person_server": "https://person.conformance.test",
  "person_seed_hex": "<public fixture 32-byte Ed25519 seed>",
  "person_kid": "ps-1",
  "person_subject": "directed-person-1",
  "person_lifetime": 300,
  "auth_lifetime": 180,
  "permitted_scopes": ["read"],
  "resource_kid": "resource-1",
  "resource_jwk": {"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":"<public key>"}
}
```

Lifetimes are seconds. `resource` identifies the fixture Resource, not this PS.
Configure admitted AP/Resource public keys and the PS's own public key for
presented-token verification. Construct a native PS with fixed clock, unique
native issuance IDs, a retained in-memory store, a binding callback returning
the configured opaque subject/lifetime, and an authorization callback granting
requested permitted scopes with the configured lifetime. Deliberately deny a
scope outside that list using the native policy-denial API. Neither callback
receives a scenario name or expected response. Do not synthesize protocol
refusals, verify incoming credentials outside the SUT, or mint response tokens
outside its native implementation.

Announce `{"version":1,"url":"http://127.0.0.1:<port>/person"}` and serve the
same listener's native `/person` and `/token` endpoints. Reconstruct logical HTTPS
using the **received** Host and path. Preserve body bytes and signature headers;
do not replace authority with the configured PS or repair a malformed proof.
Return native status, headers and body unchanged. No control endpoint is needed.
The runner supplies the HTTP proofs and the Resource JWT, including the actual
presented Person token obtained from that launcher.

Go uses `personserver.NewPSAuthorization`, `testutil.NewMissionStore` as its
TokenStore, fixed ClockFunc, native BindPerson/Authorize callbacks and native
Handler. The store is an in-memory development helper, not persistence evidence.
The runner's PS oracle uses no AAuth package.

Rust uses `PersonServer::new`, `Config`, `MemoryStore::default`, and a native
`Policy` implementation. Config receives the fixed Person lifetime; the policy
returns the configured Auth lifetime and requested allowed scopes or
`PolicyError::Denied`. The native server owns proof verification, incoming token
verification, retained lineage, JWT issuance, and refusal responses. Host-supplied
AP and Resource keys use `AgentProviderKeys` and `TrustedIssuerKeys`; the native
PS also resolves its own signing key for presented-token verification. The
buffered `http::Request<Vec<u8>>` retains actual received Host, path, body and
proof fields, and `handle` supplies the response unchanged. The transport
regression checks those bytes with an intentionally foreign received authority.
The Rust launcher now requires the Person Server crate in the selected checkout
alongside Agent, Core, JOSE and Resource.

The build helper also copies Go adapter tests so explicit Host preservation
and its empty-Host fallback can be tested in the generated module. That Agent
transport correction is separate from PS protocol coverage.

## Four-party authorization role

`role: "authorization.federated"` starts three native roles with distinct logical
HTTPS identities and keys on one loopback listener. The Person Server bootstrap
above gains:

```json
{
  "access_server": "https://access.conformance.test",
  "access_seed_hex": "<public fixture 32-byte Ed25519 seed>",
  "access_kid": "as-1",
  "resource_seed_hex": "<public fixture 32-byte Ed25519 seed>",
  "federation_transport": "http://127.0.0.1:<relay-port>"
}
```

Configure the native PS to bind the fixture person and consent to federation.
Configure the native AS to trust that PS and authorize only requested permitted
scopes, using the requested Auth lifetime; native issuance enforces parent
limits. Configure the native Resource to require the fixture scope, name this
AS in its challenges and trust its Auth tokens. Host subject and PS policies
must use verified native principals.

Announce the loopback Resource path `/whoami`. Route requests by actual received
Host to the native PS, AS or Resource. Preserve method, target, headers and body
and return native responses. Emit the common JSON subject echo only after native
Resource authorization. A synchronous PS exchange must be able to reach the AS
on this listener while the PS request is pending.

The PS resolves the configured AS's logical `/token` endpoint. Its host transport
sends the already signed request to `federation_transport`, changing only the
physical connection destination. Preserve an explicit Host; use URI authority
only when no Host is present. Preserve all signed headers and body bytes, including
Content-Digest. Do not retry, redirect, repair or re-sign native PS output. Return
the relay's actual status, headers and bounded response body to the native PS.
This transport is deliberately loopback HTTP; it is not a production TLS client.

Independent-PS scenarios use only the native Resource and AS endpoints in this
bundle. Their Person tokens and AS request proofs come from the harness; the
native PS is unused. No adapter changes or target-specific expectations select
this driver, and its report contains no native PS issuance/delivery claims.

The harness relay independently checks native output, then forwards to the AS
or injects the scenario's declared fault. No scenario name or expectation is
sent to the adapter. Fixed public trust snapshots may be constructed from the
fixture keys, but incoming proof and credential verification, retained Person
lineage, challenge/issuance and AS-grant verification belong to native code.

Go uses `resource.NewFederatedAuthorization`,
`personserver.NewFederatedAuthorization`, `accessserver.New`, the native handlers,
and `testutil.NewMissionStore` for PS state. Rust uses
`PsAuthorizationResource::new_federated`, `PersonServer::with_federation`,
`AccessServer::new`, and `MemoryStore`; its host `Federation` adapter supplies
endpoint resolution and transport. The build helper includes the Rust AS crate
and enables the launcher's `federation` feature only for this role, leaving the
other roles buildable against earlier native APIs.

Budget scenarios use the same listener. `POST /authorize` is the Resource
authorization endpoint and `POST /usage` is the usage query. Protected paths
are `{path}-budget-grant` (metered), `{path}-budget-omit` (not metered; an
auth token with no budget claim still returns the subject),
`{path}-budget-reserve` (a header reservation and an optional cost-only
trailer), and `{path}-budget-usage` (metered on the usage ledger). The unsigned
fixture headers are `X-Fixture-Cost`, `X-Fixture-Offer`, `X-Fixture-Hold`, and
`X-Fixture-Settle`. Declared units are `credits` and `points`, both decimals 0,
with metadata maximum 10000000. When the harness Person Server allocates, it
sends `budget.amount` 2000000 in `credits`. The adapter does not read
`budget_units` or `usage_endpoint` metadata; those two paths are fixed.

## Deferred four-party authorization

`role: "authorization.deferred"` uses the four-party fixture and native role
composition above. Both launchers implement it. The build helper copies
`adapters/go/deferred.go` for this role alone. Rust selects the `deferred`
feature, which includes `federation`, and adds the native Access Server
dependency. Earlier roles do not compile deferred API calls. A Rust source
revision without the native deferred APIs fails compilation for this role;
that build failure is not conformance evidence.

Go configures native AS `DeferredConfig` with `testutil.NewAccessAuthorizationStore`
and native PS `FederatedDeferredConfig` with
`testutil.NewFederatedAuthorizationStore`. Rust configures native AS and PS
`DeferredConfig` with separate `MemoryContinuations::new(64)` stores through
`AccessServer::with_deferred` and `PersonServer::with_deferred`. Both lifetimes
are 30 seconds; the fixed clock does not advance, and AS pending decisions
advertise zero retry delay. Rust also sets the PS Agent retry delay to zero.
Incoming Agent and PS authentication, pending URL creation, continuation state,
grant verification and terminal consumption remain native code.

The loopback-only host control `POST /__fixture/deferred` accepts
`{"stage":0,"reference":""}`. Stage 0 represents unsettled payment, stage 1
settled payment awaiting approval, stage 2 approval, and stage -1 denial.
The existing scope policy applies first. A nonempty `reference` calls the
native PS `AdvanceFederation` (Go) or `advance_federation` with
`FederationInput::Poll` (Rust) once after changing host policy. The Rust AS
deferred callback checks the same scope policy before returning a payment or
approval requirement, denial, or normal native issuance. These are host inputs,
not protocol responses or proof-validation shortcuts. The runner
records control responses separately and requires the corresponding native AS
and PS exchanges; a successful control response alone cannot pass a clause.

The relay observes every PS request and native AS response separately from
fault injection. It can replace a payment Location with a foreign origin or
corrupt the final grant presented to the PS. It never repairs native proofs.
Payment uses a public fixture `WWW-Authenticate` challenge; there is no payment
provider, money transfer or billing relationship cache in the adapter.

The Rust transport admits native AS `/token/pending/<reference>` paths only on
the configured HTTPS AS origin, alongside its original `/token` endpoint. The
relay preserves the native signed method, headers and body. The Agent polls
only its PS URL; the fixture host explicitly advances PS-to-AS polling.

## Parent-mediated sub-agent authorization

`role: "authorization.subagent"` uses the same native PS/AS/Resource bundle and
bootstrap as deferred authorization. Direct scenarios additionally set
`person_direct: true`, which configures the native PS without federation; all
other scenarios configure native federation. Rust builds with the `subagent` feature,
which includes `deferred` and `federation`. Each scenario starts a fresh bundle
so parent binding revocation, clock changes and consumed continuations cannot
change another scenario's result. Native PS and AS endpoints consume optional
`subagent_token`; their code verifies the relationship and issues child-bound
credentials. The adapter does not parse, verify, mint or repair those credentials.

The independent driver acts as the fixture AP, parent, child and (for direct
three-party cases) Resource. Its parent key is the existing fixture Agent key;
its child key is the public seed `06` repeated 32 times. AP fixture tokens have
separate identities, keys and compact bytes. The wrong-provider scenario declares
a second AP with its own valid issuer/subject and distinct signing key; the
runner serves that AP on a separate bounded loopback fixture. Bootstrap
`additional_agent_providers` supplies its logical issuer and physical `transport`.
The adapter fetches its actual fixture metadata/JWKS and admits it through native
`AgentProviderKeys`, leaving the same-provider relationship check as the
decisive refusal. No private AP seed is passed in that trust declaration. The parent signs PS `/person`,
`/token`, GET polls and DELETE cancellation. The child signs native Resource
requests with the Person/Auth credential received from the PS. The runner
independently verifies native Person/Auth signatures, child holder key, subject,
audience, authorization and both Agent lifetimes; separate shorter-child and
shorter-parent cases make each Agent lifetime decisive; delegation claims must stay
absent from credentials seen by the Resource. Immediate direct cases use a
fixture-signed Resource token, and therefore claim native PS issuance and
independent credential verification only. Four-party cases obtain the actual
native Resource challenge and exercise native Resource use after delivery.

The relay separately captures native PS proofs, native AS responses and exact
parent, child, Resource and presented-token compact bytes. It checks the POST
body and GET poll proof independently. Native AS/PS success cannot be replaced
by a host control response. Refusal assertions require a 4xx response with no
credential; child token errors also check status and code. Both parent-binding
revocation scenarios require HTTP `400` with `error: revoked_presented_token`
and no credential. The `depth` scenario keeps the HTTP signer top-level and
presents a grandchild token with two `+` naming segments and `parent_agent`
pointing to the intervening child. Its `subagent.depth` row checks the
grandchild parameter refusal (`400 invalid_subagent_token`). The separate
`child-direct` scenario checks the child-signed endpoint guard under
`subagent.mediation`. Neither row claims AP issuance rejection.
A child poll is tested before and after AS completion, followed by a successful
parent poll and a second parent poll returning `410`. Cancellation requires
successful 2xx with no credential and subsequent `410`; timeout requires
`408 expired` followed by `410`; the protocol does not
fix the DELETE success status.

Rust's loopback host control `POST /__fixture/subagent` accepts the existing
`stage`/`reference` policy inputs. It also accepts a bounded `now_offset` in
seconds from the bootstrap clock and `revoke: true` with `parent_issuer` and
`parent_subject`. The clock is shared by all native roles; revocation calls the
retained native `Store::revoke_binding` on the parent principal. These controls
exercise in-memory policy and state only. They do not claim AP token revocation,
durable continuation recovery, real payment, consent UI, recursive delegation,
missions, or production TLS/discovery.

The Go launcher compiles `adapters/go/subagent.go` only for this role. Direct
scenarios run `personserver.NewPSAuthorization`; the others run
`personserver.NewFederatedAuthorization` with `FederatedDeferredConfig` and an
AS with `DeferredConfig`, each with a 30-second lifetime and in-memory
`testutil` stores. Additional providers from `additional_agent_providers` are
admitted from their fixture metadata and JWKS into the launcher's static key
resolver; the native PS and AS decide whether their tokens qualify. Go's host
control at `POST /__fixture/subagent` accepts the same members as Rust's:
`revoke` calls the native `Server.RevokeAgentBinding` for the parent's
`AgentBinding`, `now_offset` moves the clock shared by all three roles,
`stage` selects the AS policy and a nonempty `reference` makes one
`AdvanceFederation` call. These controls change policy, time and binding state
only. They do not claim Agent-token revocation cascades, durable continuation
recovery, real payment, consent UI, recursive delegation, missions, or
production TLS/discovery.

## Events roles

The bootstrap `extension` object carries the Agent identifier (`agent`) and,
per role: the Resource identity, subscription and ticket paths and trusted
Person Servers (`events.subscription`); the event endpoint, the fixture AP
seed and kid, the subscribed Resource and trusted Resources
(`events.agent-provider`); trusted Resources and a fixture Agent token
(`events.agent`). Trusted issuers are `{issuer, transport}` pairs; the launcher
fetches their metadata and JWKS from the runner's loopback documents and
admits them as fixed trust snapshots. Clocks are fixed at the bootstrap time.
Go builds `adapters/go/events.go`; Rust builds the `events` feature and links
the Agent Provider crate.

- `events.subscription` announces the subscription path and routes it to the
  native public registration (`EventService.PublicSubscriptionHandler`;
  `EventsResource::register`), the ticket path to native protected
  registration, and `POST /__fixture/ticket` `{"person_token"}` to a control
  that verifies the person token natively (`aauth.VerifyPersonToken`;
  `PersonToken::verify`) and issues a ticket from it, answering `{"url"}`.
- `events.agent-provider` announces the event endpoint path and serves the
  native AP: metadata, JWKS and the inbox (`agentprovider.Server.Handler`;
  `AgentProvider::metadata`, `EventInbox::receive`). `POST /__fixture/subscribe`
  `{"max_uses"}` calls native subscribe-token issuance for the fixture Agent
  and the subscribed Resource and answers `{"token"}`.
- `events.delivery` runs the subscription launcher with
  `agent_providers` (`{issuer, transport}`) and adds `POST /__fixture/fire`
  `{"agent_provider","eid","body"}`: native event preparation and delivery
  (`EventService.PrepareEvent`/`DeliverEvent`;
  `EventsResource::prepare_event`/`delivery_request`). Go resolves
  `event_endpoint` through its native `HTTPEventEndpointResolver`; Rust's host
  fetches the AP metadata and passes it to `delivery_request`, as its API
  requires. Both transports change only the physical destination of the signed
  request and answer `{"status"}` with the AP's HTTP status.
- `events.agent` announces `/__fixture/event` and passes
  `{"event_token","body","content_type"}` to the native check
  (`agent.Client.AcceptEvent`; `aauth_rust_agent::verify_event`), answering
  `{"accepted"}` with the native error text on refusal.

aauth-go's API contract gives some Events duties to its stores: the
`agentprovider.EventInboxStore` compares a delivery's Resource and Agent with
the subscription, counts uses and retains the bytes its `EventInboxReader`
hands to the Agent, and `resource.ProtectedSubscriptionStore` consumes a
ticket on commit. The Go launcher uses the library's own in-memory stores,
`testutil.NewEventInboxStore` and `testutil.NewProtectedEventStore`, so those
decisions are aauth-go's and every Events clause is claimed for it.
`POST /__fixture/pending` calls native `PendingEvents` (Rust:
`EventStore::pending` on the library's `MemoryEventStore`) and answers
`{"events":[{"event_token","body"}]}`. The Go Agent store returns a context
for every `eid`: context lookup and deduplication are not graded. aauth-rust's
stores are its own (`MemorySubscriptionStore`, `MemoryEventStore`).

## R3

`r3.resource` and `r3.issuer` share `adapters/go/r3.go` (registered through
`extensionLaunchers`) and the Rust `r3` feature, which adds the
`aauth-rust-r3` crate. The bootstrap `extension` carries public JWKs and kids
for the PS, AS, Resource and other server, the person subject and lifetimes,
permitted scopes, the R3 vocabulary, `tools` and `grantable`, the Resource
seed (`r3.resource`) or PS seed and `r3_transport` (`r3.issuer`). Both announce
the fixture Resource path on a loopback listener and restore only the HTTPS
scheme from the received Host.

For `r3.resource` the launcher trusts the AP, PS (`aauth-person.json`), AS
and other server (`aauth-access.json`) and the Resource's own key. It builds
the authoritative MCP definition from `tools`, maps `POST /op/<tool>` to that
tool, gives a fixed display, and an in-memory document store. Four-party uses
Go `resource.NewFederatedAuthorization` and Rust
`PsAuthorizationResource::new_federated`; three-party uses
`resource.NewPSAuthorization` and `PsAuthorizationResource::new`, each with
`R3Config` and the authorization endpoint. Four-party also enables per-call
proposals (Go `R3PerCallConfig` with in-memory proposal and retry stores; Rust
`with_r3_per_call` with an in-memory `R3CallStore`, `hold` off): the call's
`record` body value is its one inline parameter. The application handler
echoes `{"operation","sub"}` and counts its executions; Rust passes per-call
results to `r3_retain`. `GET /__fixture/r3/executions` reports those counts.
It is the only host control; it changes nothing.

For `r3.issuer` the launcher runs Go `personserver.NewPSAuthorization` with
`DirectR3Config`, or Rust `PersonServer::new(...).with_r3(R3IssuerConfig)`.
Egress admission allows only `{Resource}/r3/`; the transport sends the PS's
already signed fetch to `r3_transport`, changing only the socket. Fixed
consent grants requested permitted scopes and the document's `grantable`
operations; the R3 audit log is in memory. The native PS fetches, verifies the
hash, signs and refuses on its own.

These launchers make no TLS, discovery-admission, durable-custody, consent-UI,
held (`202`) per-call or release-gating claim.

For `r3.federated-issuer` the Go launcher hosts `accessserver.New` with
`R3Config` and `personserver.NewFederatedAuthorization` with `R3Config` on one
listener routed by Host. One HTTP client sends the PS's AS requests to that
listener and both servers' R3 fetches to `r3_transport`. The AS policy grants
requested permitted scopes and the document's `grantable` operations; the PS
consents. aauth-rust's Access Server issues no R3 Auth tokens, so the build
helper declares the Rust target unavailable for this role.

## Mission roles

`mission.person-server` uses the Person Server bootstrap fields above. The
launcher serves the native Person Server, announces the fixture Resource path
for the readiness check (only its physical origin is used) and adds the
loopback host control `POST /__fixture/mission`. Its members are host inputs
only: `now_offset` (seconds, shared clock), `expires_in` (the approval policy's
mission lifetime), `approve` (a pending proposal's `Location`, approved as the
person) and `install` (`{"s256","agent"}`: record an approved mission for
issuance). The fixture person approves proposals as proposed, accepts updates
and completions, grants permissions and grants the `read` scope.

Go configures `personserver.NewPSAuthorization` with `MissionConfig` (an
immediate `Approve` that copies the proposal and sets `ExpiresAt` from
`expires_in`, `AcceptUpdate`, `ConfirmPersonAcceptedCompletion`),
`PermissionConfig`, `AuditConfig` and `testutil.NewMissionStore`. Its approval
is immediate and retains the mission for issuance itself, so `approve` is
refused and `install` changes nothing.

Rust configures `PersonServer::new(...).with_missions().with_governance(...)`
over `MemoryStore`. A proposal is always deferred; `approve` signs the native
approval POST as the Person Server (`jwks_uri`, covered digest and type) with
`aauth_rust_signature_key::sign_request` and passes it to `handle`. Because
`with_missions` retains the approved document in the mission audit and does
not install an issuance record, `install` reads that document with
`Store::read_mission_audit` and installs it with
`MemoryStore::install_approved_mission` for the fixture person, as the crate
leaves to the host. An `expires_in` control is kept for the next approval,
which carries `expires_at` (that many seconds after the fixture clock, RFC
3339), as the native approval takes it from aauth-rust 0.1.0-alpha.20. The
launcher never terminates a mission itself.

`mission.resource` runs the four-party bundle (Go `runFederatedServers`,
Rust `federation::run`); its federation transport refuses every request
because the slice stops at the Resource's challenge. Rust's Resource refuses
mission-bound person tokens unless the host opts in, so this role calls the
native `with_mission_context`. Go's federated Resource documents that it needs
no configuration for a mission-bound person token; nothing is added.
Rust builds both roles with the `mission` feature, which includes
`federation`, and adds the Access Server and Signature-Key crates.

## Supervision roles

Both launchers are built with the Rust `supervision` feature and the
`aauth-rust-supervision-server` crate, or with `adapters/go/supervision.go`.
Each scenario starts a fresh launcher. The loopback-only host control is
`POST /__fixture/supervision`; it changes host policy or calls a host
method the library exposes, and its answer is never graded.

`supervision.server` bootstraps `extension.supervisor` (issuer, public seed,
kid) and `extension.person_servers` (issuer, kid, public JWK, `accept`).
Announce the logical metadata path `/.well-known/aauth-supervisor.json` and
serve the native handler for every other path, reconstructing logical HTTPS
from the received Host. Configure the native server with its signing key, a
fixed clock, an in-memory store and the admitted Person Server keys under
`aauth-person.json`. Host connect policy accepts the `accept` Person Servers
and refuses the others; host decision policy allows person-token, auth-token
and mission acts and a permission whose action is `fixture.allow`, denies
`fixture.deny`, asks for `fixture.ask` and defers `fixture.defer`. Controls:
`{"resolve":{"sdi":"...","verdict":"allow"}}` resolves a deferred decision
through the native host call (Go `ResolveDecision`, Rust `decide_pending`);
`{"rate_limit":true}` makes the next supervision request a host rate limit.
Neither supervision server limits a Person Server by itself. Rust answers the
host limit with its own `SupervisionError::RateLimited.response`; Go exports
no rate_limited response and answers `501` with `not_offered`.

`supervision.person-server` bootstraps the Person Server fields of the
direct role plus `extension` `supervisor`, `supervisor_transport` (the
harness supervisor's loopback address), `supervisor_subject` (the directed
sub, host configuration), `supervisor_keys` (the supervisor and the foreign
supervisor under `aauth-supervisor.json`) and `resource`. Announce `/person`.
Route every Agent to the supervisor, carry the native Person Server's signed
requests unchanged to the transport (Go through its HTTP client, Rust
through `Supervision::send`), and serve the supervisor's metadata to it from
the same transport. The Person Server's own authorization policy refuses: it
is never consulted for a supervised Agent. Controls: `{"resolve":"allow"}`
records the person's allow, without a reason, on the held act (Go
`ResolveSupervision` on a `PendingSupervision` entry, Rust
`resolve_supervision` on the `SupervisionHold` the last response carried);
`{"advance":true}` polls the supervisor once (`AdvanceSupervision`,
`advance_supervision`); `{"deliver":true}` delivers queued events
(`DeliverSupervisionEvents`, `deliver_supervision`).

## Community aauth-go launcher

`build-adapters -community-source DIR` compiles `adapters/community-go`
against a checkout of the community module `github.com/aauth-dev/aauth-go`
(tested at v0.3.0, commit `5aff16d`); the target id is `aauth-go-community`.
Every source file in that directory is compiled, and each role file registers
its launcher; a role with no registration is refused at startup. The launcher
uses only the module's exported API, with the fixture's fixed clock wherever
the API takes one.

- `resource.agent-identity`: `ResourceGuard` at `AccessAgent`, with a
  `StaticResolver` holding the fixture AP's published JWKS.
- `agent.signing`: `AttachSignatureKey` and `SignRequest` on the control
  job's request. `SignRequest` takes `created` from the wall clock and has no
  clock input, so `core.agent-created` is not claimed for this target.
- `person-server.direct`: `personserver.New` at `/person` and `/token`, with
  `MemoryStore`, a `Decider` that binds the agent to the fixture person and
  refuses scopes outside the fixture policy (host code `access_denied`), and
  static resolvers for the AP, the fixture Resource and the PS's own key. The
  module derives directed subjects itself, so the configured-subject adapter
  contract (`ps.host-person-profile`) is not claimed.
- `authorization.federated`: the module's `personserver.Server` (federating
  through `accessserver.NewClient`), `accessserver.Server` and a Resource,
  routed by received Host. The Resource is composed from the exported
  functions `ResourceGuard` itself calls (`ParseSignatureKey`,
  `VerifyAndExtract*`, `IssueResourceToken`, the challenge helpers and
  `WriteSignatureFailure`), because the guard issues resource tokens at the
  wall clock while `IssueResourceToken` takes the fixture clock. The AS's own
  metadata request is answered in process by the native AS; signed token
  requests go through `federation_transport`. The module's server signer
  also takes `created` from the wall clock, so under the fixture clock the
  native AS refuses the native PS's request as stale; scenarios that use the
  native PS cannot complete for this target. The independent-PS scenarios
  are unaffected. The module has no Budgets, so the budget clauses are not
  claimed.
- `mission.person-server` and `mission.resource`: the module's mission,
  permission and audit endpoints with an approval policy that approves as
  proposed and sets `expires_at` from the `expires_in` control; approval is
  immediate, so `approve` is refused and `install` changes nothing.

Declared unavailable for this target (`cmd/build-adapters/community.go`): the
Events, R3 and Supervision roles (the module does not implement those
drafts) and `authorization.subagent`, whose host control advances PS-to-AS
polling once per reference; the module's PS polls its AS on each Agent poll.
`authorization.deferred` is not run for this target for the same reason, and
because the module's AS never answers 402 itself.

## Signature-Key roles

`sigkey.verifier` and `sigkey.signer` read the bootstrap `extension`:
`verifier`, `agent_provider`, `signer`, `signer_dwk`, `jwks_url`,
`self_jwt_typ`, `algorithms` and `documents`, a map from each logical HTTPS
origin to the loopback transport serving its discovery documents. The
verifier announces the path of `verifier`; the signer announces the path of
the bootstrap `resource` (`/control`). Each verifier scenario starts a fresh
launcher, since its documents differ.

The verifier is the native Resource with its further schemes enabled; its
responses are returned unchanged. The 200 echo of the verified scheme is
adapter contract. Go uses `resource.NewAgentIdentity` with
`FurtherSchemesConfig` (hwk, jkt-jwt, self-jwt with the extension's
`self_jwt_typ` as `SelfJWTType`, jwks_uri, jwks) and a native
`signaturekey.HTTPKeyResolver` for Agent Provider, jwks_uri and jwks keys: the
resolver fetches, parses and selects keys itself; the host supplies only an
egress admitter for the fixture origins and a transport that maps them to
loopback. Rust uses `AgentIdentityResource::with_further_schemes` and, for a
`Decision::OtherScheme`, the `PreparedRequest` method its member calls for.
The crate never fetches, so the launcher fetches the fixture documents (the
JWKS through the `jwks_uri` that `metadata_jwks_uri` validates) and passes
their bytes to `AgentProviderKeys`, `TrustedIssuerKeys`, `verify_self_jwt`
and `verify_jwks`; for jwks the crate leaves selecting the kid to the host, so
mixed key sets are graded under jwks_uri and the Agent Provider only. Proof
errors are answered with the crate's own `Decision::SignatureFailure`
mapping. The community launcher sends a jwks_uri member to
`VerifyServerRequest` and every other request to `VerifyAndExtractAgent`,
which refuses other schemes itself, and answers failures with
`WriteSignatureFailure`.

The signer posts its result to the job's `transport`, preserving the logical
Host. Go uses `SignHWKRequest`, `SignJWTRequest`, `SignJWKSURIRequest`,
`SignSelfJWTRequest` and `SignRequest` with jwks and jkt-jwt credentials;
Rust uses `sign_request` with the matching `KeyMaterial`; the community
module uses `agentprovider.SignHWK`, `AttachSignatureKey` with `SignRequest`,
`ServerSigner` and `agentprovider.SignJKTJWT`, which read the wall clock.
Schemes and algorithms a library does not offer are listed in
`cmd/build-adapters/sigkey.go` and left unclaimed.

## Community vectors role

`role: "vectors.library"` announces `/vector`. The runner POSTs one JSON
object per case; the launcher calls one public function of its library for
the case's `kind` and answers 200 with the normalized result, or 501
`{"not_offered":"..."}`. It builds an in-memory request from the supplied
method, URL, headers and body and passes the supplied clock, window, required
components, key and trust documents; it never verifies, signs or repairs
anything itself.

| Kind | aauth-go | aauth-rust | community aauth-go |
| --- | --- | --- | --- |
| agent-identifier | `ValidateAgentIdentifier` | `validate_agent_identifier` | `ParseAgentIdentifier` |
| server-identifier | `ValidateServerIdentifier` | `validate_server_identifier` | `ValidateServerIdentifier` |
| jwk-thumbprint | `jose.JWK.Thumbprint` | `Jwk::thumbprint` | `JWK.Thumbprint` |
| metadata | `events.DecodeAgentProviderMetadata` for `aauth-agent.json` only; the others are not offered | `metadata_jwks_uri` | decode into the role's type, then `Validate` |
| signature-error | `signaturekey.ParseError` | `parse_signature_error` | `ParseSignatureError` |
| requirement | `ParseRequirement`, then `ParseAuthTokenRequirement` or `ParseInteractionRequirement` | Agent `Requirement::parse`; deferred values through `PendingResponse::parse` on the 202 framing | `ParseRequirement` |
| signature-key | `signaturekey.PrepareRequest` with default (jwt-only) options | `PreparedRequest::prepare_with_schemes(..., &["jwt"])` | `ParseSignatureKey` |
| jwt | `VerifyAgentToken`, `VerifyPersonToken`, `VerifyResourceToken`, `VerifyAuthToken` with a `StaticKeyResolver` | `AgentToken`, `PersonToken`, `ResourceToken`, `AuthToken` `parse` then `verify` with `TrustedIssuerKeys::from_documents` | `VerifyAgentToken` (agent-token lifetime ceiling lifted, as the module's own vector test does), `VerifyPersonToken`, `VerifyAuthToken`; no standalone resource-token verifier is exported |
| http-signature | `PrepareRequest` then `Verify`; `require_body_coverage` adds content-digest and content-type to the required components | `prepare_with_components` with the vector's required components, then `verify` | `VerifyRequestWithOptions` |

The Go launcher is `adapters/go/vectors.go`, the Rust launcher
`adapters/rust/src/vectors.rs` (feature `vectors`, with the Signature-Key
crate), and the community launcher `adapters/community-go/vectors.go`.

## Signature-Key vectors role

`role: "vectors.signature-key"` announces the path of the bootstrap
`resource` (`/signature-key`). The runner POSTs one JSON job at a time and
the launcher answers with its library's own result. It decides nothing
itself.

A `sign` job carries the request before signing, `created`, an optional
`nonce` and one or more `signatures`: a label, the private key (Ed25519
`seed_hex` or `pkcs8_base64` with `alg`), the scheme and the member's
parameters. The launcher signs with its native signer at `created` and
answers 200 `{"headers":{...}}` with every header field of the signed
request, 501 `{"not_offered":"..."}` when the library has no API for the
job, or 422 `{"error":"..."}` when the library refuses to sign. aauth-go
uses `SignRequests` with the matching `Credential` constructor; it has no
way to present a cache identifier it was not issued. aauth-rust uses
`sign_requests` with the matching `KeyMaterial`; it takes no `nonce`.

A `verify` job carries the received request, `now` and the environment:
the verifier configuration, the documents and the x509 trust. The launcher
answers with its native verifier's HTTP response unchanged, a 200 echo of
the verified scheme or a refusal with `Signature-Error`. aauth-go builds
`resource.NewAgentIdentity` with every further scheme (hwk, jkt-jwt,
jwks_uri, jwks, x509, cached), a fresh `AssertionCache` and a native
`HTTPKeyResolver` whose transport serves the documents from memory; the
host's x509 callback returns the chain from the documents with the trust
anchors and CRLs. A self-jwt member goes straight to `PrepareRequest` and
`VerifySelfJWT`, the verifier the Resource's self-jwt further scheme calls,
and a refusal is a 401
whose `Signature-Error` is `FormatError(NormalizeError(err))`. aauth-rust
builds `AgentIdentityResource` with every further scheme; for a
`Decision::OtherScheme` the host passes the document bytes to the
`PreparedRequest` method the member calls for (`verify`,
`TrustedIssuerKeys::from_documents`, `verify_jwks`, `verify_self_jwt`,
`verify_jkt_jwt`, `verify_x509`, `verify_cached` with an empty
`AssertionCache`) and answers failures with the crate's own
`Decision::SignatureFailure` mapping. As in the sigkey roles, aauth-rust
leaves selecting a direct jwks kid to the host.

The Go launcher is `adapters/go/sigkey_vectors.go`, the Rust launcher
`adapters/rust/src/sigkey_vectors.rs` (feature `sigkey-vectors`). The
community module has no launcher for this role.

## Bootstrap roles

No launcher exists yet for either library. `cmd/build-adapters/bootstrap.go`
reports aauth-go and aauth-rust not offered for all three roles, with the
reason, so a full run grades every assertion `not_claimed`. This section is
the contract a launcher meets. The Bootstrap draft defines no routes or
bodies (lines 371 and 410), so the paths come from
`fixture.extensions.bootstrap` and the bodies are fixed below.

The bootstrap `extension` object carries the fixture AP seed and kid
(`ap_seed_hex`, `ap_kid`), the agent token lifetime (`agent_lifetime`) and,
per role, the paths it serves. Clocks are fixed at the bootstrap `now`.

- `bootstrap.agent-provider` announces `/.well-known/aauth-agent.json` and
  serves the native hosted AP on one listener: metadata and JWKS, and the
  native handlers at `enrollment_path`, `refresh_path`,
  `single_key_refresh_path` and `subagent_path`. Host policy approves every
  enrollment and refresh whatever its empty `evidence`, assigns each durable key its own identifier, issues
  `agent_lifetime` tokens with the `ps` the refresh body names, and approves
  sub-agents of a top-level agent. Enrollment answers any 2xx. Refresh and
  sub-agent issuance answer `200 {"agent_token"}`. Refusals are the native
  answers, unchanged.
- `bootstrap.agent` announces `/control` and configures the native agent's
  bootstrap client with the AP at the bootstrap `issuer`, reached at
  `ap_transport`, the three paths and `person_server` as its `ps`. The agent
  generates its own keys. Each control job runs one native operation and
  answers 200 when it ran: `enroll`, `refresh` (two-key), `subagent` (sends
  the job's `jwk` and `discriminator` with the agent's current token), and
  `call` (a signed request to `url` through `transport` with the current
  token). Requests keep the logical Host. The control answer is not graded.
- `bootstrap.self-hosted` announces `/.well-known/aauth-agent.json`, serves
  the native self-hosted AP's metadata and JWKS, and routes `issue_path` to
  the token-issuing process. `{"agent", "jwk", "ps"}` self-issues a
  top-level token. `{"parent_token", "jwk", "discriminator"}` issues a
  sub-agent of that parent through the native call, which decides whether
  the parent may have one. Both answer `200 {"agent_token"}`, or the native
  refusal as a 4xx.

Native APIs a launcher would use: aauth-go has `agentprovider.EnrollmentService`
(`EnrollmentHandler`, `RefreshHandler`, `SingleKeyRefreshHandler`),
`Server.SubagentHandler`, `Server.Issue`, `Server.IssueSubagent`,
`SelfHostedAgent` and `agent.BootstrapClient`. aauth-rust has `AgentProvider::issue`,
`AgentProvider::issue_subagent` and `PreparedRequest::verify_jkt_jwt`, and
no enrollment or refresh service.
