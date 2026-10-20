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
credential; protocol-prescribed child token errors also check status and code.
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

The Go build helper currently emits an explicit unavailable target for this
complete role, with revision `not_measured`, no command and no claims. It reads
and builds no Go source. The runner records every Go assertion as `not_claimed`
without launching a process. Go already implements immediate parent mediation;
this declaration describes the unimplemented/unqualified shared role adapter
and deferred child integration. It does not establish a Go library failure or
pass. Its existing immediate and deferred top-level roles remain available.
A later Go cycle can enable the same scenarios and expectations after native
adapter support is ready.
