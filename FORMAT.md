# Scenario format, version 1

The suite directory contains `fixture.json`, `clauses.json` and nonempty
`scenarios/*.json`, loaded in filename order. Unknown fields, unsupported versions,
duplicate scenario/assertion/clause IDs, unknown clauses and invalid fixture keys
are errors. Use unique JSON object member names: the Go JSON decoder otherwise
uses its standard last-value behavior for duplicate object members.

The fixture supplies a shared `id`, fixed Unix-second `now`, logical HTTPS
`issuer`/`origin`, Resource `path`, AP `kid`, Agent `subject` and two 32-byte
hex Ed25519 seeds. The AP seed is RFC 8032 test vector 1; the Agent seed is synthetic.

The suite SHA-256 hashes relative filename, byte count and exact bytes of the
fixture, catalog and sorted scenarios, separated by NULs. It identifies inputs
and expectations, including formatting; it does not identify the runner executable.

The catalog has `version: 1`, `sources` and `clauses`. Sources record full commit,
SHA-256 and permanent URL. Each clause has `id`, `source`, `section`, URL `anchor`
and `scope`: `protocol`, `adapter-contract`, `recommended` or `out-of-slice`. Optional `role`
defaults to `resource.agent-identity`; Agent clauses use `agent.signing`. These reference
source headings rather than replace normative text. Re-pinning requires reviewing
the referenced text and expectations even when clause IDs stay unchanged.

## Requests and assertions

A scenario has `version`, unique `id`, `title`,
`role_under_test` (`resource.agent-identity`, `agent.signing`,
`person-server.direct`, `authorization.federated`, `authorization.deferred` or
`authorization.subagent`), `given` matching the fixture ID,
`token`, `request` and nonempty `assertions`. See [valid](scenarios/02-valid.json).

`token.iat_offset`/`exp_offset` are seconds relative to the fixed clock. JWT `jti`
is the scenario ID; `dwk` is `aauth-agent.json`. Issuer, subject and confirmation
key come from the fixture. Protected `alg` is `Ed25519`, `typ` is `aa-agent+jwt`.

For `resource.agent-identity`, `request.method` is GET and `path` equals the fixture
path; bodies, queries, custom headers and multiple exchanges are outside that
profile. `proof` is `unsigned`
or `jwt`; `created_offset` is relative to the fixed clock. `covered` is an ordered,
non-repeating list from `@method`, `@authority`, `@path`, `signature-key`. Omitting
a component creates a valid signature over deliberately incomplete coverage.
`tamper_signature: true` flips a signature byte after signing. Only physical
loopback addresses differ between targets; logical requests/JWTs/proofs are identical.

`request.endpoint: "person"` selects `fixture.person_path` instead, an endpoint
that requires the person's identity; `path` must equal it. There `proof` may
also be `person`: a fixture Person Server Person token (`aa-person+jwt`, `aud`
the fixture origin, `sub` the fixture person subject, `cnf` the Agent key, the
`token` offsets) signed like `jwt`. Remote mode does not exercise these
scenarios, since a deployment names one Resource endpoint.

For `agent.signing`, method is GET or POST, path is an origin-relative path with
optional query, `proof` is `sut`, and optional `headers` accepts Authorization.
Bodies are empty, `created_offset` is zero, and the Agent receives a valid fixture
token. Its native API generates Signature-Key/Input/Signature. No expected
signature bytes or signature base are sent to the launcher. The third scenario
requires query and Authorization coverage as a receiving application profile;
there is no additional-component API argument in this limited adapter contract.

Every assertion has unique scenario-local `id`, `clause`, `kind`, and `equals`.
Resource kinds:

| Kind | Other fields | Check |
| --- | --- | --- |
| `status` | — | HTTP status equals the integer. |
| `sfv-token` | `header`, `member` | All header lines parse as a dictionary; member is an Item whose Token equals the string. A quoted string fails. Unknown members are ignored. |
| `sfv-strings` | `header`, `member` | Member is an Inner List of Strings exactly matching the array; use when order is significant. |
| `sfv-string-set` | `header`, `member` | Same String list type, comparing component membership without order/duplicates; used for required coverage. |
| `json-member` | `member` | Object contains that top-level member with equal value/type. Absence differs from null. |
| `problem-if-present` | — | On application/problem+json, require object type `urn:ietf:params:sig-error:` plus expected code, and any status must match HTTP. Other body representations yield `not_exercised`. |

Agent kinds (each clause must belong to the scenario's role):

| Kind | Check |
| --- | --- |
| `wire-preserved` | Method, logical URL, empty body, exact presented token and canonical Authorization value match the input; an invented Authorization also fails. |
| `wire-proof` | Independent Ed25519 verification of the actual received signature base, with matching Signature-Key/Input/Signature labels and AP-bound confirmation key. |
| `wire-token` | Presented JWT verifies under the fixture AP, with expected alg/type/kid/issuer/subject/discovery document/confirmation key and unexpired `exp`. This checks presentation, not SUT client verification. |
| `wire-created` | Signature-Input `created` equals the configured Unix-second clock. |
| `wire-covers` | Listed component Strings are covered; order may differ and additional supported fields may be present. |

An Agent scenario with `request.endpoint: "person"` (path `fixture.person_path`)
runs the person flow in ADAPTERS.md: the harness Resource asks for a Person
token and the harness Person Server issues one. The optional
`request.resource_metadata_unpublished: true`, allowed only there, has that
Resource publish no metadata document and answer a read of it `404`.
`token.ps: true`, allowed only
there, names the fixture Person Server in the Agent token's `ps` claim. Its assertions use only the
boolean kinds `wire-person-request` (one valid signed Person token request
naming this Resource) and `wire-person-token` (one retry presenting the issued
token under a valid Agent-key signature); other Agent scenarios cannot use them.

The Agent oracle supports only Ed25519 JWT credentials, bodyless requests,
`@method`, `@authority`, `@path`, `@query`, `signature-key` and `authorization`,
without component parameters. Header values use RFC 9421 field canonicalization
(trim outer SP/HTAB, combine field lines with comma-space). The oracle is not a
general AAuth server or JWT validator. Other algorithms, full Signature Parameter
validation, bad-token client behavior and discovery negotiation need later cases.

## Targets and reports

A target file has `version: 1`, optional `role` (default `resource.agent-identity`)
and nonempty `implementations`. `agent.signing` selects the three Agent cases.
Reports contain only the selected role's clauses/cases; the suite digest still
covers all files, so adding another role changes it. Each entry has
unique `id`, `revision`, executable `command` array and explicit `claims` of known
clause IDs. Commands execute directly without a shell; relative commands resolve
from the runner's working directory. The helper declares the selected role's
protocol and adapter-contract clauses; `-claim-recommended` adds the SHOULD-level `recommended` clauses, which are otherwise reported `not_claimed`. It also claims the `out-of-slice` clauses `cmd/build-adapters/adopted.go` lists for that implementation. Edit the manifest to narrow claims. Reports retain declared provenance.

Unclaimed assertions are `not_claimed`. Claimed assertions are `pass`, `fail`,
`error` (transport/startup) or `not_exercised` (conditional representation absent).
Clause cells prioritize failure, error, observed passes, then no exercised
assertions. Counters retain conditional absences even alongside observed passes.
A clause pass covers only its listed assertions. No section percentage is computed.

JSON reports retain base64 response bytes, headers, logical request headers/base
and assertion expected/actual/detail values. Bodies are bounded to 64 KiB;
redirects and timeouts are errors. Markdown shows the matrix and assertion evidence.
Any assertion failure, transport error or adapter startup error makes the run unsuccessful;
so does an all-unclaimed or all-unexercised run.

A remote-mode report (see [REMOTE.md](REMOTE.md)) adds `"transport": "remote"`
and names the deployed servers it tested under the implementation's `remote`,
by party, with the `agent` and `control` it names. Its claims default to the role's protocol and adapter-contract
clauses, as for a launcher. A scenario remote mode cannot exercise keeps its
assertions, each `not_exercised` with the reason in `detail`.

Execution errors are retained on the case independently of clause claims. They
make overall execution fail even when that case's assertions are not claimed.

## Person Server direct profile

`fixture.person_server` supplies issuer, public test signing seed/kid, configured
person subject, Person/Auth lifetimes in seconds, permitted scopes, and the
Resource's public test signing seed/kid. These bytes participate in the suite
digest. This fixture permits only `read`; requests for `admin` are host denials.

Person Server scenarios use `role_under_test: "person-server.direct"` and
`person: {"mutation":"..."}`. They omit `request`: the role prescribes signed
POST `/person` and POST `/token` with JSON and covered body digest/type. Request
fields on this role are rejected to avoid silently ignoring authored inputs.
`token` offsets select the AP Agent token interval. `short-parent` selects a
45-second parent explicitly. Supported mutations are `none`, `tampered-proof`,
`tampered-body`, `wrong-aud`, `wrong-jkt`, `wrong-sub`, `wrong-jti`, `wrong-ps`,
`expired-resource`, `expired-presented`, `denied-scope`, and `short-parent`.

Each assertion names `stage: "person"` or `"token"`, a role-specific clause,
and one expected answer shared by all targets. Existing `status`, `sfv-token`
and `json-member` work against that stage's actual response. New boolean kinds:

| Kind | Check |
| --- | --- |
| `ps-jwt-signature` | Independent Ed25519 verification plus exact alg, typ and fixture kid. |
| `ps-jwt-identity` | PS issuer/discovery document, Resource audience (a string, or the one-member array RFC 7519 also permits), nonempty subject/JTI; Auth PS and subject match presented Person lineage. This fixture forbids unexpected mission, tenant and delegation fields. |
| `ps-jwt-subject` | Subject equals the configured host binding; adapter contract. |
| `ps-jwt-key` | Confirmation public JWK equals this Agent's fixture key. |
| `ps-jwt-lifetime` | Integer issued time at fixture now, positive current expiry, one-hour and Agent/presented parent bounds; response expires_in equals signed expiry. Resource-token expiry is not an Auth-token parent bound. |
| `ps-jwt-no-authorization` | Person claims contain neither scope nor account. |
| `ps-jwt-scope` | Auth token has exactly configured read scope, no unrequested account; adapter contract. |
| `ps-no-token` | Parameter-token refusal JSON object releases neither Person nor Auth token. |
| `ps-jwt` | Combined valid fixture JWT profile, available for composite tests. It grades subject lineage, not the configured host subject, which only `ps-jwt-subject` grades. |

Reports retain ordered `exchanges`, each with stage, actual method/logical URL,
headers, base64 request body, signature base, response and independently observed
JWT claims/results. The Resource JWT is derived only after a returned Person JWT
passes the independent oracle. A failed prerequisite remains a case execution
error even if an assertion for another stage is unclaimed. Missing required
stages are errors. Protocol failures remain failures, never target-specific
alternative expected answers.

## Four-party authorization profile

`fixture.access_server` adds a distinct HTTPS issuer, public test seed and kid;
the Person Server fixture also supplies the native Resource's signing seed.
`role_under_test: "authorization.federated"` uses `federated.mutation` and omits
`request` and `person`. Role identities must differ. The loader rejects
incompatible assertion stage/kind combinations.

The runner performs the prescribed native exchange in stages:

| Stage | Observed operation |
| --- | --- |
| `initial` | Agent-identity request to Resource; person-token challenge. |
| `person` | PS issues the Person token used in the next request. |
| `challenge` | Resource challenges that exact Person token for authorization at the AS. |
| `handoff` | Native PS's signed AS POST, before any injected fault. |
| `access` | Native AS response, before any injected fault. |
| `token` | Native PS response to the Agent. |
| `protected` | Resource consumes the delivered Auth token; positive cases only. |

`federated.harness_ps: true` selects the independent PS driver. It issues the
fixture Person token itself and signs the AS request with independent Ed25519
code. Native PS endpoints are never called. PS delivery faults (`grant-*`) and
assertions on `person`, `handoff`, or `token` are rejected. The ten
`fixture-ps-*` scenarios use only `initial`, `challenge`, `access`, and
`protected`. Budget scenarios 74–78 use the same driver and may also assert
`step-up`, `step-up-other`, `reserved`, `following`, `usage`, `usage-unknown`,
`usage-no-ps`, `usage-two-keys`, `usage-jkts`, `second-token`,
`second-protected`, and `refusal`. The runner records `usage-baseline` and
`second-challenge` for later stages and does not grade them. The default
driver uses the native PS and the stages in the table above.

`fed-challenge` checks the Resource JWT's signature, actual presented JTI,
PS/person/key context, AS audience, scope and current expiry.
`fed-ps-proof` verifies native PS `jwks_uri` identity, Ed25519 proof, required
coverage, and digest of actual body bytes. `fed-forwarded` requires the three
compact token parameters to equal those supplied to the PS exactly. These kinds
require boolean expectations and their corresponding stage. The `ps-jwt*` and
`ps-no-token` kinds work on Person, AS and delivered-token stages; generic HTTP
assertions work on every response stage.

Mutations are `none`, `short-agent`, `as-proof`, `as-body`, `as-resource-aud`,
`as-resource-jti`, `as-resource-ps`, `as-resource-key`, `as-presented-expired`,
`grant-signature`, `grant-iss`, `grant-aud`, `grant-key`, `grant-sub`,
`grant-scope`, `grant-exp`, `grant-ps`, and `as-denial`. Request-context mutations
are signed by the fixture Resource/PS keys and then re-signed as PS requests,
so they isolate context checks from cryptographic corruption. Grant mutations
preserve the native AS response separately, then alter and re-sign one claim
(or deliberately sign with the wrong key).

`federation_handoff` retains original and delivered request bytes, independent
PS proof observation, exact-token comparison, native and delivered responses,
and any relay error. An absent handoff or relay error fails execution even if
its clauses are unclaimed. Reported `access` assertions always grade native AS
output; `token` assertions grade what the native PS actually delivers.

`federated.budget` is omitted, `grant`, `omit`, `consume`, `header`, `usage`,
or `cap`. Omitted keeps the reactive person-token challenge on the fixture path
and offers no Budget. The other modes replace that challenge with one signed
`POST {origin}/authorize`. The JSON body is
`{"scope":"read","budget":{"amount":N,"unit":"credits","decimals":0}}`.
`grant`, `consume`, `header`, `usage`, and `cap` request 5000000. `omit`
requests 9000000. The Resource offers that requested amount unchanged. Its
metadata maximum for `credits` and for `points`, both at decimals 0, is
10000000. The `challenge` stage for these modes is the authorization response
(`200` and `resource_token`), not the reactive `401`.

`grant` is the native four-party Budget case. The native Person Server narrows
a 5000000 offer to 2000000 and the Access Server echoes that amount. The
protected call uses `{path}-budget-grant`. With no `X-Fixture-Cost` header its
cost is 1000, so `remaining` is 1999000. Header `cost` is optional in the
draft; this fixture knows the cost before it writes the header, and the
scenario grades that header.

`omit`, `consume`, `header`, `usage`, and `cap` set `harness_ps`. The harness
signs the PS-to-AS request. For `omit` that request has no `budget` member, and
the auth token must omit the `budget` claim. The protected call uses
`{path}-budget-omit`, which is not metered, and returns the subject. For
`consume`, `header`, `usage`, and `cap` the harness request carries
`{"amount":2000000,"unit":"credits","decimals":0}`. That figure is one
per-token allocation. Both current Access Servers echo it. The draft permits a
lower amount; this fixture grades the echo.

`consume` uses `{path}-budget-grant`. It sends `X-Fixture-Cost: 1500000` on
`protected`, then `X-Fixture-Cost: 1000000` on `step-up`. That second call does
not fit and does not draw the grant down, so `remaining` stays 500000. The
fresh Resource token offers 5000000 credits. `fed-consumed` on `step-up`
requires `budget_consumed`: `jti` equals the presented auth token's `jti`,
`consumed` is 1500000, and the claim has those two members. `step-up-other`
repeats the refusal with `X-Fixture-Offer: points`. Those headers are unsigned
fixture policy. `fed-consumed-if-present` passes when `budget_consumed` is
absent. When the claim is present, `consumed` must be 1500000, the claim must
have exactly two members, and that Resource token's `budget` must be `credits`
at decimals 0. A record stated in another scale fails.

`header` uses `{path}-budget-reserve`. `X-Fixture-Hold` is the reservation and
`X-Fixture-Settle`, when present, is the cost committed after the body. Both
are unsigned fixture headers. The `reserved` call holds 800000 and settles
400000, so the header is `remaining` 1200000 and `reserved` 800000 with no
`cost`. `sfv-trailer-if-present` passes when the `AAuth-Budget` trailer field
is absent. When the field is present, `cost` must be 400000.
`sfv-trailer-absent` still requires `remaining` and `reserved` to be missing
from a trailer that is present, and passes when no trailer is sent. The
harness reads trailers with the Go HTTP client. That client removes the
`Trailer` header after parsing and exposes only declared trailer fields, so a
scenario does not grade the `Trailer` header itself. The `following`
call holds 100000 and settles 100000. Header `remaining` is net of that new
hold: 2000000 - 400000 - 100000 = 1500000, and `reserved` is 100000. There is
no abandoned request.

`usage` charges 1000 on `{path}-budget-usage`. Before that charge the harness
`POST`s `{origin}/usage` as `usage-baseline`, signed as the Access Server
(`jwks_uri`, access seed, `kid` `as-1`). It repeats the query as `usage` after
the charge. The known subject is `directed-person-1` with `ps`
`https://person.conformance.test`. The ledger key is `(ps, sub, aud)`.
`all_time` is cumulative for that key, including earlier scenarios in the same
process. `usage-delta` subtracts the baseline `all_time` from the later one.
An omitted `usage` object on the baseline counts as 0. The later object must
contain `all_time`, and the difference must be 1000. The response is graded
for `aud` `https://access.conformance.test`, unit `credits`, and decimals 0.
Subject `unknown-person` returns 200, omits `usage`, and still reports
`credits` at decimals 0. An Access Server scope key without `ps` is HTTP 400
`invalid_request`, as is a body with both `sub` and `tenant`. A `jkts` array
containing only an unknown thumbprint returns `"jkts":{}` rather than a zero.

`cap` uses `{path}-budget-grant` and the harness allocation. It spends 1500000
on the first auth token (`remaining` 500000), then repeats authorization. The
second auth token is another harness Access Server POST with the same 2000000
allocation. It spends 1500000 on that token. A following 1000000 on the first
token is refused and leaves that token's `remaining` at 500000. Each auth
token is its own cap.

`fed-budget` compares the JWT `budget` object on `challenge`, `access`,
`token`, `step-up`, `step-up-other`, or `second-token`. `null` requires the
claim to be absent. `fed-consumed` compares `budget_consumed` on `step-up` or
`step-up-other`. An object `{"consumed":N}` also requires `jti` to equal the
presented auth token's `jti` and exactly two members. `sfv-integer` compares
one bare integer member of a dictionary header. `sfv-absent` requires that
member to be missing. `json-path` walks dot-separated object members. `null`
means the path is absent; a present value, including JSON null, fails.
`header-equals` compares one header value; an empty string means the header
is absent.

## Deferred four-party profile

`role_under_test: "authorization.deferred"` uses the same four-party fixture,
omits `request`, `person` and `federated`, and supplies `deferred.outcome`:
`payment`, `approval`, `denied`, `invalid-grant` or `foreign-location`.

Stages are `access` (initial native AS response), `pending` (initial native PS
response), `waiting` (Agent poll), `approval` (AS poll after payment), `result`
(terminal AS poll), `token` (PS delivery), `protected` (Resource use), `gone`
(repeated Agent poll) and `as-gone` (repeated authenticated PS poll). The runner
also retains prerequisite Person/challenge and host-control exchanges. Only
stages reached by the selected outcome can satisfy assertions.

Boolean `deferred-pending` checks same-origin Location and the response shape:
202 requires nonnegative integer Retry-After, no-store and a nonempty JSON
status string; the payment profile requires 402 with WWW-Authenticate.
`deferred-stable` additionally requires the previous pending URL. The loader
limits pending checks to access/pending/approval, stable checks to
waiting/approval, proof checks to access/approval/result, and exact initial
forwarding to access; an absent proof observation is an error.
`deferred-proof` independently verifies native PS POST or bodyless GET proof
at the actual endpoint. `deferred-forwarded` checks exact initial Resource,
presented and Agent token bytes. The existing `ps-jwt-*`, `ps-no-token`, status,
JSON-member and Structured Field token assertions grade actual responses.

`deferred_handoffs` retains each original/delivered request and response,
independent proof observations and relay errors. A failed prerequisite or relay
error fails execution independently of claim selection. These scenarios do not
advance time or exercise persistence beyond the running native role instances.

## Parent-mediated child slice

`role_under_test: "authorization.subagent"` uses the existing Person/AS fixture
and adds `subagent: {"outcome":"..."}`. Its request profile is prescribed by the
driver; `request`, `person`, `federated` and `deferred` fields must be absent.
Allowed outcomes are `direct`, `immediate`, `approval`, `payment`, `denied`,
`cancel`, `expiry`, `revoked-pending`, `revoked-binding`, `wrong-parent`,
`wrong-provider`, `wrong-key`, `depth`, `expired-child`, `child-direct`,
`child-poll`, `short-child` and `short-parent`. Both implementations receive identical wire
inputs and literal expectations when they claim this role.

The `wrong-provider` outcome requires `subagent.foreign_provider` with a distinct
HTTPS `issuer`, `kid` and public fixture `seed_hex`. The seed signs the fixture
Agent input, and a separate runner-owned AP transport serves its actual metadata
and public JWKS. Its child has a matching foreign-provider subject and the
original parent_agent. No other outcome accepts this foreign fixture.
`short-parent` supplies a 45-second parent and a 600-second child; the independent
Person and Auth oracles apply the shorter parent ceiling.

The `depth` outcome is a top-level-parent-signed request carrying a grandchild
Agent token. Its subject has two `+` segments, and its authoritative
`parent_agent` names the child. It expects `400 invalid_subagent_token` and no
credential; `subagent.depth` covers this grandchild parameter refusal only.
`child-direct` separately checks refusal of a child-signed PS request under
`subagent.mediation`. Both `revoked-binding` and `revoked-pending` pin HTTP `400`
and JSON `error: revoked_presented_token`, alongside no-credential checks.

Each assertion names an exercised stage. `subagent-jwt` independently validates
native child-bound Person/Auth credentials; `subagent-proof` checks observed
native PS signatures; `subagent-forwarded` compares all four exact token
compacts; `subagent-pending` checks same-origin pending response shape;
`subagent-refused` requires 4xx with no credential; `subagent-no-token` requires
no credential; and `subagent-cancelled` requires 2xx with no credential.
These kinds require boolean `equals`. Ordinary `status` and `json-member`
assertions remain available. The loader rejects kind/stage combinations for
which the runner has no observation. Reports retain request/response bytes,
independent JWT claims and separate PS/AS handoffs.

An optional target `unavailable` string is permitted only for this role, with
empty `command` and `claims`. It is a declaration of missing adapter support;
all its assertions remain `not_claimed`, and an all-unavailable run cannot pass.
No launcher is started and no native response is invented for such a target.

## Events profiles

Four extension roles grade draft-hardt-aauth-events at `70d6737` (catalog
source `events`). `fixture.extensions.events` supplies the event Resource and a
second Resource (HTTPS issuer, public test seed, kid), the subscription and
ticket paths, the AP's `event_endpoint`, a second Agent identifier and an
unrelated public test key. Scenarios carry their inputs in `input`; every
assertion names a `stage`.

| Role | `input` | Stages |
| --- | --- | --- |
| `events.subscription` | `mutation` (`none`, `expired`, `wrong-aud`, `wrong-typ`, `wrong-dwk`, `empty-eid`, `cnf-mismatch`, `bad-signature`); optional `ticket` (`bound`, `other-key`, `reused`) | `registration`; `ticket` and, for `reused`, `first` |
| `events.agent-provider` | `max_uses` (0 is unlimited), up to 8 `deliveries`, each `mutation` and `body`, and optional `pending` | `metadata`, `subscribe`, `delivery-N`, `pending` |
| `events.agent` | `mutation` and `body` | `event` |
| `events.delivery` | `max_uses` and `fires`, a list of booleans (with or without a body) | `registration`, `fire-N`, `delivery-N` |

The harness plays the Agent and AP for registration: it mints the subscribe
token under the fixture AP key and signs the POST with covered `content-type`
and `content-digest`. A ticket case first sends a fixture person token to the
launcher's ticket control. For the AP it plays the Resource: it reads the
native subscribe token's `eid`, mints event tokens under the Resource key and
signs each delivery under `self-jwt`. Delivery mutations change one property:
the body digest, `cnf`, expiry, `typ`, coverage, the proof key, `kid`, `eid`,
the issuing Resource, `aud` or the token signature. For the Agent it mints the
event token and hands token and body to the launcher's event control. For a native Resource's delivery it registers a
subscription, asks the launcher to fire each event, and captures the signed
delivery at its own loopback AP, which publishes `event_endpoint` and answers
`202`.

Two kinds are added. `events-subscribe-token` (stage `subscribe`, boolean)
verifies the native subscribe token under the fixture AP key with `typ`
`aa-subscribe+jwt` and checks `iss`, `dwk`, `sub`, `aud`, `cnf`, nonempty `eid`
and `jti`, `iat` before an unexpired `exp`, and `max_uses` exactly as
requested. `events-accepted` (stage `event`, boolean) is the native Agent's
acceptance as the launcher reports it. `events-pending` (stage `pending`, boolean) requires the
native AP's retained deliveries for the Agent to hold each `202` delivery once
with its exact token and body, and no refused one. `events-delivery` (stage `delivery-N`,
boolean, `member` naming the property) grades a captured delivery with
independent code: `self-jwt` (an `aa-event+jwt` under the Resource key with
`iss`, `dwk`, the subscribed Agent as `aud`, `jti`, `iat` and an unexpired
`exp`), `eid` (equal to the subscribe token's), `cnf-absent`, `body-s256`
(present and equal with a body, absent without), `coverage` (base components,
plus `content-digest` matching the body and `content-type` with a body) and
`proof` (the HTTP signature verifies with the same key). Generic kinds grade the responses,
including `status-class` and `sfv-token-present` where the draft fixes no
status or code.

## R3 profiles

Two extension roles grade `draft-hardt-aauth-r3` at `70d6737` (catalog source
`r3`). Fixture `extensions.r3` names the vocabulary (`urn:aauth:vocabulary:mcp`),
the Resource's authoritative `tools`, the `grantable` tools of the issuer's
fixed consent, and an `other_server` (issuer, public seed, kid): a server both
launchers trust but that no R3 document entitles. Each scenario starts a fresh
launcher. Scenario inputs are in `input`; every assertion names a `stage`.

`role_under_test: "r3.resource"` puts a native Resource under test. The harness
is Agent, AP, PS and (four-party) AS: it mints the Person token and the Auth
tokens itself and signs every request. `input` has `topology` (`four-party`
or `three-party`), `operations` (tools requested in `r3_operations`), optional
`vocabulary` (`urn:aauth:vocabulary:openapi` to request an unadvertised one),
`fetches`, `grant` and `per_call` (the harness Auth token's `r3_granted` and
`r3_per_call`), `calls` and `per_call_flow`. Stages, in order:

| Stage | Exchange |
| --- | --- |
| `metadata` | unsigned GET of `/.well-known/aauth-resource.json` |
| `authorize` | POST `/authorize` with `r3_operations`, Person token in `Signature-Key` |
| `fetch-<mode>` | GET `r3_uri` as `access` (AS, `jwks_uri`, `aauth-access.json`), `person` (PS, `aauth-person.json`), `other` (the other server), `agent` (Person token, `jwt`), `unsigned`, or `tampered` (AS id, flipped signature); a repeated mode is `fetch-<mode>-2` |
| `call-<tool>` | POST `/op/<tool>` `{"record":"r-1"}` with the harness Auth token |
| `fetch-proposal` | AS-signed GET of the proposal named by the per-call challenge |
| `retry-<tool>`, `repeat-<tool>` | the call with the harness per-call Auth token; `mismatch` retries with `{"record":"r-2"}`, `complete` retries and repeats |
| `executions` | the launcher's count of executed calls per tool (host control) |

Kinds: `r3-vocabularies` (keys of `r3_vocabularies` are URIs, standard-namespace
keys name a defined vocabulary, MCP is advertised), `r3-resource-token`
(Resource-key Ed25519, `aa-resource+jwt`, Resource `iss`, topology `aud`, both
`r3_uri` and `r3_s256`), `r3-no-resource-token`, `r3-document-digest` (status
200 and SHA-256 of the served bytes equal `r3_s256`), `r3-no-document`,
`r3-document-fields`, `r3-document-covers` (the document's operations include
each requested one), `r3-per-call-challenge` (401 or 202 `requirement=auth-token`
whose Resource token names a proposal, the AS and the class Auth token's
`jti`), `r3-proposal` (exactly the invoked operation and its `record`
parameter), `r3-executions` (a count) and `r3-single-use` (one execution after
the repeat; `not_exercised` when the approved call never ran). All but
`r3-executions` take boolean `equals`. Generic kinds grade any stage's
response. R3 exchanges are ordinary persistent HTTP/1.1 requests: unlike the
other roles' transport they send no `Connection: close`.

`role_under_test: "r3.issuer"` puts a native three-party PS under test. The
harness is Agent and AP (the PS issues the Person token natively), and the
Resource: it mints an R3 Resource token whose `aud` is the PS and serves the
document at `r3_uri` on a loopback endpoint the launcher reaches. `input` has
`document` (`exact`, `altered`: equal-length bytes that do not hash to
`r3_s256`, or `missing`: 404), `operations` and optional `scope` (`read`).
Stages are `person`, `fetch` (the requests that reached the R3 endpoint; only
role kinds) and `token`. Kinds: `r3-fetched` (every request was a GET of
`r3_uri` and at least one arrived), `r3-fetch-proof` (each verifies as the PS
under `jwks_uri` with `id` its issuer and `aauth-person.json`, covering the base
components), `r3-auth-token` (PS-key `aa-auth+jwt`, PS `iss` and `ps`, Resource
`aud`, the Resource token's `r3_uri`/`r3_s256`, `r3_granted` in the vocabulary
with operations from the document), `r3-auth-scope` (the issued `scope`) and
`r3-no-auth-token`.

`role_under_test: "r3.federated-issuer"` puts a native four-party PS and AS
under test as one bundle. The harness is Agent, AP and Resource: the Resource
token's `aud` is the AS and the document endpoint chooses the bytes it serves
by the `jwks_uri` id a request names. `input.document` is `exact`, `altered-as`
or `altered-ps` (bytes that do not hash to `r3_s256`, served to that signer
only). Stages are `person`, `fetch-access` and `fetch-person` (the requests
naming that server; role kinds only) and `token`. `r3-fetched` and
`r3-fetch-proof` grade the AS or PS fetches; a PS that makes no fetch leaves
its proof `not_exercised`, and a request naming neither server fails both.
`r3-auth-token` checks the AS-issued token (AS key, `aauth-access.json`, PS in
`ps`) as for the three-party issuer. A target may be declared unavailable for
this role.

## Mission profiles

`role_under_test: "mission.person-server"` runs a native Person Server with
its mission endpoint, permission and audit. `"mission.resource"` runs the
native four-party bundle and reads only the Resource's challenge. Scenarios
carry `input: {"flow": "..."}`; the expiry flow adds `expires_in` (1-50
seconds). Agent tokens are prescribed by the driver, so `token` is omitted.
`fixture.extensions.missions` names a second Agent (`other_agent_seed_hex`,
`other_agent_subject`, issued by the fixture AP) and the proposal
`description`. Each scenario starts a fresh native bundle.

The driver reads `mission_endpoint`, `person_token_endpoint`,
`auth_token_endpoint`, `permission_endpoint` and `audit_endpoint` from the
Person Server metadata, proposes a mission naming the fixture Resource and
accepts either a `200` approval or a `202` with a same-origin `Location`. For
`202` it asks the host to approve, then polls as the Agent. It then asks the
host to record the approval for issuance. Flows and the stages they observe:

| Flow | Stages after `approval` |
| --- | --- |
| `approval` | `metadata`, `proposal`, `read` (owner GET of `{mission_endpoint}/{s256}`) |
| `person-token` | `person` (POST person token naming the mission) |
| `unknown-mission`, `malformed-mission`, `other-agent` | `unknown`, `malformed`, `other` |
| `action-missing`, `action-unknown` | `action` |
| `not-owned` | `not-owned` (second Agent, owner's mission), `unknown` (second Agent, absent mission) |
| `update` | `action`, `person` |
| `completion` | `action`, `after-update`, `after-completion`, `after-person` |
| `completion-token` | `person`, `before-token`, `action`, `after-token` |
| `expiry` | `person`, then the clock moves past `expires_at`: `after-person`, `after-update` |
| `governance` | `before-permission`, `before-audit`, `action` (completion), `after-permission`, `after-audit` |
| `resource-copy` (Resource role) | `challenge` |

Role kinds, all boolean: `mission-endpoint-url` (https, no query or fragment),
`mission-s256` (SHA-256 of the decoded bytes, unpadded base64url),
`mission-encoded` (unpadded base64url), `mission-blob` (`agent` equals the
fixture Agent, RFC 3339 `approved_at`, nonempty `description`),
`mission-served` (bytes served later equal the approval; `not_exercised` when
the PS does not expose the mission), `mission-person-token` (verified person
token for the Resource, bound to the Agent key, carrying the approved
`mission_s256`), `mission-person-exp` (`exp` no later than `expires_at`;
`not_exercised` without one), `mission-no-token`, `mission-equivalent`
(same status, body bytes and header names apart from `Date`) and
`mission-resource-copy` (the challenge's Resource token verifies under the
fixture Resource key and carries the presented `mission_s256`). Generic kinds
grade the stage's response. When the approved blob has no `expires_at`, the
expiry flow's later stages are `not_exercised` with the reason recorded.

## Supervision profiles

Two extension roles grade draft-hardt-aauth-supervision (catalog source
`supervision`) from both sides. Identities are in `fixture.extensions.supervision`:
the supervisor's issuer, seed and kid, the directed `subject` the harness
Person Server connects, a second Person Server the supervisor's host refuses
(`other_person_server`), a second supervisor whose keys a Person Server admits
but never calls (`foreign_supervisor`), and the mission blob a harness Person
Server reports. The harness Person Server of the first role is
`fixture.person_server`. All seeds are public test vectors.

### `supervision.server`

The native supervision server is under test and the harness is its Person
Server. `input.steps` is an ordered script; every step names a unique `stage`.
A request step names an `endpoint` (`metadata`, `connect`, `mission`,
`mission/$s256`, `decision`, `event`, or `location:<stage>` for the pending
URL an earlier stage returned), an optional `method`, and a JSON `body`
template. It is signed under `jwks_uri` by `signer` `ps` (default) or
`other-ps`, or sent `unsigned`; `omit_body_components` sends the body's
Content-Type and Content-Digest but leaves them uncovered; `accept_signature`
adds the Accept-Signature a Person Server sends; `repeat` resends an earlier
stage's exact bytes. `expect` is a prerequisite status: any other ends the
case as an execution error. A `control` step posts its object to the
launcher's host control instead. A control the launcher answers `501` with
`not_offered` marks every claimed assertion `not_exercised` with that reason:
the implementation does not offer the duty, which is never a pass.

Body placeholders are whole JSON strings: `$now` and `$exp` (the clock and 60
seconds later, as numbers), `$sub`, `$agent`, `$resource`, `$agent_token`,
`$resource_token`, `$presented_token`, `$mission` and `$s256`. The forwarded
tokens are signed by the fixture issuers; the supervisor treats them as
opaque. An unknown placeholder is a loader error.

Assertions name a request `stage`. Generic kinds grade that stage's response.
Boolean kinds: `ss-signed` (a response signature that verifies under the
fixture supervisor key, with `Signature-Key` `jwks_uri` naming its issuer and
`aauth-supervisor.json`, covering `@status`, `content-type` and
`content-digest`, `;req` components taken from the request, and a matching
Content-Digest); `ss-same-response` and `ss-same-location` (equal to the stage
named in `member`); `ss-pending` (202, same-origin Location, integer
Retry-After); `ss-metadata-endpoints` (the four endpoints HTTPS on the
issuer's origin); `ss-retry-after`; and `ss-no-decision` (a refusal carries
no `decision`).

### `supervision.person-server`

The native Person Server is under test with supervision routing every Agent
to the harness supervisor. The harness is that supervisor, the Agent and its
Agent Provider. `input.act` is `person_token`, or `auth_token` or
`mission_proposal` (each after a person token the supervisor allows);
`input.decision` is how the harness supervisor answers that act: `allow`
(signed; `allow_exp_offset` sets its `exp`; a proposal is allowed as
proposed, with its description), `allow-no-description` (proposals only),
`deny`, `ask`, `defer` (202 with a pending URL; a poll then gets a signed
allow), `server-error`, `wrong-sdi`, `bad-signature` (another key under the
supervisor's id), `foreign-signer` (the foreign supervisor's valid signature)
or `unsigned`. Every other supervision request is allowed. `second_act`
requests a second person token.

The stages are `person`, `token`, `mission`, `poll` (the Agent's poll of the Person
Server's pending URL after `ask`, `server-error` or `defer`), `person-again`
and `deliver`. Host controls answer for the person (`ask`, `server-error`),
advance a deferred decision once (`defer`) and finally deliver queued events.
`ps-credential` requires a Person Server token in the stage response that
verifies under the fixture key; `ps-credential-exp` also requires its `exp`
no later than the allow's. `ps-mission` requires an approved mission whose
`s256` is the digest of its `mission` bytes and whose description is the one
allowed. At stage `deliver`, kinds grade what the
supervisor received, chosen by `member` `selector` or `selector/path`, where
a selector is `connect`, `decision`, `proposal`, `poll`, `event:<name>`,
`report:<action>` or `mission:<action>`, with `#n` for the nth:
`ss-request-proof` (the Person
Server's `jwks_uri` signature, coverage and digest), `ss-request-has` (member
present and nonempty), `ss-request-equals`, `ss-request-token` (an exact
forwarded token), `ss-sdi-distinct` (the first two decision requests carry
different `sdi`) and `ss-mission-match` (a report's `s256` and `mission` are
those the Agent received, and the digest matches).

## Signature-Key profiles

Two extension roles grade draft-hardt-httpbis-signature-key (catalog source
`key`) and the AAuth HTTP Message Signatures profile (source `core`).
`fixture.extensions.sigkey` holds the verifier URL, the signer's receiving
URL, the `jwks_uri` signer identity (issuer, `aauth-resource.json`, kid,
Ed25519 seed), the direct JWKS URL, PKCS #8 test keys for ES256, ES384, RS256
and PS256, the ML-DSA-44 seed and its kids for the signer and the Agent
Provider, the jkt-jwt identity seed and the self-jwt `typ`. All keys are
public test keys.

### `sigkey.verifier`

`input` names `scheme` (`hwk`, `jwt`, `jwks_uri`, `jwks`, `self-jwt`,
`jkt-jwt` or `x-unregistered`), `alg` (`hwk` varies it, `jwt` may confirm
an `ES256` key, and `ML-DSA-44` needs `jwks: pq-only`), `mutation` and an optional `jwks` key set (`mixed`
or `pq-only`, for the Agent Provider under `jwt` or the signer under
`jwks_uri`). The harness serves the Agent Provider, signer and direct JWKS
documents on loopback, one origin each, and signs one request to the
verifier with independent code. Mutations: `uncovered-signature-key`,
`missing-member` (the Signature-Key label is `sig1` while the signature is
`sig`), `hwk-kid`, `alg-eddsa` (hwk `alg` or `cnf.jwk` `alg`),
`header-eddsa` (JWS `alg`), `alg-kty` (an OKP key naming ES256), `alg-crv`
(a P-384 key naming ES256), `symmetric` (an HS256 key, HMAC signature),
`no-exp` and `unknown-kid`. Generic kinds grade the response; `sigkey-pq`
(a code string, `""` for any) passes when the request verified, or when the
verifier answered 401 with that Signature-Error code: a verifier need not
implement ML-DSA, but MUST refuse a key type it does not implement with
defined feedback.

### `sigkey.signer`

`input` names `scheme` (`hwk`, `jwt`, `jwks_uri`, `jwks`, `self-jwt` or
`jkt-jwt`), `alg` (`hwk` varies it and `jwt` may confirm an `ES256` key),
`method` and `body`. The harness
posts a control job with the fixture key, the target and the credential the
signer presents (the jwt, self-jwt and jkt-jwt assertions are minted by the
harness), receives the signed request and verifies it independently.
`sigkey-signed` requires one signature label whose signature verifies under
the expected key over the received components, covering `@method`,
`@authority`, `@path` and `signature-key`, with a covered Content-Digest
matching the body. `sigkey-member` requires the selected member to carry
exactly the expected scheme and parameters (for hwk the public key with `alg`
and no `kid`). `sigkey-created` compares `created` with the fixture clock.

## Community vectors profile

`role_under_test: "vectors.library"` grades the 94 test vectors of the
community aauth-go v0.3.0, copied unchanged into `vectors/community/` (see its
PROVENANCE.md), one scenario per case (`scenarios/400-493`). `input` holds
`source` (`file` under `vectors/`, the file's `sha256`, the case `index`),
the file's `kind` and the `case` exactly as the file carries it; a unit test
checks every embedded case against the copied file. The fixture is unused
apart from its clock, which a `signature-key` case uses as `created`.

The runner turns each case into one JSON input for the launcher, so a
launcher calls a native function and nothing else: the received request with
the vector's signed headers and any tamper applied, the verifier's clock
(`created` plus `at_offset`, or a JWT's `iat`, or 2026-01-01 when it has
none, as the vector files define), the window (60 seconds when absent),
the issuer's metadata and a JWKS holding the vector key without `d`, and for
`requirement` a 202 framing around the vector's header. A `signature-key`
case is a GET carrying the vector's Signature-Key and a placeholder signature
for label `sig`, enough to reach Signature-Key processing.

The launcher answers 200 with a normalized result (`accepted`, and per kind
`code`, `thumbprint`, `required_input`, `requirement`, `resource_token`,
`url`, `interaction_code`, `jwt`; `scheme` and `error` are evidence only),
or 501 `{"not_offered":"..."}` when the library has no public function for
the case. `unoffered` lists result members the library cannot produce.
`vector-result` compares the result member named by `member` with `equals`;
`vector-result-not` passes unless that member holds `equals`;
a not-offered kind or member is `not_exercised`, never a pass. The case's
result object is kept as the report's case `evidence`.

Expectations come from the drafts, not from the vectors. Where they differ:

| Vector expectation | Graded as | Why |
| --- | --- | --- |
| `canonical` byte-for-byte serialization (signature-error, requirement) and exact minted JWT bytes | not graded | the files' own emitter's format; their examples put a space after `;`, RFC 9651 serializes none |
| Signature-Error `params` keeping an unknown member's value | not graded | the draft only requires ignoring it (line 951) |
| `sig="jwt";jwt="x"` and `sig=jwt` without `jwt`: `invalid_signature` | refusal only | protocol step 5 (line 2248) points to `invalid_key`, signature-key line 1018 ("malformed") to `invalid_signature` |
| ES256 tokens, request keys and thumbprints accepted | `recommended` clauses | ES256 is a SHOULD (protocol line 2166) |
| a changed body with the original Content-Digest refused | `out-of-slice`, graded only when claimed | no pinned MUST checks the digest against the body |
| a JWT without `iat` refused; a person token carrying `scope` refused | `out-of-slice`, graded only when claimed | lines 2307 and 898 bind the issuer; no verification step names the refusal |
| thumbprint of a JWK without `alg` | `out-of-slice`, graded only when claimed | every AAuth key carries `alg` (line 2170) |
| resource, auth and person tokens whose `aud` is a one-element array verify | `out-of-slice`, graded only when claimed | the drafts define `aud` as one URL (lines 742, 850, 867) and verify per RFC 7519 (line 2313), whose `aud` may be an array; the array form is not settled |
| `sig1=hwk;..., sig=jwt;jwt="...";cache` yields the token | no `unsupported_scheme` (`vector-result-not`) | the vector's JWT carries `cache` without `jti`, which signature-key line 538 forbids, so acceptance is not fixed; the unselected `hwk` member still must not cause a refusal (line 157) |
| agent-identifier `name`, `discriminator`, `domain` | not graded | parsed fields are an API choice; validity is graded |
| metadata documents round-trip through Go types | accepted | the verifier-side check (line 1981) and REQUIRED members |

An `out-of-slice` clause is graded only for a target that claims it.
`build-adapters` claims one for an implementation whose native API settles
it (`cmd/build-adapters/adopted.go`); for every other target its assertions
are `not_claimed` and the case result is recorded as evidence.

The missing-member case (`sig1=jwt;...` with signature label `sig`) is graded
`invalid_signature`, settled by the draft text in the
`vector.sigkey.missing-member` clause.

## Signature-Key vectors profile

`role_under_test: "vectors.signature-key"` grades the vectors of
[`vectors/signature-key/`](vectors/signature-key/README.md), one scenario
per vector (`scenarios/5xx-sigvec-*.json`, numbered from 500 in file
order). `input` holds `source` (`file`, its `sha256`, the vector `index`),
the `vector` exactly as the file carries it and the `environment` it is
evaluated in: the file's verifier configuration, its documents with the
vector's own replacing those at the same URL, and the x509 trust. A unit
test checks every embedded vector and environment against the file. The
fixture is unused apart from the Agent Provider the Go launcher reads at
start-up.

The runner sends the received request (the vector's request with its
`signed` fields), the vector's `now` and the environment to the launcher,
which answers with its native verifier's response. Generic kinds grade it:
a `verify` vector expects status 200 and the verified `scheme` in the echo;
a `reject` vector expects 401 and the `Signature-Error` code, or any
`Signature-Error` when the drafts fix none; a `verify-or-reject` vector
uses `sigkey-pq`. Clauses are per scheme and algorithm (`sigvec.*`) and per
refusal (`sigvec.reject.*`); the ES256 clauses are `recommended`, as ES256
is a SHOULD.

`cmd/sigkey-vectors` generates the file, its scenarios and `APPENDIX.md`
with the same launchers (`-write`), or re-signs every vector and reports
any difference from the published bytes (`-check`).

## Bootstrap profiles

Three extension roles grade draft-hardt-aauth-bootstrap at `70d6737`
(catalog source `bootstrap`). The draft is informational and uses no BCP 14
keywords (line 130), so the map has no keyword sentences from it. Each
`protocol` clause is a core or Signature-Key requirement the draft applies
to enrollment, refresh or sub-agent issuance, with the draft's line in its
`section`. The draft's own guidance is `recommended`. The routes and bodies,
which the draft leaves to each AP (lines 371 and 410), are
`adapter-contract`. The single-key refresh is optional for an AP (line 150),
so its clauses, for the AP and for the agent, are `out-of-slice`. The
agent's refresh margin is a core SHOULD (line 1301) the draft applies (line
291), so its clause is `recommended`. A target that claims none of a
scenario's clauses does not run that scenario; its assertions are reported
not claimed.

`fixture.extensions.bootstrap` supplies the enrollment, refresh, single-key
refresh and sub-agent paths, the self-hosted issue control path, the agent
token lifetime (3600 seconds), five public test seeds (`durable`,
`other_durable`, `ephemeral`, `second_ephemeral`, `subagent`), the
discriminator a parent offers (`search1`) and a foreign AP (HTTPS issuer,
seed, kid). The fixture AP issuer, seed and kid are the AP's identity; the
fixture Person Server is the agent's configured `ps`.

| Role | `input` | Stages |
| --- | --- | --- |
| `bootstrap.agent-provider` | `flow` and `mutation`: `refresh` (`none`, `unenrolled`, `jkt-iss`, `jkt-typ`, `jkt-signature`, `jkt-expired`, `proof-key`), `rotate`, `installs`, `single-key` (each `none`), `subagent` (`none`, `no-discriminator`, `nested`, `foreign-parent`, `expired-parent`) | `enroll`, `refresh`; `refresh-2` for `rotate`; `enroll-other`, `refresh-other` for `installs`; `subagent`, with `subagent-1` before it for `nested`. `foreign-parent` and `expired-parent` send only `subagent` |
| `bootstrap.agent` | `operations`: `enroll` first, then `refresh` (at most twice) or one `single-key`, then optionally one `subagent` or `call`; after a `refresh`, up to two `renew` operations last, with one `remaining` entry (seconds, above 0 and below the agent lifetime) per `renew` | the operation names, the second refresh `refresh-2`, the second renew `renew-2` |
| `bootstrap.self-hosted` | up to six `issues`, each a top-level `agent` local name or a `parent` (1-based index of an earlier issue) with a `discriminator`, and a `key` (a fixture seed name, or `ap` for the published key); optional `metadata` | `issue-N`, then `metadata` and `jwks` |

For the hosted AP the harness plays the agent. It enrolls a durable key with
an `hwk`-signed `POST {"evidence": {}}`, then refreshes with `jkt-jwt`: a `jkt-s256+jwt`
naming JWT signed by the durable key, `iss` its JWK Thumbprint URI, `cnf.jwk`
the ephemeral key and a `jti`, in a request signed by the ephemeral key with
body `{"ps": <fixture PS>, "evidence": {}}`. The `evidence` member is the slot
for whatever the AP requires (Bootstrap line 106), empty here. A single-key refresh is the same body signed
under `hwk` by the durable key. A sub-agent request presents the parent's
token under `jwt`, signed by its key, with body `{"jwk", "discriminator"}`,
the draft's example members. Every request covers `content-type` and
`content-digest`. A refresh answers `200 {"agent_token"}`. Mutations change
one property: the naming JWT's durable key (never enrolled), `iss`, `typ`,
signature or expiry; the HTTP signing key; or the parent, which is a
sub-agent token the AP issued, a token the foreign AP signed, or a token the
fixture AP key signed whose `exp` has passed. A sub-agent request that has
no parent token to send is a case error, not a refusal.

For the agent the harness plays the AP and the Resource. The launcher's
control receives `{"operation"}` jobs: `enroll`, `refresh`, `single-key`,
`subagent` with `jwk` and `discriminator`, `call` with `method`, `url` and
`transport`, and `renew` with `now`. For a `renew` the harness moves its own
clock to the current agent token's `exp` less the `remaining` entry and sends
that time as `now`; the agent refreshes at that clock only when it judges the
token inside the refresh margin (core line 1301, Bootstrap line 291). Only
`renew` may follow a `renew`, because the clock has moved. The harness AP
verifies each request independently at its clock and issues fixture-key
tokens bound to the delegated key, or to the durable key for `single-key`,
so later operations can proceed. Its
answers carry `Cache-Control: no-store`. It ignores body members it does not
grade, such as `evidence`. The
control's answer is evidence only.

For the self-hosted AP the harness posts each issue to the launcher's issue
control, `{"agent", "jwk", "ps"}` for a top-level agent or `{"parent_token",
"jwk", "discriminator"}` for a sub-agent, and reads `{"agent_token"}`. It then
reads the metadata and the JWKS at its `jwks_uri`, which must be on the AP's
origin.

Four kinds are added, each with a boolean expectation and a `member` naming
the property.

- `bootstrap-token` grades an issued agent token. `signature` verifies it as
  `aa-agent+jwt` under the fixture AP key. `claims` checks `iss`, `dwk`,
  `jti`, `iat` at the fixture clock and an `exp` after it. `identifier` checks
  `aauth:local@domain` with the AP's domain, and no `+` for a top-level
  agent. `top-level` checks that `parent_agent` is absent. `key` checks that
  `cnf.jwk` is the requested key with `alg`. `ps` checks the configured
  Person Server. `lifetime` checks above 300 seconds and at most 24 hours.
  `same-subject` (stage `refresh-2`) and `new-subject` (stage
  `refresh-other`) compare `sub` with the first refresh. `subagent-identity`
  checks `iss` and the parent, and the parent's local part, `+` and a
  discriminator. `subagent-claims` checks `ps` copied, `exp` not after the
  parent's, and the offered discriminator. `distinct-subject` (self-hosted
  top-level issues) checks a `sub` no earlier issue got.
- `bootstrap-no-token` passes on a 4xx response with no `agent_token`.
- `bootstrap-request` grades a request the agent sent. `hwk-proof` is an
  enrollment POST signed under `hwk` by the key it carries. `naming-jwt`
  applies the `jkt-jwt` checks above. `durable-anchor` checks the naming
  JWT's header key against the enrolled key. `ephemeral-proof` checks that
  the delegated key signed the request. `naming-jti` checks for a `jti`.
  `fresh-ephemeral` checks a delegated key that is neither the durable key
  nor an earlier one. `body-coverage` checks `content-type` and
  `content-digest` coverage with a digest of the actual body. `parent-proof`
  checks the last issued token under `jwt`, signed by its key.
  `subagent-key` checks the body `jwk`. `durable-absent` checks a `jwt`
  request the durable key did not sign. `refreshed-token` checks a Resource
  call that presents the last issued token and is signed by its key.
  `single-key-proof` (stage `single-key`) is a POST to the single-key refresh
  path signed under `hwk` by the enrolled durable key. `refresh-sent` (stages
  `renew`, `renew-2`) is whether the agent sent a POST to the refresh path
  during the operation; it grades both the refresh inside the margin and its
  absence outside it. `margin-refresh` checks that request as a two-key
  refresh anchored at the enrolled durable key, with an unexpired naming JWT
  and a signature created at the moved clock. Every signature check requires
  `created` within 60 seconds of the harness clock, which is the fixture
  clock until a `renew` moves it, and coverage of `@method`, `@authority`,
  `@path` and `signature-key`.
- `bootstrap-jwks` (stage `jwks`): `ap-key` checks that the metadata
  `issuer` is the AP and the JWKS holds the AP key under its kid.
  `agent-keys-absent` checks that no agent key issued in the scenario is in
  the JWKS.

Generic kinds grade the stage responses. Remote mode does not run these
roles.
