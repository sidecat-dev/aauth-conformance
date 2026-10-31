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
and `scope`: `protocol`, `adapter-contract` or `out-of-slice`. Optional `role`
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
non-out-of-slice clauses; edit the manifest to narrow claims. Reports retain declared provenance.

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
| `ps-jwt-identity` | PS issuer/discovery document, Resource audience, nonempty subject/JTI; Auth PS and subject match presented Person lineage. This fixture forbids unexpected mission, tenant and delegation fields. |
| `ps-jwt-subject` | Subject equals the configured host binding; adapter contract. |
| `ps-jwt-key` | Confirmation public JWK equals this Agent's fixture key. |
| `ps-jwt-lifetime` | Integer issued time at fixture now, positive current expiry, one-hour and Agent/presented parent bounds; response expires_in equals signed expiry. Resource-token expiry is not an Auth-token parent bound. |
| `ps-jwt-no-authorization` | Person claims contain neither scope nor account. |
| `ps-jwt-scope` | Auth token has exactly configured read scope, no unrequested account; adapter contract. |
| `ps-no-token` | Parameter-token refusal JSON object releases neither Person nor Auth token. |
| `ps-jwt` | Combined valid fixture JWT profile, available for composite tests. |

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
