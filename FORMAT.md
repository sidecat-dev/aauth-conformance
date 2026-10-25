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
code. Only `initial`, `challenge`, `access` and `protected` stages are permitted;
native PS endpoints are never called. PS delivery faults (`grant-*`) and native
PS assertions are rejected for this driver. The ten `fixture-ps-*` scenarios
measure the native Resource and AS without depending on a native PS. The
default driver uses the native PS and all stages above.

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

`federated.budget` is omitted, `grant`, or `omit`. Omitted keeps the reactive
person-token challenge on the fixture path and offers no Budget. `grant` and
`omit` replace that challenge with one signed `POST {origin}/authorize`. The
JSON body is `{"scope":"read","budget":{"amount":N,"unit":"credits","decimals":0}}`.
`grant` and `consume` use amount 5000000. `omit` uses amount 9000000. The
Resource offers that requested amount unchanged. Its metadata maximum for
`credits` and for `points`, both at decimals 0, is 10000000. The Person Server
ceiling for a 5000000 offer is 2000000, and the Access Server echoes that
ceiling. A 9000000 offer is omitted from the PS-to-AS request, so the auth
token has no `budget` claim. The protected call uses `{path}-budget-grant` for
`grant` and `consume`, and `{path}-budget-omit` for `omit`, on the same
Resource issuer. Only the grant path is metered. With no `X-Fixture-Cost`
header its cost is 1000, so `remaining` is 1999000. `consume` sends
`X-Fixture-Cost: 1500000` on `protected`, then `X-Fixture-Cost: 1000000` on
`step-up`. That second call does not fit. The fresh Resource token offers
5000000 credits and carries `budget_consumed` for the presented auth-token
`jti`, with `consumed` 1500000. `step-up-other` repeats the refusal with
`X-Fixture-Offer: points`. That offer is 5000000 points and omits
`budget_consumed` because the unit differs from the metered grant. These two
headers are fixture policy, not protocol fields, and are not covered by the
signature. The `challenge` stage for these modes is the authorization response
(`200` and `resource_token`), not the reactive `401`. `fed-budget` compares the
JWT `budget` object on `challenge`, `access`, `token`, `step-up`, or
`step-up-other`; `null` requires the claim to be absent. `fed-consumed`
compares `budget_consumed` on `step-up` or `step-up-other`. An object
`{"consumed":N}` also requires `jti` to equal the delivered auth token's `jti`.
`null` requires the claim to be absent. `header` uses the same 5000000 request
and 2000000 ceiling as `grant`. Its protected calls use `{path}-budget-reserve`.
`X-Fixture-Hold` is the reservation and `X-Fixture-Settle`, when present, is
the cost committed after the body. Both are unsigned fixture headers. The
`reserved` call holds 800000 and settles 400000, so the header is `remaining`
1200000 and `reserved` 800000 with no `cost`, and the trailer is `cost` 400000
only. The `abandoned` call holds 500000 and does not settle. A completed
response still carries trailer `cost` 500000, because the Resource commits the
hold before finishing the response. The `following` call holds 100000 and
settles 100000; its header `remaining` 1000000 shows that the abandoned hold
was already spent. A recipient that never receives a trailer treats the
reservation as spent; this scenario grades the completed response, which does
carry the trailer. `sfv-integer` compares one bare integer member of a
dictionary header. `sfv-absent` requires that member to be missing. The
`sfv-trailer-integer` and `sfv-trailer-absent` kinds read the trailer instead.
`usage` charges 1000 on `{path}-budget-usage`, which has its own ledger. The
harness then `POST`s `{origin}/usage` with an Access Server `jwks_uri` proof.
The known subject is `directed-person-1` with `ps` `https://person.conformance.test`;
`usage.all_time` is 1000, `Cache-Control` is `no-store`, and the response is
unsigned. Subject `unknown-person` omits `usage` and still reports `credits`
at decimals 0. An Access Server scope key without `ps` is HTTP 400
`invalid_request`, as is a body with both `sub` and `tenant`. A `jkts` array
containing only an unknown thumbprint returns `"jkts":{}` rather than a zero.
`json-path` walks dot-separated object members. `null` means the member is
absent. `header-equals` compares one header value; an empty string means the
header is absent.

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
