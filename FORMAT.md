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
and `scope`: `protocol`, `adapter-contract` or `out-of-slice`. These reference
source headings rather than replace normative text. Re-pinning requires reviewing
the referenced text and expectations even when clause IDs stay unchanged.

## Requests and assertions

A scenario has `version`, unique `id`, `title`,
`role_under_test: "resource.agent-identity"`, `given` matching the fixture ID,
`token`, `request` and nonempty `assertions`. See [valid](scenarios/02-valid.json).

`token.iat_offset`/`exp_offset` are seconds relative to the fixed clock. JWT `jti`
is the scenario ID; `dwk` is `aauth-agent.json`. Issuer, subject and confirmation
key come from the fixture. Protected `alg` is `Ed25519`, `typ` is `aa-agent+jwt`.

In v1, `request.method` is GET and `path` equals the fixture path; bodies, queries,
custom headers and multiple exchanges are future slices. `proof` is `unsigned`
or `jwt`; `created_offset` is relative to the fixed clock. `covered` is an ordered,
non-repeating list from `@method`, `@authority`, `@path`, `signature-key`. Omitting
a component creates a valid signature over deliberately incomplete coverage.
`tamper_signature: true` flips a signature byte after signing. Only physical
loopback addresses differ between targets; logical requests/JWTs/proofs are identical.

Every assertion has unique scenario-local `id`, `clause`, `kind`, and `equals`:

| Kind | Other fields | Check |
| --- | --- | --- |
| `status` | — | HTTP status equals the integer. |
| `sfv-token` | `header`, `member` | All header lines parse as a dictionary; member is an Item whose Token equals the string. A quoted string fails. Unknown members are ignored. |
| `sfv-strings` | `header`, `member` | Member is an Inner List of Strings exactly matching the array; use when order is significant. |
| `sfv-string-set` | `header`, `member` | Same String list type, comparing component membership without order/duplicates; used for required coverage. |
| `json-member` | `member` | Object contains that top-level member with equal value/type. Absence differs from null. |
| `problem-if-present` | — | On application/problem+json, require object type `urn:ietf:params:sig-error:` plus expected code, and any status must match HTTP. Other body representations yield `not_exercised`. |

## Targets and reports

A target file has `version: 1` and nonempty `implementations`. Each entry has
unique `id`, `revision`, executable `command` array and explicit `claims` of known
clause IDs. Commands execute directly without a shell; relative commands resolve
from the runner's working directory. The helper declares the tested first-slice
clauses; edit the manifest to narrow claims. Reports retain declared provenance.

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
