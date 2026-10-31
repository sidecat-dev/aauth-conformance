# AAuth conformance scenarios

Run the same wire scenarios against different AAuth implementations. Six roles
are available:

- **Resource in Agent-identity mode:** the harness plays the Agent and Agent
  Provider (AP), creating Ed25519 tokens/proofs and serving fixture metadata/JWKS.
- **Person Server direct authorization:** the harness plays Agent, AP and Resource,
  obtains a real Person token over HTTP, constructs a Resource challenge from it,
  and independently verifies the native PS-issued Auth token.
- **Agent signing:** the harness plays the AP and receiving Resource. The SUT
  signs outbound requests; the harness independently verifies the received proofs.
- **Four-party authorization:** the harness plays Agent and Person Server (PS)
  against native Resource and Access Server (AS). Additional cases exercise a
  native PS too, observing its signed handoff and grant verification.
- **Deferred four-party authorization:** the harness plays Agent and AP while
  native PS and AS retain payment/approval continuations. Host controls simulate
  settlement and approval; the runner grades signed requests and native responses.
- **Parent-mediated sub-agent authorization:** the harness plays parent, child and
  AP, checks child-bound native credentials and exact PS-to-AS forwarding, and
  exercises parent-only polling, cancellation, expiry and binding revocation.

The harness uses no AAuth library to generate inputs or grade these roles.

Six scenarios—unsigned request, accepted identity, tampered signature, expired
token, uncovered Signature-Key and future `created`—produce 17 assertions per
implementation. Every assertion names a pinned draft clause. The
[example report](reports/first-slice.md) records a real Go/Rust run. Its counts
cover these assertions, not entire draft sections or complete AAuth conformance.

The Agent role adds GET, empty POST to another path, and GET with query and
Authorization: 16 assertions per implementation. The [Agent report](reports/agent-signing.md)
records both native signers. Only valid AP-token inputs are supplied; this does
not test the Agent's rejection of bad AP tokens or its Person Server flows.

## Run against local checkouts

Install Go 1.25 or later. For the Rust launcher, install rustup and put
`~/.cargo/bin` on PATH. The build helper copies the selected implementation's
`rust-toolchain.toml`; first builds may download that toolchain and dependencies.
Use implementation checkouts with the APIs in [ADAPTERS.md](ADAPTERS.md); tested
commits appear in the example report. The current Rust launcher links the Person
Server crate as well as Agent/Core/JOSE/Resource, so select a checkout containing
all five crates. Four-party authorization also needs the Access Server crate.
Historical reports identify their then-current launcher
and source revisions. The Rust alpha crates need not be published.

From this checkout:

```sh
go run ./cmd/build-adapters -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust
go run ./cmd/aauth-conformance
```

These commands select the Resource role by default. To test the Agent instead:

```sh
go run ./cmd/build-adapters -role agent.signing -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust -out build/agent
go run ./cmd/aauth-conformance -targets build/agent/targets.json -report build/agent-report.json -markdown build/agent-report.md
```

The Agent cases require the APIs at Go `e93fd53` / Rust `934217d` or compatible
successors. Role selection lives in the generated manifest; the scenario files
run unchanged for every implementation.

The helper builds launchers and `build/targets.json`, recording source revisions
without editing the implementation checkouts. The runner starts its AP and each
launcher on random loopback ports, executes the same files and stops its children.
It writes `build/report.md` (clause matrix and assertion evidence) and
`build/report.json` (pins, suite digest, revisions, logical request headers/base,
observed responses and per-assertion results). Agent reports also retain the
signing command, actual received headers/body and control response. Response
bodies are base64 encoded.

To run only Go, omit `-rust-source`; to run only Rust, omit `-go-source`.
The scenarios stay unchanged. You can also build a standalone runner:

```sh
go build -o build/aauth-conformance ./cmd/aauth-conformance
build/aauth-conformance -suite . -targets build/targets.json -report build/report.json -markdown build/report.md
```

The binary exits 0 when at least one claimed assertion passes and none fails or
errors, 1 for failed/incomplete execution, and 2 for invalid input/output errors.
`go run` wraps nonzero program statuses; use the binary to distinguish 1 from 2
in automation. Missing targets never count as passes.

## Read the result

Target manifests declare the clauses being tested, not an upstream full-conformance
statement. The matrix distinguishes `pass`, `fail`, `error`, `not_claimed` and
`not_exercised`. An absent optional Problem Details representation is unexercised,
not failure or success. The existing Resource and Agent slices do not test the
person-token requirement. The separate Person Server slice tests issuance and
direct grants, not a Resource's person-token challenge behavior.

The valid case's 200 JSON subject echo is labeled `adapter-contract`: the draft
allows the Resource's own policy and application response. Failure cases check
AAuth's 401 mapping, typed Structured Fields and conditional Problem Details URNs.

Agent assertions check input preservation, mathematical Ed25519 proof over the
received method/authority/path/headers, mandatory coverage, the configured
Unix-second `created`, and AP-signed token presentation with the correct
confirmation key. Query and Authorization coverage is required by this receiving
Resource profile and labeled `adapter-contract`; both native signers provide it.
Signature labels may differ. The verifier checks the listed fields, not every
Signature Parameter rule or every JWT claim rule in the cited sections.

All Agent requests have **empty bodies**, including POST. This result says
nothing about body integrity. A host sending a body must arrange covered
`content-digest` generation and verification. Identical signed requests are
accepted again here: replay detection and storage are host duties outside these
slices. The fixed seeds and fixed clock make these repeatable tests.

**All roles use loopback HTTP test transport.** Launchers reconstruct logical
HTTPS identities from received Host/path. Fixed clocks, trusted AP documents and
allow policies are test configuration. The default Resource and Agent results
do not measure TLS,
enrollment, discovery admission/caching, rotation, replay storage, delegation,
or complete Person Server behavior. Body-integrity evidence comes only from the
stated JSON exchanges in the PS and four-party slices below, not the bodyless
Agent/Resource cases. Fixture private seeds are public test vectors.

## Person Server direct authorization

Build and run the shared Person Server scenarios with:

```sh
go run ./cmd/build-adapters -role person-server.direct -go-source /path/to/aauth-go -out build/person
go run ./cmd/aauth-conformance -targets build/person/targets.json -report build/person-report.json -markdown build/person-report.md
```

The slice currently has **12 scenarios and 109 assertions per implementation**.
The [dual implementation report](reports/person-server-direct.md) records
**218 passing assertions** against Go `d914b4f` and Rust `4bdfc6e`. Add
`-rust-source /path/to/aauth-rust` to the build command to select both targets.
The same scenario files and expected answers apply to both implementations.

The positive fixture requests a 60-second Person token, a 180-second Auth grant
and a 600-second Agent token. This makes the presented-token ceiling decisive
independently of the Agent ceiling; the separate 45-second Agent case exercises
that other parent. A regression supplies a correctly signed grant that omits
only the presented ceiling and requires the auth-lifetime assertion to fail.
These short fixtures do not drive the one-hour limit to its boundary. A passing
row records these observations, not every condition in the cited section.

Confirmation keys are compared by validated public Ed25519 key material,
including required algorithm/shape and canonical 32-byte key encoding. Optional
public JWK metadata such as `kid` or `use` need not be echoed identically. Private
key material, a wrong algorithm or a genuinely different key still fails. JWT
signatures are verified over their original compact segments before this check.

The harness signs JSON POSTs with covered Content-Type and SHA-256 Content-Digest.
It obtains an actual Person token from `/person`, verifies the returned JWT with
standard Ed25519 cryptography, then issues a Resource JWT naming those exact
Person bytes and calls `/token` with `resource_token` and `presented_token`.
It checks the Auth JWT independently. Negative cases change proofs or body bytes,
Resource audience/key/person/PS/presented-JTI, expiry, and requested scope. A short
Agent parent checks both issued lifetime bounds. The expired-presented case
re-signs the actual returned Person claims under the public fixture PS seed with
an expired time interval, preserving all lineage fields.

The launchers supply native in-memory retained stores and fixed host binding and
scope policies. Host-selected subject and exact read-only policy expectations
are `adapter-contract`; no synthetic state endpoint is used. A passing result
does not prove storage durability, revocation or retention deadlines. The oracle
covers this fixture's Ed25519 JWT profile, not every JOSE or JWT validation rule.
Missions, tenant/account claims, subagents, downstream chaining, AS federation,
interaction, discovery admission, replay, TLS, and key rotation remain outside
this PS slice. Returned `expires_in` must agree with the verified signed expiry.

The Go Agent adapter also preserves an explicit signed Request.Host when mapping
to loopback, using URL.Host only as the empty-Host fallback. Its regression runs
against the copied adapter module:

```sh
go test -C build/person/aauth-go-adapter -count=1
```

## Four-party authorization

```sh
go run ./cmd/build-adapters -role authorization.federated -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust -out build/federated
go run ./cmd/aauth-conformance -targets build/federated/targets.json -report build/federated-report.json -markdown build/federated-report.md
```

This slice has **34 scenarios and 398 assertions per implementation**. Scenarios
01–49 are the original four-party cases (28 scenarios, 336 assertions). Scenario
73 is the native Budget grant: the Resource offers 5000000, the Person Server
narrows it to 2000000, and the protected call costs 1000. Scenarios 74–78 use
the harness Person Server. Scenario 74 omits the Budget parameter and requires
the Access Server to issue no budget claim. Scenario 75 requires a same-scale
consumption record and checks a different-unit record only when the Resource
sends one. Scenario 76 reserves a hold and settles part of it; a cost-only
trailer is graded when present. Scenario 77 charges 1000 and grades the usage
query as a delta from a baseline read. Scenario 78 spends 1500000 on each of
two auth tokens, then refuses a further 1000000 on the first token without
lowering its remaining 500000. The fixture amounts, paths, and assertion kinds
are in `FORMAT.md`. The
[four-party report](reports/four-party-authorization.md) records Go `831d55f` and
Rust `843be82` for the original 28 scenarios. Select those revisions or
compatible successors; older Rust checkouts without native AS/federation APIs
can still run the other roles. A checkout without the Budget authorization
endpoint fails scenarios 73–78.

Ten independent-PS cases play Agent, AP and PS entirely in the harness, testing
the native Resource and AS with the same fixture credentials and wire recipe.
The harness issues a Person token, obtains a native Resource challenge, signs
the AS POST itself, independently checks the resulting Auth token and presents
it to the Resource. These cases never call native PS endpoints or count harness
issuance/verification as native conformance.

Eighteen additional cases start at the Resource's person-token challenge, obtain
a native Person token, return for an AS-targeted Resource challenge, and redeem
it at the native PS. The PS signs its own AS request using `jwks_uri`. The native AS
issues an Auth token, the PS verifies and delivers it, and the Agent presents
it to the Resource. The independent oracle verifies the tokens, exact forwarded
compact credentials, PS proof, covered JSON type, and actual SHA-256 body digest.
Separate short Person and Agent lifetimes exercise both expiration ceilings.

A loopback relay in the native-PS cases retains the original PS request and native AS response before
injecting deliberate faults. Cases corrupt the PS proof/body, re-sign conflicting
Resource context or an expired presented token, and replace a native grant with
an incorrectly signed or incorrectly bound grant. The JSON report retains both
original and delivered bytes. These are adversarial inputs, not claims that the
PS normally emits contradictory credentials. The AS must refuse the request
faults; the PS must refuse unverifiable grants and relay terminal denial.

The fixed host policies bind one directed subject, consent to federation and
grant only `read`; the final subject echo and AS's chosen `403 access_denied`
policy response are adapter contracts. Composite JWT assertions check the
protocol bindings within that configured fixture, including its expected
subject and scope. They are not general-purpose JWT validators. AS proof/body
refusals are checked at the AS as 401 and at the PS for no released token; this
slice does not prescribe the PS's classification of its own rejected proof.

Both adapters host distinct logical PS, AS and Resource identities and keys.
Fixed trusted-key snapshots and loopback HTTP are intentional test configuration.
No TLS, discovery admission, AS deferred interaction/payment, Auth-token step-up,
mission, R3, revocation or durable-store parity is claimed by this slice.

The Rust four-party transport regression preserves explicit Host, proof headers,
body bytes and non-success responses:

```sh
cargo test --manifest-path build/federated/aauth-rust-adapter/Cargo.toml --features federation --target-dir build/federated/rust-target
```

## Extend or contribute

[FORMAT.md](FORMAT.md) describes scenarios, pins and result semantics;
[ADAPTERS.md](ADAPTERS.md) specifies the launcher protocol. Add cases before
changing harness behavior and cite the exact pinned section. Keep implementation
names and alternative expectations out of scenarios; retain disagreements in reports.

```sh
go test -race ./...
go vet ./...
gofmt -l cmd internal adapters/go
```

After building the Rust launcher for the Agent role, also run its transport
regression (including rejection of a body unexpectedly added by the signer):

```sh
cargo test --manifest-path build/agent/aauth-rust-adapter/Cargo.toml --target-dir build/agent/rust-target
```

The race check needs a platform C compiler; the runner builds with
`CGO_ENABLED=0`. CI runs native tests on Linux x86_64 and cross-compiles runner
binaries for Linux x86_64/ARM64; it does not run native ARM64 tests. Actual SUT runs require
separately selected source checkouts and are distinct from runner unit tests.
The generic Structured Fields parser is also used by aauth-go; parser agreement
alone is not independent RFC 9651 proof. See [third-party notices](THIRD-PARTY-NOTICES.md).

MIT licensed. Canonical home:
[sidecat-dev/aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance).

## Deferred authorization and payment

Five scenarios add 88 assertions for payment followed by approval, approval
without payment, denial, an invalid returned grant, and a foreign pending URL.
They observe native PS-to-AS signed polls, exact initial token forwarding,
stable pending URLs, verified Agent delivery, protected Resource use and
single terminal consumption. The [report](reports/deferred-authorization.md)
records the Go baseline. Both native adapters can run this profile against
source revisions that provide their deferred AS and PS APIs.

```sh
go run ./cmd/build-adapters -role authorization.deferred -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust -out build/deferred
go run ./cmd/aauth-conformance -targets build/deferred/targets.json -report build/deferred-report.json -markdown build/deferred-report.md
```

Use revisions with the deferred APIs in [ADAPTERS.md](ADAPTERS.md). Rust uses
the `deferred` adapter feature; an older source revision without those native
APIs fails compilation. Absence is not a pass. Payment processing, billing
caches, elapsed-time backoff, expiry, concurrent polling, process recovery and
companion/delegated/mission
continuations are outside these five scenarios. Native Go tests cover timing,
concurrency and state-store failure separately. No real payment occurs.

After building this profile, run the Rust adapter's transport tests and strict
Clippy check against the same selected library checkout:

```sh
cargo test --manifest-path build/deferred/aauth-rust-adapter/Cargo.toml --features deferred --target-dir build/deferred/rust-target
cargo clippy --manifest-path build/deferred/aauth-rust-adapter/Cargo.toml --all-targets --features deferred --target-dir build/deferred/rust-target -- -D warnings
```

## Parent-mediated sub-agent authorization

The `authorization.subagent` role adds one-level parent-mediated direct and
federated child authorization, bounded AS approval/payment, parent-only polling,
child credential holder checks, independently trusted foreign-provider refusal,
hostile relationship inputs, separate parent/child lifetime bounds, parent binding
revocation, cancellation, expiry and terminal consumption. It uses separate
scenarios and clauses; the original role inputs and expectations are retained.
To run this role against **Go only**, start in the harness repository root and
replace `/path/to/aauth-go` with the absolute path to your Go checkout:

```sh
go run ./cmd/build-adapters -go-source /path/to/aauth-go \
  -role authorization.subagent -out build/subagent
go run ./cmd/aauth-conformance -targets build/subagent/targets.json \
  -report build/subagent-report.json -markdown build/subagent-report.md
```

Keep these commands together: `-out build/subagent` writes the manifest at
`build/subagent/targets.json`. It does not change the runner's default
`build/targets.json`. Pass the matching `-targets` path, and choose the report
paths explicitly as above. The manifest selects the role and implementation;
the runner uses that selection.

To compare Go and Rust, add `-rust-source /path/to/aauth-rust` to the same build
command. For Rust only, supply that flag and omit `-go-source`. At least one
source flag is required. Rust builds also need the toolchain described in
[Run against local checkouts](#run-against-local-checkouts).

For scripts that need the runner's exact exit status, build and invoke its
binary with the same paths:

```sh
go build -o build/aauth-conformance ./cmd/aauth-conformance
build/aauth-conformance -targets build/subagent/targets.json \
  -report build/subagent-report.json -markdown build/subagent-report.md
```

The binary exits **0** for a passing run, **1** for failed/incomplete execution,
and **2** for invalid input or output errors. `go run` turns a nonzero program
status into shell status 1 and prints the original status, so it cannot preserve
that distinction for a calling script. For example, a missing manifest is
binary exit 2; verify `-targets` if the error names `build/targets.json` after
you built into `build/subagent`.

The slice has **18 scenarios and 191 assertions per implementation**. The
[sub-agent report](reports/subagent-authorization.md) records both native
implementations against the same expected answers. Select Go and Rust
revisions that provide native sub-agent PS, AS and binding-revocation APIs;
an older checkout fails to compile its launcher rather than passing. See
[the adapter contract](ADAPTERS.md#parent-mediated-sub-agent-authorization)
for the observed boundaries and named gaps.

## Supervision

`supervision.server` grades a native supervision server with the harness as
its Person Server; `supervision.person-server` grades a native Person Server
that consults the harness as its supervision server. Both cite
draft-hardt-aauth-supervision at the pin and use the same files for Go and
Rust:

```sh
go run ./cmd/build-adapters -role supervision.server -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust -out build/supervision-server
go run ./cmd/aauth-conformance -targets build/supervision-server/targets.json -report build/supervision-server-report.json -markdown build/supervision-server-report.md
```

Use `-role supervision.person-server` the same way. A few clauses state
normative behavior the draft gives without a BCP 14 keyword (what a Person
Server does with allow, deny and ask, when the supervisor is unavailable, and
how it polls a deferred decision); their section text says so. Host
rate-limiting is a host choice: an implementation that exports no
rate_limited answer is recorded `not_exercised` with the reason, not passed.
