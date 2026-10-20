# AAuth conformance scenarios

Run the same wire scenarios against different AAuth implementations. Three roles
are available:

- **Resource in Agent-identity mode:** the harness plays the Agent and Agent
  Provider (AP), creating Ed25519 tokens/proofs and serving fixture metadata/JWKS.
- **Person Server direct authorization:** the harness plays Agent, AP and Resource,
  obtains a real Person token over HTTP, constructs a Resource challenge from it,
  and independently verifies the native PS-issued Auth token.
- **Agent signing:** the harness plays the AP and receiving Resource. The SUT
  signs outbound requests; the harness independently verifies the received proofs.

The harness uses no AAuth library to generate inputs or grade either role.

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
all five crates. Historical reports identify their then-current launcher
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

**This slice uses loopback HTTP test transport.** Launchers reconstruct logical
HTTPS identities from received Host/path. Fixed clocks, trusted AP documents and
allow policies are test configuration. These results do not measure TLS,
enrollment, discovery admission/caching, rotation, replay storage, body digests,
delegation, or complete Person Server behavior. The separate PS slice below
tests its stated endpoints only. Fixture private seeds are public test vectors.

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
`CGO_ENABLED=0`. CI tests and builds the runner on Linux x86_64/ARM64. Actual SUT runs require
separately selected source checkouts and are distinct from runner unit tests.
The generic Structured Fields parser is also used by aauth-go; parser agreement
alone is not independent RFC 9651 proof. See [third-party notices](THIRD-PARTY-NOTICES.md).

MIT licensed. Canonical home:
[sidecat-dev/aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance).
