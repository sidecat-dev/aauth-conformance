# AAuth conformance scenarios

Run the same wire scenarios against different AAuth implementations. The first
slice tests a **Resource in Agent-identity mode**. The harness plays the Agent
and Agent Provider (AP), creating its own Ed25519 tokens and HTTP signatures and
serving fixture metadata/JWKS. It uses no AAuth library to generate test inputs.

Six scenarios—unsigned request, accepted identity, tampered signature, expired
token, uncovered Signature-Key and future `created`—produce 17 assertions per
implementation. Every assertion names a pinned draft clause. The
[example report](reports/first-slice.md) records a real Go/Rust run. Its counts
cover these assertions, not entire draft sections or complete AAuth conformance.

## Run against local checkouts

Install Go 1.25 or later. For the Rust launcher, install rustup and put
`~/.cargo/bin` on PATH. The build helper copies the selected implementation's
`rust-toolchain.toml`; first builds may download that toolchain and dependencies.
Use implementation checkouts with the APIs in [ADAPTERS.md](ADAPTERS.md); tested
commits appear in the example report. The Rust alpha crates need not be published.

From this checkout:

```sh
go run ./cmd/build-adapters -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust
go run ./cmd/aauth-conformance
```

The helper builds launchers and `build/targets.json`, recording source revisions
without editing the implementation checkouts. The runner starts its AP and each
launcher on random loopback ports, executes the same files and stops its children.
It writes `build/report.md` (clause matrix and assertion evidence) and
`build/report.json` (pins, suite digest, revisions, logical request headers/base,
observed responses and per-assertion results). Response bodies are base64 encoded.

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
not failure or success. The person-token requirement is outside this slice.

The valid case's 200 JSON subject echo is labeled `adapter-contract`: the draft
allows the Resource's own policy and application response. Failure cases check
AAuth's 401 mapping, typed Structured Fields and conditional Problem Details URNs.

**This slice uses loopback HTTP test transport.** Launchers reconstruct logical
HTTPS identities from received Host/path. Fixed clocks, trusted AP documents and
allow policies are test configuration. These results do not measure TLS,
enrollment, discovery admission/caching, rotation, replay storage, body digests,
Person Servers or delegation. Fixture private seeds are public test vectors.

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

The race check needs a platform C compiler; the runner builds with
`CGO_ENABLED=0`. CI tests and builds the runner on Linux x86_64/ARM64. Actual Resource runs require
separately selected source checkouts and are distinct from runner unit tests.
The generic Structured Fields parser is also used by aauth-go; parser agreement
alone is not independent RFC 9651 proof. See [third-party notices](THIRD-PARTY-NOTICES.md).

MIT licensed. Canonical home:
[sidecat-dev/aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance).
