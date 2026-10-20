# Launcher protocol, version 1

A launcher supplies host configuration and transport around one implementation's
native Resource or Agent API. The optional bootstrap `role` defaults to
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
