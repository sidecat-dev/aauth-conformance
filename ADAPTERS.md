# Resource launcher protocol, version 1

A launcher supplies host configuration and transport around one implementation's
Resource API. It must not read scenarios/expectations, verify signatures outside
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
