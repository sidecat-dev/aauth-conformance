# aauth-protocol crates against remote mode

This page compares the community Rust crates `aauth-protocol` 0.2.0 and
`aauth-person-server` 0.1.0 with aauth-go and aauth-rust. All three ran in
one remote mode run, against real HTTPS deployments, with the same suite
build. [deployments/run-remote.sh](../deployments/run-remote.sh) reproduces
it. The crates' deployment and what it adds to them are in
[deployments/aauth-protocol](../deployments/aauth-protocol/).

| Implementation | Revision |
| --- | --- |
| aauth-protocol crates | `aauth-protocol` 0.2.0 (Resource), `aauth-person-server` 0.1.0 on `aauth-protocol` 0.1.0 (Person Server) |
| aauth-go | `3deb5b7` |
| aauth-rust | `v0.1.0-alpha.19` (`1b4059e`) |

Suite digest `0ef5aa79e182`, run on 2026-11-02 UTC. The crates name
protocol draft `-11`. The suite grades against the drafts' editor copies of
2026-10-03.

## Counts

Assertions per role. The Person Server rows leave out the profile's fixed
subject clause, `ps.host-person-profile`, for all three: the crate cannot be
configured to issue that subject, so the clause is not applicable to it.

| Role | Implementation | Pass | Fail | Not exercised |
| --- | --- | ---: | ---: | ---: |
| `resource.agent-identity` | aauth-protocol 0.2.0 | 12 | 1 | 4 |
| | aauth-go | 17 | 0 | 0 |
| | aauth-rust | 17 | 0 | 0 |
| `person-server.direct` | aauth-person-server 0.1.0 | 66 | 24 | 9 |
| | aauth-go | 90 | 0 | 9 |
| | aauth-rust | 90 | 0 | 9 |
| `authorization.federated` | crates | not applicable | | |
| | aauth-go | 62 | 0 | 336 |
| | aauth-rust | 62 | 0 | 336 |

With the subject clause counted, aauth-go and aauth-rust each pass 99 Person
Server assertions, with 10 not exercised. The crates have no Access Server
and no four-party Resource, so the four-party role does not apply to them.

The Person Server's person token stage matches aauth-go and aauth-rust
exactly: 57 passed and 6 not exercised in all three. Every difference is in the auth token stage.

## Findings

- **Auth tokens are refused without a mission.** Every auth token request
  answered `403` with `{"error":"access_denied","detail":"an auth token is
  issued only within a mission"}`. The crate documents this as fixed policy.
  The protocol draft makes `mission_s256` optional, and the suite's direct
  Person Server scenarios present none. This one answer causes all 24 Person
  Server failures:
  - In the valid and short-parent scenarios, `ps.auth-endpoint` expects
    `200`, so the auth token checks under `ps.common-verification`,
    `ps.auth-structure`, `ps.auth-lifetime` and `ps.host-scope-policy` find
    no token.
  - Five resource token faults expect `400 invalid_resource_token` under
    `ps.resource-verification`: wrong audience, key, person, lineage and
    Person Server. An expired resource token expects
    `400 expired_resource_token` under `ps.errors`. Each got the `403`
    above. The mission check runs before the resource token is verified, so
    the crate's resource token checks were never reached.
- **The 9 auth token passes come from the same refusal.** Six are
  "no token issued" checks on the fault scenarios. Three are the denied
  scope scenario, which expects `403 access_denied` from scope policy. None
  of them shows that the crate checks the resource token or the scope.
- **The Resource sends no `required_input`.** Under `core.verification`, a
  request whose signature does not cover `signature-key` got
  `401` with `Signature-Error: error=invalid_input` and no `required_input`
  member. The suite expects
  `required_input=("@method" "@authority" "@path" "signature-key")`. The
  HTTP Signature Keys draft makes the member RECOMMENDED: a server SHOULD
  include it, and MAY omit it as a disclosure risk.
- **The Resource sends no response body.** The four `key.response-body`
  checks were not exercised, because the crate offers no error body and the
  draft permits other body representations.
- **The expired agent token result depends on the deployment.** The crate
  reports an expired agent token as `TokenError` `token_expired` and names no
  answer for it. The deployment answers `Signature-Error: error=expired_jwt`,
  the mapping `aauth-person-server` uses itself. That check passed.
- **Not exercised in every implementation.** The expired presented token
  scenario needs the Person Server's private key, so remote mode cannot run
  it.
