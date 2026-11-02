# aauth-protocol deployment

Serves two community crates over HTTPS for remote mode:

| Name | Role | Built with |
| --- | --- | --- |
| `https://api.aauth-protocol.test` | Resource, agent identity, at `/whoami` | `aauth-protocol` 0.2.0, `resource::authenticate` |
| `https://person.aauth-protocol.test` | Person Server, direct (three-party) | `aauth-person-server` 0.1.0, `PersonServer` |

Both crates are taken from the crates.io registry at those exact versions;
`Cargo.lock` pins every dependency. `aauth-person-server` 0.1.0 is built on
`aauth-protocol` 0.1.0, so the Person Server runs that release, not 0.2.0.
The crates offer no Access Server or four-party Resource, so the four-party
role is not deployed.

## What the deployment adds

The crates leave a few things to the host. This deployment fills them in as
follows, and does nothing else on the wire:

- **Unsigned request.** A request with no `Signature`, `Signature-Input` or
  `Signature-Key` header is answered `401` with
  `resource::challenge(&Requirement::AgentToken)`.
- **Signature errors.** A `SignatureError` is answered `401` with
  `Signature-Error` set to its `header_value()`, as the crate documents.
- **Token errors.** The crate names no answer for a `TokenError`. The
  deployment uses `aauth-person-server`'s own mapping: `token_expired` is
  `Signature-Error: error=expired_jwt`, any other code is
  `error=invalid_jwt`, both with `401`.
- **Trusted issuers.** `resource::authenticate` looks up whichever issuer a
  token names. The deployment's resolver refuses any issuer that is not a
  configured agent provider before `JwksResolver` fetches anything.
- **The person.** The test profile binds every request to one person. The
  Person Server finds the person for a request without `login_hint` only
  through the agent key's binding, so the store treats every key not yet
  bound as bound to that person.
- **Network.** Both crates fetch through a `Fetch` over this deployment's
  client. It routes each name by the `resolve` map, refuses every other name,
  and trusts only the configured CA, in place of the crates' default
  `ReqwestFetch::guarded`, which refuses loopback addresses.

`src/main.rs` shares aauth-rust's HTTPS server and client,
`../aauth-rust/src/https.rs`. Keys are generated at start and state is kept
in memory.

## Profile items the crates cannot follow

- **Subject.** The Person Server derives each `sub` from a secret, the
  person and the audience. The profile's fixed subject `directed-person-1`
  cannot be configured. [deployment.json](deployment.json) leaves the
  clause that grades it, `ps.host-person-profile`, unclaimed.
- **Auth tokens.** The Person Server issues an auth token only within a
  mission, and that is fixed policy. The suite's direct Person Server
  scenarios present no mission, so every auth token request is refused. Those
  clauses stay claimed: the endpoint exists and its answer is graded.

## Build and run

```sh
cargo build --release --locked
target/release/aauth-protocol-deployment deployment-config.json
```

The configuration has the members the [deployments README](../README.md)
lists, except that it names only `identity_resource` and
`direct_person_server`, and trusts only `agent_providers`.
[`run-remote.sh`](../run-remote.sh) builds and runs it with the other two
deployments.
