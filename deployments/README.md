# Reference deployments

Each folder stands up one AAuth library as real HTTPS servers that remote
mode ([REMOTE.md](../REMOTE.md)) can test. They are the deployments the
remote counts were measured against, and a worked example of preparing your
own:

- [aauth-go](aauth-go/) serves aauth-go's native roles.
- [aauth-rust](aauth-rust/) serves aauth-rust's native roles.
- [aauth-protocol](aauth-protocol/) serves the community `aauth-protocol`
  and `aauth-person-server` crates: an agent-identity Resource and a direct
  Person Server, under `https://api.aauth-protocol.test` and
  `https://person.aauth-protocol.test`. Its README says what the deployment
  adds to them.

aauth-go and aauth-rust start the same roles under their own names, with a
signing key generated at start. They discover every other party's keys over
HTTPS, and trust only the suite's parties and each other. Their policy
follows the remote mode test profile. `LIB` below is `go` or `rust`.

| Name | Role | Suite role it serves |
| --- | --- | --- |
| `https://api.aauth-LIB.test` | Resource, agent identity, at `/whoami` | `resource.agent-identity` |
| `https://person.aauth-LIB.test` | Person Server, direct (three-party) | `person-server.direct` |
| `https://records.aauth-LIB.test` | Resource, four-party, at `/records` | `authorization.federated` |
| `https://ps.aauth-LIB.test` | Person Server, four-party | `authorization.federated` |
| `https://access.aauth-LIB.test` | Access Server | `authorization.federated` |
| `https://ap.aauth-LIB.test` | Agent Provider with an event endpoint, serving `aauth:agent@ap.aauth-LIB.test` | `events.agent-provider`, `events.agent` |
| `https://events.aauth-LIB.test` | Events Resource, subscriptions at `/events/subscribe` | `events.subscription`, `events.delivery` |
| `https://ss.aauth-LIB.test` | Supervision server | `supervision.server` |
| `https://sps.aauth-LIB.test` | Person Server whose every Agent the suite's supervisor at `https://ss.conformance.test` supervises | `supervision.person-server` |
| `https://r3.aauth-LIB.test` | R3 Resource, four-party, at `/authorize` | `r3.resource` |
| `https://r3-direct.aauth-LIB.test` | R3 Resource, three-party, at `/authorize` | `r3.resource` |
| `https://r3-person.aauth-LIB.test` | Person Server issuing R3 Auth tokens | `r3.issuer` |
| `https://r3-ps.aauth-go.test`, `https://r3-access.aauth-go.test` | Person Server and Access Server issuing four-party R3 Auth tokens (aauth-go only) | `r3.federated-issuer` |
| `https://verifier.aauth-LIB.test` | Signature-Key verifier Resource at `/verify` | `sigkey.verifier` |
| `https://control.aauth-LIB.test` | Host controls, under one path per suite role | every role with a control |

aauth-rust's Access Server offers no R3 issuance, so the aauth-rust
deployment does not serve `r3.federated-issuer`. State is kept in memory
and is lost when a server stops. The host controls are test hooks for the
suite, not part of any library.

## Reproduce the remote run

```sh
deployments/run-remote.sh /path/to/aauth-go /path/to/aauth-rust build/remote-run
```

The script builds the suite runner, the two library deployments against the
two checkouts, and the aauth-protocol deployment from its pinned crates. It
makes a throwaway test CA and certificates, starts the deployments on
loopback ports and runs remote mode against each. The reports are written to
`build/remote-run/remote-aauth-go/`, `build/remote-run/remote-aauth-rust/`
and `build/remote-run/remote-aauth-protocol/`. `LIBS` and `REMOTE_ROLES`
narrow a run, for example `LIBS="go rust" REMOTE_ROLES="supervision.server"`.

It needs Go 1.25 or later, rustup, openssl and jq. Every name is routed to
its loopback port by the suite's `-resolve` flags and each deployment's
`resolve` map, so no DNS or hosts entries are needed.

[roles/](roles/) says what the library deployments serve, one file per role
family: `names` (server names, with `LIB` for the library), `trusted`
(further suite parties to trust) and `roles` (the deployment file's roles).
Optional `libraries` limits a file to some libraries, and `roles_by_lib`
replaces a role for one library. aauth-go uses it to leave unclaimed what
its launchers leave unclaimed, where the library hands a duty to its host.

## Configuration

The aauth-go and aauth-rust deployments read one JSON file:

| Member | Meaning |
| --- | --- |
| `listen` | Address to serve HTTPS on. |
| `cert`, `key` | PEM certificate and key for all its names. |
| `ca` | PEM roots it trusts for outbound HTTPS. |
| `resolve` | `host:443` to address, for every name it connects to; others are refused. |
| `identity_resource`, `direct_person_server`, `federated_resource`, `federated_person_server`, `access_server` | The issuer identifiers of the core roles. |
| `names` | The further roles' names, by the key each role file documents; `control` is the host-control origin. |
| `agent_providers`, `person_servers`, `resources`, `trusted` | The suite's parties it trusts. |
