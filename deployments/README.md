# Reference deployments

Each folder stands up one AAuth library as real HTTPS servers that remote
mode ([REMOTE.md](../REMOTE.md)) can test. They are the deployments the
remote counts were measured against, and a worked example of preparing your
own:

- [aauth-go](aauth-go/) serves aauth-go's native roles.
- [aauth-rust](aauth-rust/) serves aauth-rust's native roles.

Both start the same five roles under their own names, with a signing key
generated at start. They discover every other party's keys over HTTPS, and
trust only the suite's parties and each other. Their policy follows the
remote mode test profile.

| Name | Role | Suite role it serves |
| --- | --- | --- |
| `https://api.aauth-LIB.test` | Resource, agent identity, at `/whoami` | `resource.agent-identity` |
| `https://person.aauth-LIB.test` | Person Server, direct (three-party) | `person-server.direct` |
| `https://records.aauth-LIB.test` | Resource, four-party, at `/records` | `authorization.federated` |
| `https://ps.aauth-LIB.test` | Person Server, four-party | `authorization.federated` |
| `https://access.aauth-LIB.test` | Access Server | `authorization.federated` |

State is kept in memory and is lost when a server stops.

## Reproduce the remote run

```sh
deployments/run-remote.sh /path/to/aauth-go /path/to/aauth-rust build/remote-run
```

The script builds the suite runner and both deployments against the two
checkouts. It makes a throwaway test CA and certificates, starts both
deployments on loopback ports and runs remote mode against each. The reports
are written to `build/remote-run/remote-aauth-go/` and
`build/remote-run/remote-aauth-rust/`.

It needs Go 1.25 or later, rustup and openssl. Every name is routed to its
loopback port by the suite's `-resolve` flags and each deployment's
`resolve` map, so no DNS or hosts entries are needed.

## Configuration

Each deployment reads one JSON file:

| Member | Meaning |
| --- | --- |
| `listen` | Address to serve HTTPS on. |
| `cert`, `key` | PEM certificate and key for all five names. |
| `ca` | PEM roots it trusts for outbound HTTPS. |
| `resolve` | `host:443` to address, for every name it connects to; others are refused. |
| `identity_resource`, `direct_person_server`, `federated_resource`, `federated_person_server`, `access_server` | Its five issuer identifiers. |
| `agent_providers`, `person_servers`, `resources` | The suite's parties it trusts. |
