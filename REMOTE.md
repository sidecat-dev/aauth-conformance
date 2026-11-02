# Remote mode

Remote mode runs the suite against AAuth servers you have deployed, over
HTTPS, with no adapter. You name your servers by URL. The suite plays every
other party itself: the Agent, the Agent Provider and, depending on the role,
the Resource or the Person Server. It writes the same clause-tagged reports
as a launcher run, so the counts compare directly.

## What it runs

| Suite role | Servers you name | Scenarios run |
| --- | --- | ---: |
| `resource.agent-identity` | `resource` | 6 of 6 |
| `person-server.direct` | `person_server` | 11 of 12 |
| `authorization.federated` | `resource`, `access_server`, optional `person_server` | 7 of 34 |

A scenario that needs something only a launcher has is reported
`not_exercised`, with the reason on each assertion. It is never counted as a
failure or a pass:

- **Person Server, expired presented token (19):** the suite would re-sign
  your Person Server's token, which needs its private key.
- **Four-party Budget scenarios (73-78):** they use the launcher's fixed
  budget paths and `X-Fixture-*` cost headers.
- **Four-party faults between your Person Server and Access Server (24-39):**
  the suite cannot sit between them. In the two scenarios that do run with
  your Person Server (22, 23), the `handoff` and `access` stages are not
  observed.
- **Four-party Resource-token faults (44-47, 49):** they re-sign your
  Resource's challenge, which needs its private key.

Without `person_server`, the four-party role runs only the five scenarios in
which the suite is the Person Server (40-43, 48). The other roles still need
launchers. They use host controls, library functions or a client signer, or
remote mode has no driver for them yet.

## Prepare your deployment

[deployments/](deployments/) holds reference deployments of aauth-go and
aauth-rust prepared this way, and a script that reproduces the remote run
against both.

**Trust the suite's parties.** Your servers must trust these issuers and
discover their keys:

| Issuer | Document | Trusted by |
| --- | --- | --- |
| `https://ap.conformance.test` | `aauth-agent.json` | every role |
| `https://resource.conformance.test` | `aauth-resource.json` | your direct Person Server |
| `https://person.conformance.test` | `aauth-person.json` | your four-party Resource and Access Server |

The suite serves their metadata and JWKS over HTTPS. Server identifiers carry
no port, so your servers must reach these names on port 443 of the machine
running the suite, through DNS or host entries. Give the suite a certificate
for the three names that your servers trust.

**Publish your own keys.** The suite discovers each server's Ed25519 signing
keys from its metadata (`aauth-person.json`, `aauth-access.json` or
`aauth-resource.json`) and the JWKS that names. These are the documents the
drafts already require. The suite's token checks support Ed25519 only. Its
Agent sends person token and auth token requests to the
`person_token_endpoint` and `auth_token_endpoint` your Person Server's
metadata names.

**Follow the test profile.** Some expected answers depend on host policy.
The clauses scoped `adapter-contract` grade that policy:

- The agent-identity Resource admits the suite's Agent and answers 200 with
  the JSON `{"sub": "<agent identifier>"}`.
- The Person Server binds every request to the subject `directed-person-1`.
  It grants only the `read` scope and refuses any other scope as a policy
  denial.
- The four-party Resource requires `read` and names your Access Server. It
  admits `directed-person-1` from your Person Server and from
  `https://person.conformance.test`, and answers with the same subject JSON.
- The Access Server trusts both Person Servers and grants only `read`.

If your deployment does not follow the profile, list the clauses you want
graded under the role's `claims`. Lifetimes are yours to choose, within the
drafts' parent ceilings.

## Name your servers

```json
{
  "version": 1,
  "id": "my-implementation",
  "revision": "v1.4.2",
  "roles": {
    "resource.agent-identity": {"resource": "https://api.example/whoami"},
    "person-server.direct": {"person_server": "https://ps.example"},
    "authorization.federated": {
      "resource": "https://records.example/records",
      "person_server": "https://ps4.example",
      "access_server": "https://as.example"
    }
  }
}
```

`resource` is the URL of a protected resource. The other servers are named by
their issuer identifiers. Name only the roles you want to run. One server may
appear in several roles, as long as it behaves as each role needs.

## Run

```sh
go build -o build/aauth-conformance ./cmd/aauth-conformance
build/aauth-conformance -remote deployment.json -out build/remote \
  -tls-cert suite.pem -tls-key suite.key
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `:443` | Address that serves the suite's parties. |
| `-tls-cert`, `-tls-key` | none | PEM certificate and key for the suite's three names. |
| `-ca` | system roots | PEM roots to trust for your servers. |
| `-resolve` | DNS | `host:443=address` to connect to instead, like curl's `--resolve`. Repeatable. |
| `-skew` | `5` | Seconds a server's issued-at time may differ from the suite's clock. |
| `-out` | `build/remote` | Directory for `ROLE.json` and `ROLE.md`, one pair per role. |

The exit codes are the same as a launcher run: 0 when every role passed, 1
for a failed or incomplete role, 2 for invalid input. Each report records
`"transport": "remote"` and names the servers it tested under the
implementation's `remote`.

## Limits

- Your servers read their own clocks. Issued-at checks allow `-skew`
  seconds; signed `created` values use the suite's clock.
- TLS, discovery security, egress admission and key rotation are not graded.
- A remote run exercises fewer scenarios than a launcher run of the same
  role. Compare counts over the scenarios both run.
