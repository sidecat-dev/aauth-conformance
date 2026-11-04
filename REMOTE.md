# Remote mode

Remote mode runs the suite against AAuth servers you have deployed, over
HTTPS, with no adapter. You name your servers by URL. The suite plays every
other party itself: the Agent, the Agent Provider, the Resource, the Person
Server or the Access Server, whichever the role does not name. It writes the
same clause-tagged reports as a launcher run, so the counts compare directly.

## What it runs

| Suite role | What you name | Scenarios run | Without a control |
| --- | --- | ---: | ---: |
| `resource.agent-identity` | `resource` | 6 of 6 | 6 |
| `person-server.direct` | `person_server` | 11 of 12 | 11 |
| `authorization.federated` | `resource`, `access_server`, optional `person_server` | 7 of 34 | 7 |
| `events.agent-provider` | `agent_provider`, `agent` | 17 of 17 | 0 |
| `events.subscription` | `resource` (the subscription endpoint) | 11 of 11 | 8 |
| `events.delivery` | `resource` (the subscription endpoint) | 1 of 1 | 0 |
| `events.agent` | `agent`, `control` | 11 of 11 | 0 |
| `supervision.server` | `supervision_server` | 14 of 14 | 12 |
| `supervision.person-server` | `person_server` | 12 of 12 | 9 |
| `r3.resource` | `resource` (four-party), optional `three_party_resource` | 10 of 10 | 10 |
| `r3.issuer` | `person_server` | 4 of 4 | 4 |
| `r3.federated-issuer` | `person_server`, `access_server` | 3 of 3 | 3 |
| `sigkey.verifier` | `resource` (the verifier) | 31 of 31 | 31 |

"Scenarios run" counts the scenarios that run when you name every server
and a control. The last column counts those that still run without a
control. In `r3.resource`, scenario 147 needs `three_party_resource`, and
the execution counts of 148 and 149 need the control.

The other roles still need launchers. The Agent signer and the vector roles
call library functions or a client signer. Deferred authorization,
sub-agents and missions have no remote driver.

### What is not exercised, and why

A scenario that needs something only a launcher has is reported
`not_exercised`, with the reason on each assertion. It is never counted as a
failure or a pass. The reasons:

- **Re-signs a deployed server's token (19).** The expired presented token
  scenario of `person-server.direct` needs your Person Server's private key.
- **Re-signs the Resource's challenge (44-47, 49).** The four-party
  Resource-token faults need your Resource's private key.
- **Injects a fault between your Person Server and Access Server (24-39).**
  The suite cannot sit between them.
- **The Person Server's request to the Access Server is not observable.** In
  the four-party scenarios that run with your Person Server (22, 23), the
  `handoff` and `access` stages are not observed.
- **Uses the launcher's budget paths and `X-Fixture-*` cost headers (73-78).**
- **The deployment names no `person_server`.** Then the four-party role runs
  only the five scenarios in which the suite is the Person Server (40-43, 48).
- **Needs a host control, and the deployment names no control.** The reason
  names the control path. See [Host controls](#host-controls).
- **The deployment names no `three_party_resource`** (`r3.resource`, 147).
- **A supervised Person Server's events and reports, without a control.**
  It delivers them when its host asks (`{"deliver": true}`), so without a
  control the `event:` and `report:` assertions of
  `supervision.person-server` are not exercised.
- **A supervised Person Server that made no connect in the run.** It
  connects to a supervisor once. If it was connected to the suite's
  supervisor before the run, restart it to grade its connect.
- **The supervision server publishes no `jwks_uri`.** The draft makes
  `jwks_uri` optional, and a server without one signs no decisions, so the
  `ss-signed` assertions are not exercised.

## Prepare your deployment

[deployments/](deployments/) holds reference deployments of aauth-go and
aauth-rust prepared this way, and a script that reproduces the remote run
against both.

**Trust the suite's parties.** The suite serves the metadata and JWKS of
every party it plays over HTTPS, under its fixture names. These are the
names that `aauth-conformance -harness-names` prints:

| Name | Plays | Your role trusts it when |
| --- | --- | --- |
| `ap.conformance.test` | Agent Provider (`aauth-agent.json`, with an `event_endpoint`) | every role with an Agent |
| `resource.conformance.test` | Resource (`aauth-resource.json`) | your Person Server, Access Server, Agent Provider, Agent and R3 issuers |
| `person.conformance.test` | Person Server (`aauth-person.json`) | your four-party Resource and Access Server, Events Resource, supervision server and R3 Resources |
| `access.conformance.test` | Access Server (`aauth-access.json`) | your four-party R3 Resource |
| `other-resource.conformance.test` | a second Events Resource | your Agent Provider |
| `other-ps.conformance.test` | a Person Server you must refuse | your supervision server |
| `ss.conformance.test` | the supervision server (`aauth-supervisor.json`, with a `jwks_uri`) | your supervised Person Server |
| `foreign-ss.conformance.test` | another supervision server, whose decisions your Person Server must refuse | your supervised Person Server |
| `other.conformance.test` | a trusted server no R3 document entitles | your four-party R3 Resource |
| `signer.conformance.test`, `keys.conformance.test` | the `jwks_uri` signer (`aauth-resource.json`, and `example-configuration` for a `dwk` that names no AAuth role) and a direct JWKS URL | your verifier |
| `ap-mixed`, `ap-pq-only`, `signer-mixed`, `signer-pq-only` `.conformance.test` | the same parties with mixed or post-quantum-only key sets | your verifier |

Server identifiers carry no port. Your servers must reach these names on
port 443 of the machine running the suite, through DNS or host entries.
Give the suite a certificate for all of them that your servers trust.

**Publish your own keys.** The suite discovers each server's signing keys
from the metadata document its role publishes (`aauth-person.json`,
`aauth-access.json`, `aauth-resource.json`, `aauth-agent.json` or
`aauth-supervisor.json`) and the JWKS that names. These are the documents
the drafts already require. Token, response and request signatures are
checked with Ed25519 or ES256 (P-256) keys, each under its own algorithm. The
suite reads endpoints from the same metadata: a Person Server's
`person_token_endpoint` and `auth_token_endpoint`, an R3 Resource's
`authorization_endpoint`, a supervision server's four endpoints and an Agent
Provider's `event_endpoint`.

**Follow the test profile.** Some expected answers depend on host policy.
The clauses scoped `adapter-contract` grade that policy:

- **Resources.** The agent-identity Resource admits the suite's Agent and
  answers 200 with the JSON `{"sub": "<agent identifier>"}`. The four-party
  Resource requires `read`, names your Access Server and admits
  `directed-person-1` from your Person Server and from
  `https://person.conformance.test`, with the same answer.
- **Person and Access Servers.** The Person Server binds every request to the
  subject `directed-person-1`. It grants only the `read` scope and refuses
  any other scope as a policy denial. The Access Server trusts both Person
  Servers and grants only `read`.
- **Agent Provider.** It serves one Agent, the one the role names as `agent`,
  whose signing key is the fixture's agent key. It trusts
  `resource.conformance.test` and `other-resource.conformance.test`.
- **Events Resource.** It trusts the suite's Agent Provider and Person
  Server, admits any verified subscription, delivers only to trusted Agent
  Providers, and publishes `aauth-resource.json` with a `jwks_uri`. Its
  ticket URLs may use any path on its origin.
- **Agent.** It trusts `resource.conformance.test` as an event signer.
- **Supervision server.** It connects only `person.conformance.test` and
  refuses `other-ps.conformance.test` with 403 and `unsupported_iss`. It
  allows token and mission acts and the permission `fixture.allow`, and
  defers `fixture.defer`. Pending `Location` URLs are on its own origin.
- **Supervised Person Server.** It routes every Agent to the supervision
  server `https://ss.conformance.test`, with the person's identifier there
  `ss-directed-person-1`, discovers that server's keys from its
  `aauth-supervisor.json` and acts only on decisions it signed. Its own
  policy decides nothing for those Agents. It binds `directed-person-1`, as
  the direct Person Server does, and offers missions.
- **R3 Resources.** Both offer the MCP tools `records.read`,
  `records.export` and `records.delete` at `/op/{tool}` and accept
  `directed-person-1` with `read`. The four-party one trusts
  `access.conformance.test`, the suite Person Server and
  `other.conformance.test`, and offers per-call authorization. The
  three-party one trusts the suite Person Server.
- **R3 issuers.** They trust the suite's Agent Provider and Resource, fetch
  R3 documents only under `https://resource.conformance.test/r3/`, and grant
  `records.read` and `records.export`.
- **Signature-Key verifier.** It answers a verified request with 200. It
  trusts the suite's Agent Provider and the signer, JWKS and variant names
  above. Self-issued JWTs carry `typ` `conformance-self+jwt`.

If your deployment does not follow the profile, list the clauses you want
graded under the role's `claims`. Lifetimes are yours to choose, within the
drafts' parent ceilings.

### Host controls

Some scenarios need the host to act in a way no protocol message asks for:
an Agent Provider issuing a subscribe token (the Events draft leaves that to
the AP), a Resource firing an event, an Agent checking an event token, a
supervision server resolving a deferred decision, or a Person Server
answering for the person, polling a deferred supervisor or delivering its
queued events. `pending` names the held act by the pending URL the Person
Server gave the Agent. A deployment that offers
these test hooks names a `control` URL per role. The suite POSTs JSON to
these paths under it, and treats every answer as host input, never protocol
output:

| Role | Path | Body | Answer |
| --- | --- | --- | --- |
| `events.agent-provider` | `/__fixture/subscribe` | `{"max_uses", "agent", "agent_jwk", "resource"}` | `{"token"}` |
| `events.agent-provider` | `/__fixture/pending` | `{"agent"}` | `{"events": [{"event_token", "body"}]}` |
| `events.subscription` | `/__fixture/ticket` | `{"person_token"}` | `{"url"}` |
| `events.delivery` | `/__fixture/fire` | `{"agent_provider", "eid", "body"}` | `{"status"}` |
| `events.agent` | `/__fixture/event` | `{"event_token", "body", "content_type"}` | `{"accepted", "error"}` |
| `supervision.server` | `/__fixture/supervision` | `{"resolve": {"sdi", "verdict"}}` or `{"rate_limit": true}` | 200 |
| `supervision.person-server` | `/__fixture/supervision` | `{"deliver": true}`, or `{"resolve": "allow", "pending"}` or `{"advance": true, "pending"}` | 200 |
| `r3.resource` | `/__fixture/r3/executions` (GET) | none | execution counts by tool |

A deployment without a control still runs every scenario that needs none.
Do not expose controls on a production server.

`-public` grades a deployment you do not operate. It drops every `control`
before the run, including one copied from a reference deployment, so the
scenarios that need a control are not exercised and the suite does not dial
them. A reference file often names `control.aauth-rust.internal`, or the Go
name of the same shape. That name is not public DNS. Without `-public`, a run
that still names it records `lookup ... no such host` and those assertions
are errors.

`permitted_scopes` and `denied_scopes` are the deployment's scope profile. Omitted, the suite does not assume that an Auth token carries `read` or that `admin` is refused, and those checks are `not_exercised`. A check that needs an Auth token is `not_exercised` when the token endpoint does not issue one. The endpoint status itself stays a failure.

`-harness-domain aauth.sidecat.dev` publishes each harness party as `name-harness.aauth.sidecat.dev` instead of `name.conformance.test`. A third party can resolve those names and fetch them over a public certificate. The Person Server still has to trust `https://resource-harness.aauth.sidecat.dev`.

Set `bootstrap_provider` in the deployment file, or pass `-agent-provider`,
to an Agent Provider the servers under test trust. The suite enrolls its
durable key there and refreshes an agent token whose `ps` is the Person
Server that role names. A Person Server accepts the token only when `ps` is
its own issuer, so the provider has to copy `ps` from the refresh body. The
hosted provider `https://ap.aauth.sidecat.dev` does. A scenario that needs
an expired or shorter agent token is not exercised: this suite does not hold
the provider's signing key. `supervision.server` still signs as the harness
Person Server, so that role needs the callback receiver below. Enrollment
does not publish that server.

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
    },
    "events.agent-provider": {
      "agent_provider": "https://ap.example",
      "agent": "aauth:agent@ap.example",
      "control": "https://test-hooks.example/ap"
    },
    "supervision.server": {"supervision_server": "https://ss.example"}
  }
}
```

| Member | Meaning |
| --- | --- |
| `resource`, `three_party_resource` | URL of a protected resource, or of the endpoint the role names. |
| `person_server`, `access_server`, `agent_provider`, `supervision_server` | Issuer identifiers. |
| `agent` | The agent identifier, `aauth:local@domain`, your Agent Provider serves for the suite's Agent. |
| `control` | HTTPS URL under which the role's host controls are served. |
| `claims` | Clauses to grade, if not the role's default. |

Name only the roles you want to run. One server may appear in several
roles, as long as it behaves as each role needs. A name the suite serves is
refused.

## Run

```sh
go build -o build/aauth-conformance ./cmd/aauth-conformance
build/aauth-conformance -harness-names        # names for the suite's certificate
build/aauth-conformance -remote deployment.json -out build/remote \
  -tls-cert suite.pem -tls-key suite.key
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `:443` | Address that serves the suite's own parties. This is the callback receiver. |
| `-tls-cert`, `-tls-key` | none | PEM certificate and key for the suite's names. |
| `-ca` | system roots | PEM roots to trust for your servers. Leave it unset for public certificates. |
| `-resolve` | DNS | `host:443=address` to connect to instead, like curl's `--resolve`. Repeatable. |
| `-skew` | `5` | Seconds a server's clock may differ from the suite's. |
| `-out` | `build/remote` | Directory for `ROLE.json` and `ROLE.md`, one pair per role. |
| `-public` | off | Grade a deployment you do not operate. Omit host controls. `-listen` must not be loopback. |
| `-agent-provider` | deployment `bootstrap_provider`, or none | Bootstrap Agent Provider to enroll the suite's durable key at. The suite presents that provider's agent token. A server is graded only when it trusts this provider. |
| `-harness-names` | off | Print the names the suite serves, one per line, and exit. |

The exit status is 0 when no role failed. A role whose assertions are all
`not_exercised` or `not_claimed` did not fail, and its `execution` is
`not_exercised`. The status is 1 when an assertion is `fail` or `error`, or
a run or case records an error (`execution` `failed_or_incomplete`). It is 2
for invalid input. A role with a passing assertion and no failure has
`execution` `passed`. Each report records `"transport": "remote"` and names
the servers it tested under the implementation's `remote`.

### Callback receiver

The scenarios that still run call back to the suite. A Resource delivers to
the Agent Provider, an R3 issuer fetches documents under
`https://resource.conformance.test/r3/`, a supervision server checks the
Person Server it connected, and a supervised Person Server connects to
`https://ss.conformance.test`. Those names have no public DNS. The graded
deployment routes every name `-harness-names` prints to the suite's
`-listen` address, and trusts the certificate that listener presents.

`-public` refuses a loopback `-listen`. The graded servers are not on the
suite's machine, so `127.0.0.1` is not a receiver they can reach. Listen on
every interface (`:8443`, `0.0.0.0:8443`) or on a public IP. The deployment's
route is what sends port 443 of the harness names to that address.

## How remote grading differs

- **Clocks.** Your servers read their own clocks. Issued-at and signed
  `created` values from your servers may differ from the suite's clock by
  `-skew` seconds. The suite signs with its own clock.
- **Identities.** Where an expected value names a fixture identity your
  deployment replaces, such as a supervision server's `issuer`, the suite
  expects your server's identity instead.
- **Agent Provider `event_endpoint`.** The suite grades the endpoint your
  metadata publishes, which must be an HTTPS URL with no query or fragment,
  and delivers there. A launcher is graded against the fixture's fixed path.
- **Long-running servers.** A deployed server keeps state across scenarios.
  The suite grades what each case adds: pending events for the case's own
  event ID, R3 execution counts read before and after the calls, and a
  supervised Person Server's events and reports that carry no `sdi` or one
  of the case's own. Its first connect of the run is graded in the cases
  that follow it. The
  verifier's key-set variants use their own names, so cached keys from
  another case never apply.

## Limits

- TLS, discovery security, egress admission and key rotation are not graded.
- A remote run of the four-party role exercises fewer scenarios than a
  launcher run. Compare counts over the scenarios both run.
