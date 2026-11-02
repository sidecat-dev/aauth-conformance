//! aauth-protocol-deployment serves the Resource side of the aauth-protocol
//! crate and the Person Server of the aauth-person-server crate over HTTPS,
//! as a deployment the conformance suite's remote mode can test. Each role
//! has its own name. Both discover every other party's keys over HTTPS, from
//! the agent providers they trust only. Policy follows the suite's test
//! profile as far as the crates let a host set it: see README.md.
// Shared with the aauth-rust deployment, which owns its form; this one does
// not use every part.
#[path = "../../aauth-rust/src/https.rs"]
#[allow(dead_code)]
#[rustfmt::skip]
mod https;

use aauth_person_server::{
    self as person_server, Approval, ApprovalStatus, LogEntry, MemoryStore, Mission, Person, Spend,
    Store, StoreResult,
};
use aauth_protocol::{
    Error, Requirement,
    discovery::{JwksResolver, KeyResolver},
    httpsig::{Incoming, VerifyOptions},
    jwk::Jwks,
    resource,
    token::TokenKind,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use https::{Client, Failure};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};

/// The aauth-protocol release aauth-person-server 0.1.0 is built on.
use aauth_person_server::aauth_protocol as person_protocol;

/// The deployment: its names, what it trusts and how it connects.
#[derive(Deserialize)]
struct Config {
    listen: String,
    cert: String,
    key: String,
    ca: String,
    resolve: BTreeMap<String, String>,
    identity_resource: String,
    direct_person_server: String,
    agent_providers: Vec<String>,
}

/// GETs over this deployment's client, for both crates' discovery.
struct Network(Arc<Client>);

impl Network {
    fn fetch(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
        let mut request = Request::builder().uri(url).body(Vec::new())?;
        *request.headers_mut() = headers;
        let (parts, body) = self.0.send(&request)?.into_parts();
        Ok((parts.status, parts.headers, body.into()))
    }
}

#[async_trait]
impl aauth_protocol::discovery::Fetch for Network {
    async fn get(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> aauth_protocol::Result<aauth_protocol::discovery::Fetched> {
        let (status, headers, body) = self
            .fetch(url, headers)
            .map_err(|error| Error::Http(error.to_string()))?;
        Ok(aauth_protocol::discovery::Fetched {
            status,
            headers,
            body,
        })
    }
}

#[async_trait]
impl person_protocol::discovery::Fetch for Network {
    async fn get(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> person_protocol::Result<person_protocol::discovery::Fetched> {
        let (status, headers, body) = self
            .fetch(url, headers)
            .map_err(|error| person_protocol::Error::Http(error.to_string()))?;
        Ok(person_protocol::discovery::Fetched {
            status,
            headers,
            body,
        })
    }
}

/// Discovery for the Resource, admitting only the agent providers it trusts:
/// `resource::authenticate` looks up whichever issuer a token names.
struct Trusted {
    issuers: Vec<String>,
    resolver: JwksResolver,
}

#[async_trait]
impl KeyResolver for Trusted {
    async fn jwks(&self, issuer: &str, dwk: &str) -> aauth_protocol::Result<Jwks> {
        if !self.issuers.iter().any(|trusted| trusted == issuer) {
            return Err(Error::Discovery(format!("{issuer} is not trusted here")));
        }
        self.resolver.jwks(issuer, dwk).await
    }
}

/// The agent-identity Resource at `/whoami`: admits any trusted agent and
/// echoes its identifier.
struct IdentityResource {
    issuer: String,
    keys: Trusted,
}

impl IdentityResource {
    async fn handle(&self, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        let headers = request.headers();
        if request.uri().path() != "/whoami" {
            return respond(StatusCode::NOT_FOUND, Vec::new(), Vec::new());
        }
        if ["signature", "signature-input", "signature-key"]
            .iter()
            .all(|name| !headers.contains_key(*name))
        {
            return respond(
                StatusCode::UNAUTHORIZED,
                resource::challenge(&Requirement::AgentToken),
                Vec::new(),
            );
        }
        let body = request.body();
        let incoming = Incoming {
            method: request.method().as_str(),
            authority: host(&self.issuer),
            path: request.uri().path(),
            query: request.uri().query(),
            headers,
            body: (!body.is_empty()).then_some(body.as_slice()),
        };
        let verified = resource::authenticate(
            &incoming,
            &self.issuer,
            &[TokenKind::Agent],
            &VerifyOptions::default(),
            &self.keys,
        )
        .await;
        let signature_error = |value: String| {
            respond(
                StatusCode::UNAUTHORIZED,
                vec![("signature-error".into(), value)],
                Vec::new(),
            )
        };
        match verified {
            Ok(authenticated) => json(
                StatusCode::OK,
                serde_json::json!({ "sub": authenticated.token.sub }),
            ),
            Err(Error::Signature(error)) => signature_error(error.header_value()),
            // The crate names no answer for a token that does not verify.
            // This is aauth-person-server's own mapping (verify_agent).
            Err(Error::Token(error)) => {
                let code = if error.code == "token_expired" {
                    "expired_jwt"
                } else {
                    "invalid_jwt"
                };
                signature_error(format!("error={code}"))
            }
            Err(error) => {
                eprintln!("whoami: {error}");
                respond(StatusCode::INTERNAL_SERVER_ERROR, Vec::new(), Vec::new())
            }
        }
    }
}

/// The test profile's one person, whom every agent acts for.
fn profile_person() -> Person {
    Person::new("profile-person")
}

/// The profile binds every request to one person, named or not.
struct ProfileDirectory;

#[async_trait]
impl person_server::Directory for ProfileDirectory {
    async fn person(&self, _login_hint: &str, _tenant: &str) -> Option<Person> {
        Some(profile_person())
    }
}

/// `MemoryStore`, with every agent key not yet bound taken to be bound to
/// the profile's person: the crate finds the person for a request without
/// `login_hint` only through the key's binding.
struct ProfileStore(MemoryStore);

#[async_trait]
impl Store for ProfileStore {
    async fn binding(&self, tenant: &str, jkt: &str) -> StoreResult<Option<Person>> {
        Ok(Some(
            self.0
                .binding(tenant, jkt)
                .await?
                .unwrap_or_else(profile_person),
        ))
    }
    async fn bind(&self, tenant: &str, jkt: &str, person: &Person) -> StoreResult<Person> {
        self.0.bind(tenant, jkt, person).await
    }
    async fn mission(&self, tenant: &str, s256: &str) -> StoreResult<Option<Mission>> {
        self.0.mission(tenant, s256).await
    }
    async fn insert_mission(&self, tenant: &str, mission: &Mission) -> StoreResult<bool> {
        self.0.insert_mission(tenant, mission).await
    }
    async fn log_mission(
        &self,
        tenant: &str,
        s256: &str,
        entry: LogEntry,
        now: i64,
    ) -> StoreResult<bool> {
        self.0.log_mission(tenant, s256, entry, now).await
    }
    async fn end_mission(&self, tenant: &str, s256: &str, at: i64) -> StoreResult<Option<Mission>> {
        self.0.end_mission(tenant, s256, at).await
    }
    async fn spend(
        &self,
        tenant: &str,
        s256: &str,
        amount: u64,
        rule: Spend,
        now: i64,
    ) -> StoreResult<Option<Mission>> {
        self.0.spend(tenant, s256, amount, rule, now).await
    }
    async fn missions(&self, tenant: &str) -> StoreResult<Vec<Mission>> {
        self.0.missions(tenant).await
    }
    async fn approval(&self, tenant: &str, id: &str) -> StoreResult<Option<Approval>> {
        self.0.approval(tenant, id).await
    }
    async fn insert_approval(&self, tenant: &str, approval: &Approval) -> StoreResult<()> {
        self.0.insert_approval(tenant, approval).await
    }
    async fn transition_approval(
        &self,
        tenant: &str,
        expected: ApprovalStatus,
        next: &Approval,
    ) -> StoreResult<bool> {
        self.0.transition_approval(tenant, expected, next).await
    }
    async fn approvals(&self, tenant: &str) -> StoreResult<Vec<Approval>> {
        self.0.approvals(tenant).await
    }
}

fn respond(status: StatusCode, headers: Vec<(String, String)>, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response.body(body).expect("valid response")
}

fn json(status: StatusCode, body: serde_json::Value) -> Response<Vec<u8>> {
    respond(
        status,
        vec![("content-type".into(), "application/json".into())],
        body.to_string().into_bytes(),
    )
}

fn host(issuer: &str) -> &str {
    issuer.strip_prefix("https://").unwrap_or(issuer)
}

fn main() -> Result<(), Failure> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "deployment.json".into());
    let c: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let network = Arc::new(Network(Arc::new(Client::new(&c.ca, c.resolve.clone())?)));
    let identity = IdentityResource {
        issuer: c.identity_resource.clone(),
        keys: Trusted {
            issuers: c.agent_providers.clone(),
            resolver: JwksResolver::new(network.clone()),
        },
    };
    let person = person_server::PersonServer::new(
        person_server::Config::new(
            &c.direct_person_server,
            ProfileDirectory,
            &c.agent_providers,
        )
        .fetch(network)
        .store(Arc::new(ProfileStore(MemoryStore::new()))),
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let names = [c.identity_resource.clone(), c.direct_person_server.clone()];
    eprintln!("aauth-protocol deployment listening on {}", c.listen);
    https::serve(&c.listen, &c.cert, &c.key, move |request| {
        let name = request.uri().host().unwrap_or_default().to_owned();
        match names.iter().position(|issuer| host(issuer) == name) {
            Some(0) => runtime.block_on(identity.handle(&request)),
            Some(1) => runtime
                .block_on(person.handle(request.map(Bytes::from)))
                .map(|body| body.to_vec()),
            _ => respond(StatusCode::NOT_FOUND, Vec::new(), Vec::new()),
        }
    })
}
