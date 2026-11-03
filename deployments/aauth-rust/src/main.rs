//! aauth-rust-deployment serves aauth-rust's native Resource, Person Servers
//! and Access Server over HTTPS, as a deployment the conformance suite's
//! remote mode can test. Each role has its own name and a key generated at
//! start; it discovers every other party's keys over HTTPS from the parties it
//! trusts. Policy follows the suite's test profile: one directed person, the
//! read scope only, 60-second Person and 180-second Auth tokens.
mod events;
mod https;
mod r3;
mod sigkey;
mod supervised_person;
mod supervision;

use aauth_rust_access_server::{
    AccessServer, AuthorizationRequest as AccessRequest, Config as AccessConfig, Decision,
    PolicyError as AccessPolicyError,
};
use aauth_rust_core::{
    AgentKeyResolver, TokenError, TrustedIssuerKeys, VerifiedAgentToken, VerifiedAuthToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config as PersonConfig, Federation, FederationError, Grant,
    MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError,
};
use aauth_rust_resource::{AgentIdentityResource, PsAuthorizationConfig, PsAuthorizationResource};
use http::{Request, Response};
use https::{Client, Failure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

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
    federated_resource: String,
    federated_person_server: String,
    access_server: String,
    agent_providers: Vec<String>,
    person_servers: Vec<String>,
    resources: Vec<String>,
    /// Names of the further roles the other modules serve, by the key each
    /// module documents; "control" is the host-control origin.
    #[serde(default)]
    names: BTreeMap<String, String>,
    /// Further suite parties whose keys the resolver admits.
    #[serde(default)]
    trusted: Vec<String>,
}

/// What every role module shares.
struct Env<'a> {
    c: &'a Config,
    keys: Discovery,
    client: Arc<Client>,
}

type Handler = Box<dyn Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;

/// One route a role module serves: requests to `host` whose path starts
/// with `prefix`. The longest matching prefix wins.
struct Route {
    host: String,
    prefix: String,
    handler: Handler,
}

impl Route {
    fn new(
        issuer: &str,
        prefix: &str,
        handler: impl Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Route {
            host: host(issuer).trim_end_matches('/').to_owned(),
            prefix: prefix.to_owned(),
            handler: Box::new(handler),
        }
    }
}

const SUBJECT: &str = "directed-person-1";
const PERSON_LIFETIME: i64 = 60;
const AUTH_LIFETIME: i64 = 180;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

fn ids(prefix: &'static str) -> impl Fn() -> String + Send + Sync {
    let counter = AtomicU64::new(0);
    move || {
        format!(
            "rust-{prefix}-{}-{}",
            now(),
            counter.fetch_add(1, Ordering::Relaxed) + 1
        )
    }
}

/// Discovers a trusted party's keys over HTTPS on first use and keeps them;
/// an unknown kid fetches that party's documents again.
#[derive(Clone)]
struct Discovery {
    trusted: Arc<Vec<String>>,
    client: Arc<Client>,
    cache: Arc<Mutex<BTreeMap<(String, String), TrustedIssuerKeys>>>,
}

impl AgentKeyResolver for Discovery {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if !self.trusted.iter().any(|trusted| trusted == issuer) {
            return Err(TokenError::UntrustedIssuer);
        }
        let entry = (issuer.to_owned(), dwk.to_owned());
        let cached = self.cache.lock().map_err(|_| TokenError::InvalidKey)?.get(&entry).map(|keys| keys.key(issuer, dwk, kid));
        if let Some(Ok(key)) = cached {
            return Ok(key);
        }
        // The lock is not held across the fetch: a peer may be this process.
        let keys = self.fetch(issuer, dwk).map_err(|error| {
            eprintln!("discovering {issuer} {dwk}: {error}");
            TokenError::InvalidKey
        })?;
        let key = keys.key(issuer, dwk, kid);
        self.cache.lock().map_err(|_| TokenError::InvalidKey)?.insert(entry, keys);
        key
    }
}

impl Discovery {
    fn fetch(&self, issuer: &str, dwk: &str) -> Result<TrustedIssuerKeys, Failure> {
        let metadata = self.client.get(&format!("{issuer}/.well-known/{dwk}"))?;
        let jwks = self.client.get(&metadata_jwks_uri(issuer, &metadata)?)?;
        Ok(TrustedIssuerKeys::from_documents(
            issuer, dwk, &metadata, &jwks,
        )?)
    }
}

fn read_only(scopes: &[String]) -> bool {
    scopes.iter().all(|scope| scope == "read")
}

struct ProfilePolicy;
impl Policy for ProfilePolicy {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "profile-person".into(),
            subject: SUBJECT.into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        if !read_only(&request.scopes) {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: AUTH_LIFETIME,
        })
    }
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// The federated Person Server's route to this deployment's Access Server.
struct ToAccessServer {
    issuer: String,
    client: Arc<Client>,
}
impl Federation for ToAccessServer {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        if issuer != self.issuer {
            return Err(FederationError);
        }
        Ok(format!("{issuer}/token"))
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        self.client.send(request).map_err(|error| {
            eprintln!("federation: {error}");
            FederationError
        })
    }
}

fn json(status: u16, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body)
        .expect("static response")
}

fn host(issuer: &str) -> &str {
    issuer.strip_prefix("https://").unwrap_or(issuer)
}

fn main() -> Result<(), Failure> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "deployment.json".into());
    let c: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let client = Arc::new(Client::new(&c.ca, c.resolve.clone())?);
    let mut people = c.person_servers.clone();
    people.push(c.federated_person_server.clone());
    let mut trusted = c.agent_providers.clone();
    trusted.extend(people.iter().cloned());
    trusted.extend(c.resources.iter().cloned());
    trusted.extend(c.trusted.iter().cloned());
    trusted.extend(c.names.values().map(|name| name.trim_end_matches('/').to_owned()));
    trusted.extend([
        c.direct_person_server.clone(),
        c.federated_resource.clone(),
        c.access_server.clone(),
    ]);
    let keys = Discovery {
        trusted: Arc::new(trusted),
        client: client.clone(),
        cache: Arc::default(),
    };
    let env = Env {
        c: &c,
        keys: keys.clone(),
        client: client.clone(),
    };
    let mut routes = Vec::new();
    routes.extend(events::routes(&env)?);
    routes.extend(supervision::routes(&env)?);
    routes.extend(supervised_person::routes(&env)?);
    routes.extend(r3::routes(&env)?);
    routes.extend(sigkey::routes(&env)?);

    let identity = AgentIdentityResource::new(
        &format!("{}/whoami", c.identity_resource),
        keys.clone(),
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )?;
    // metadata() is the public document. It names no jwks_uri. /whoami stays signed.
    let identity_metadata = identity.metadata()?;
    let mut direct_config =
        PersonConfig::new(&c.direct_person_server, "rust-direct-ps", SigningKey::generate());
    direct_config.person_lifetime = PERSON_LIFETIME;
    let direct = PersonServer::new(
        direct_config,
        keys.clone(),
        MemoryStore::default(),
        ProfilePolicy,
        now,
        ids("direct"),
    )?;
    let mut federated_config = PersonConfig::new(
        &c.federated_person_server,
        "rust-federated-ps",
        SigningKey::generate(),
    );
    federated_config.person_lifetime = PERSON_LIFETIME;
    let federated_person = PersonServer::new(
        federated_config,
        keys.clone(),
        MemoryStore::default(),
        ProfilePolicy,
        now,
        ids("federated"),
    )?
    .with_federation(ToAccessServer {
        issuer: c.access_server.clone(),
        client,
    });
    let admitted = people.clone();
    let access = AccessServer::new(
        AccessConfig::new(&c.access_server, "rust-as", SigningKey::generate()),
        keys.clone(),
        move |request: &AccessRequest| {
            if !admitted.contains(&request.person_server) || !read_only(&request.scopes) {
                return Err(AccessPolicyError::Denied);
            }
            Ok(Decision {
                scopes: request.scopes.clone(),
                lifetime: AUTH_LIFETIME,
            })
        },
        now,
        ids("access"),
    )?;
    let resource = PsAuthorizationResource::new_federated(
        PsAuthorizationConfig {
            issuer: c.federated_resource.clone(),
            signed_origin: c.federated_resource.clone(),
            kid: "rust-resource".into(),
            signing_key: SigningKey::generate(),
            scopes: vec!["read".into()],
            scope_descriptions: [("read".into(), "Read the caller's identity".into())].into(),
        },
        &c.access_server,
        keys,
        move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            token.claims().sub == SUBJECT && people.contains(&token.claims().ps)
        },
    )?;
    let challenge_id = ids("challenge");
    let names = [
        c.identity_resource.clone(),
        c.direct_person_server.clone(),
        c.federated_person_server.clone(),
        c.access_server.clone(),
        c.federated_resource.clone(),
    ];
    eprintln!("aauth-rust deployment listening on {}", c.listen);
    https::serve(&c.listen, &c.cert, &c.key, move |request| {
        let name = request.uri().host().unwrap_or_default();
        let echo = |sub: &str| json(200, serde_json::json!({ "sub": sub }).to_string().into_bytes());
        match names.iter().position(|issuer| host(issuer) == name) {
            Some(0) => match request.uri().path() {
                "/.well-known/aauth-resource.json" => json(200, identity_metadata.clone()),
                _ => match identity.authorize(&request, now()).into_result() {
                    Ok((token, ())) => echo(&token.claims().sub),
                    Err(response) => *response,
                },
            },
            Some(1) => direct.handle(&request),
            Some(2) => federated_person.handle(&request),
            Some(3) => access.handle(&request),
            Some(4) => match request.uri().path() {
                "/.well-known/aauth-resource.json" => match resource.metadata() {
                    Ok(body) => json(200, body),
                    Err(_) => json(500, Vec::new()),
                },
                "/.well-known/jwks.json" => match resource.jwks() {
                    Ok(body) => json(200, body),
                    Err(_) => json(500, Vec::new()),
                },
                _ => match resource
                    .authorize(&request, now(), &challenge_id())
                    .into_result()
                {
                    Ok((token, ())) => echo(&token.claims().sub),
                    Err(response) => *response,
                },
            },
            _ => routes
                .iter()
                .filter(|route| route.host == name && request.uri().path().starts_with(&route.prefix))
                .max_by_key(|route| route.prefix.len())
                .map_or_else(|| json(404, Vec::new()), |route| (route.handler)(request)),
        }
    })
}
