//! Events roles: the native Resource registration surface, the native Agent
//! Provider inbox and the native Agent event check. Host trust snapshots,
//! fixed clocks and fixture controls only; every subscribe-token, event-token
//! and proof decision belongs to aauth-rust.
use super::{Bootstrap, fetch, person_request};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{EventInbox, MemoryEventStore, SubscribeRequest};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentProviderKeys, Confirmation, PersonToken, TokenError,
    TrustedIssuerKeys,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::events::{
    EventPayload, EventsConfig, EventsResource, MemorySubscriptionStore,
};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct Identity {
    issuer: String,
    seed_hex: String,
    kid: String,
}

#[derive(Deserialize)]
struct Trust {
    issuer: String,
    transport: String,
}

#[derive(Deserialize)]
struct Extension {
    #[serde(default)]
    resource: Option<Identity>,
    #[serde(default)]
    subscription_path: String,
    #[serde(default)]
    ticket_path: String,
    #[serde(default)]
    event_endpoint: String,
    #[serde(default)]
    ap_seed_hex: String,
    #[serde(default)]
    ap_kid: String,
    #[serde(default)]
    trusted_resources: Vec<Trust>,
    #[serde(default)]
    trusted_person_servers: Vec<Trust>,
    #[serde(default)]
    subscription_resource: String,
    #[serde(default)]
    agent_providers: Vec<Trust>,
    agent: String,
}

pub fn run(config: Bootstrap) -> Result<(), Failure> {
    let extension: Extension = serde_json::from_value(config.extension.clone())?;
    match config.role.as_str() {
        "events.subscription" | "events.delivery" => run_subscription(config, extension),
        "events.agent-provider" => run_provider(config, extension),
        "events.agent" => run_agent(config, extension),
        other => Err(format!("unknown Events role {other}").into()),
    }
}

fn seed(hex: &str) -> Result<[u8; 32], Failure> {
    if hex.len() != 64 {
        return Err("signing seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(seed)
}

// Host trust: fixture issuers' published documents, admitted by exact issuer.
struct Trusted(Vec<(String, TrustedIssuerKeys)>);
impl Trusted {
    fn load(trusts: &[Trust], document: &str) -> Result<Self, Failure> {
        let mut keys = Vec::new();
        for trust in trusts {
            keys.push((
                trust.issuer.clone(),
                TrustedIssuerKeys::from_documents(
                    &trust.issuer,
                    document,
                    &fetch(&trust.transport, &format!("/.well-known/{document}"))?,
                    &fetch(&trust.transport, "/.well-known/jwks.json")?,
                )?,
            ));
        }
        Ok(Self(keys))
    }
}
impl AgentKeyResolver for Trusted {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        match self.0.iter().find(|(trusted, _)| trusted == issuer) {
            Some((_, keys)) => keys.key(issuer, dwk, kid),
            None => Err(TokenError::UntrustedIssuer),
        }
    }
}

fn announce(path: &str) -> Result<tiny_http::Server, Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{path}")})
    );
    std::io::stdout().flush()?;
    Ok(server)
}

fn respond(incoming: tiny_http::Request, response: http::Response<Vec<u8>>) -> Result<(), Failure> {
    let mut wire = tiny_http::Response::from_data(response.body().clone())
        .with_status_code(response.status().as_u16());
    for (name, value) in response.headers() {
        wire.add_header(
            tiny_http::Header::from_bytes(name.as_str().as_bytes(), value.as_bytes())
                .map_err(|_| "invalid response header")?,
        );
    }
    incoming.respond(wire)?;
    Ok(())
}

fn reply(status: u16, value: serde_json::Value) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .expect("fixed control response")
}

fn control<T: for<'de> Deserialize<'de>>(request: &http::Request<Vec<u8>>) -> Result<T, Failure> {
    Ok(serde_json::from_slice(request.body())?)
}

/// Native public and protected registration. The ticket control verifies the
/// fixture person token natively and issues the ticket from that verified token.
fn run_subscription(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let identity = extension
        .resource
        .ok_or("events subscription role needs the Resource identity")?;
    let ap = AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?;
    let person_servers = Trusted::load(&extension.trusted_person_servers, "aauth-person.json")?;
    let resource = EventsResource::new(
        EventsConfig {
            issuer: identity.issuer.clone(),
            signed_origin: identity.issuer.clone(),
            kid: identity.kid,
            signing_key: SigningKey::from_seed(seed(&identity.seed_hex)?),
            ticket_path: extension.ticket_path.clone(),
            max_ticket_lifetime: 300,
        },
        ap,
        MemorySubscriptionStore::new(),
    )?;
    let now = config.now;
    let server = announce(&extension.subscription_path)?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let path = request.uri().path().to_owned();
        let response = if path == "/__fixture/ticket" {
            #[derive(Deserialize)]
            struct Job {
                person_token: String,
            }
            let issued = control::<Job>(&request).and_then(|job| {
                let person = PersonToken::parse(&job.person_token)?.verify(&person_servers, now)?;
                Ok(resource.issue_ticket(&person, b"conformance fixture", 120, now)?)
            });
            match issued {
                Ok(ticket) => reply(200, serde_json::json!({"url": ticket.url})),
                Err(error) => reply(422, serde_json::json!({"error": error.to_string()})),
            }
        } else if path == "/__fixture/fire" {
            // Event Delivery: the native Resource prepares and signs one event;
            // the host fetches the AP metadata and sends the request unchanged.
            #[derive(Deserialize)]
            struct Fire {
                agent_provider: String,
                eid: String,
                body: bool,
            }
            let outcome = control::<Fire>(&request).and_then(|job| {
                let payload = job.body.then_some(EventPayload {
                    content_type: "application/json",
                    body: br#"{"event_type":"slot.available"}"#,
                });
                let event = resource.prepare_event(
                    &job.agent_provider,
                    &job.eid,
                    payload,
                    now + 300,
                    now,
                )?;
                let provider = extension
                    .agent_providers
                    .iter()
                    .find(|provider| provider.issuer == job.agent_provider)
                    .ok_or("no fixture transport for this Agent Provider")?;
                let metadata = fetch(&provider.transport, "/.well-known/aauth-agent.json")?;
                let delivery = resource.delivery_request(&event, &metadata, now)?;
                send(&provider.transport, &delivery)
            });
            match outcome {
                Ok(status) => reply(200, serde_json::json!({"status": status})),
                Err(error) => reply(422, serde_json::json!({"error": error.to_string()})),
            }
        } else if path.starts_with(&extension.ticket_path) {
            resource
                .register_with_ticket(&request, now, |_| Ok(Vec::new()))
                .into_response()
        } else if path == extension.subscription_path {
            resource
                .register(&request, now, |_| Ok(Vec::new()))
                .into_response()
        } else {
            reply(404, serde_json::json!({"error":"no such fixture path"}))
        };
        respond(incoming, response)?;
    }
    Ok(())
}

/// Native Agent Provider: metadata, JWKS, the inbox at `event_endpoint`, and
/// a control that calls native subscribe-token issuance for the fixture Agent.
fn run_provider(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let provider = AgentProvider::new(
        &config.issuer,
        &extension.ap_kid,
        SigningKey::from_seed(seed(&extension.ap_seed_hex)?),
    )?
    .with_event_endpoint(&extension.event_endpoint)?;
    let resources = Trusted::load(&extension.trusted_resources, "aauth-resource.json")?;
    let inbox = EventInbox::new(&provider, resources, MemoryEventStore::new())?;
    let now = config.now;
    // The Agent token native issuance requires; its key is the fixture Agent's.
    let agent_token = provider.issue(&AgentClaims {
        iss: config.issuer.clone(),
        dwk: "aauth-agent.json".into(),
        sub: extension.agent.clone(),
        jti: "events-agent-token".into(),
        iat: now - 10,
        exp: now + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(seed(&config.agent_seed_hex)?).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let endpoint: http::Uri = extension.event_endpoint.parse()?;
    let server = announce(endpoint.path())?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let path = request.uri().path().to_owned();
        let response = match (request.method().as_str(), path.as_str()) {
            ("GET", "/.well-known/aauth-agent.json") => http::Response::builder()
                .header("content-type", "application/json")
                .body(provider.metadata()?)?,
            ("GET", "/.well-known/jwks.json") => http::Response::builder()
                .header("content-type", "application/json")
                .body(provider.jwks()?)?,
            ("POST", "/__fixture/subscribe") => {
                #[derive(Deserialize)]
                struct Job {
                    max_uses: u64,
                }
                let issued = control::<Job>(&request).and_then(|job| {
                    Ok(provider.issue_subscribe_token(
                        inbox.store(),
                        &SubscribeRequest {
                            agent_token: &agent_token,
                            resource: &extension.subscription_resource,
                            expires_at: now + 600,
                            max_uses: (job.max_uses > 0).then_some(job.max_uses),
                            subscription_expires_at: None,
                        },
                        now,
                    )?)
                });
                match issued {
                    Ok(issued) => reply(200, serde_json::json!({"token": issued.token})),
                    Err(error) => reply(422, serde_json::json!({"error": error.to_string()})),
                }
            }
            // The AP-to-Agent read path the host transport uses.
            ("POST", "/__fixture/pending") => {
                use aauth_rust_agent_provider::events::EventStore;
                let pending = inbox
                    .store()
                    .pending(&extension.agent)
                    .map_err(|e| e.to_string());
                let listed = pending.and_then(|events| {
                    events
                        .into_iter()
                        .map(|event| {
                            Ok(serde_json::json!({
                                "event_token": event.event_token,
                                "body": String::from_utf8(event.body).map_err(|e| e.to_string())?,
                            }))
                        })
                        .collect::<Result<Vec<_>, String>>()
                });
                match listed {
                    Ok(events) => reply(200, serde_json::json!({"events": events})),
                    Err(error) => reply(422, serde_json::json!({"error": error})),
                }
            }
            _ if path == endpoint.path() => inbox.receive(&request, now).into_response(),
            _ => reply(404, serde_json::json!({"error":"no such fixture path"})),
        };
        respond(incoming, response)?;
    }
    Ok(())
}

/// Hands one AP-delivered event token and body to the native Agent check.
fn run_agent(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let resources = Trusted::load(&extension.trusted_resources, "aauth-resource.json")?;
    let server = announce("/__fixture/event")?;
    for mut incoming in server.incoming_requests() {
        let mut body = Vec::new();
        incoming.as_reader().take(65537).read_to_end(&mut body)?;
        #[derive(Deserialize)]
        struct Job {
            event_token: String,
            body: String,
        }
        let response = match serde_json::from_slice::<Job>(&body) {
            Ok(job) => match aauth_rust_agent::verify_event(
                &job.event_token,
                job.body.as_bytes(),
                &extension.agent,
                &resources,
                config.now,
            ) {
                Ok(_) => reply(200, serde_json::json!({"accepted": true})),
                Err(error) => reply(
                    200,
                    serde_json::json!({"accepted": false, "error": error.to_string()}),
                ),
            },
            Err(error) => reply(400, serde_json::json!({"error": error.to_string()})),
        };
        respond(incoming, response)?;
    }
    Ok(())
}

// Sends an already signed request to a loopback fixture, changing only the
// physical destination. Host, headers and body bytes are written unchanged.
fn send(base: &str, request: &http::Request<Vec<u8>>) -> Result<u16, Failure> {
    let address: SocketAddr = base
        .strip_prefix("http://")
        .ok_or("expected HTTP loopback")?
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("loopback transport required".into());
    }
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let path = request.uri().path_and_query().ok_or("missing path")?;
    let host = request.uri().authority().ok_or("missing authority")?;
    write!(
        socket,
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method(),
        path,
        host,
        request.body().len()
    )?;
    for (name, value) in request.headers() {
        write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
    }
    write!(socket, "\r\n")?;
    socket.write_all(request.body())?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if !response.parse(&bytes)?.is_complete() {
        return Err("incomplete response".into());
    }
    response.code.ok_or("missing response status".into())
}
