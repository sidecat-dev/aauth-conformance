//! Launchers for the supervision roles around unmodified native APIs: the
//! `aauth-rust-supervision-server` crate, and a `PersonServer` with
//! supervision. Host policy, trusted fixture keys, a fixed clock, loopback
//! transport and the host controls the draft leaves to the host are all this
//! file supplies; every protocol answer is the library's.
use super::{Bootstrap, FixturePolicy, PersonKeys, fetch, person_request};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::{Act, Allowance, Answer, Ask, MissionTerms, SupervisionError};
use aauth_rust_core::{AgentKeyResolver, AgentProviderKeys, TokenError, TrustedIssuerKeys};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, Config as PersonConfig, MemoryStore, PersonAnswer, PersonServer, Supervision,
    SupervisionConfig, SupervisionHold, SupervisionUnavailable,
};
use aauth_rust_supervision_server::{
    Case, Config, ConnectAnswer, ConnectRequest, Policy, SupervisionServer, Verdict,
};
use http::{Request, Response};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct TrustedKey {
    issuer: String,
    kid: String,
    jwk: serde_json::Value,
    #[serde(default)]
    accept: bool,
}

#[derive(Deserialize)]
struct SupervisorIdentity {
    issuer: String,
    seed_hex: String,
    kid: String,
}

#[derive(Deserialize)]
struct ServerExtension {
    supervisor: SupervisorIdentity,
    person_servers: Vec<TrustedKey>,
}

#[derive(Deserialize)]
struct PersonExtension {
    supervisor: String,
    supervisor_transport: String,
    supervisor_subject: String,
    supervisor_keys: Vec<TrustedKey>,
    resource: String,
}

fn seed(hex: &str) -> Result<[u8; 32], Failure> {
    if hex.len() != 64 {
        return Err("fixture seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(seed)
}

/// A host trust snapshot built from public fixture keys under `dwk`.
fn trusted(key: &TrustedKey, dwk: &str) -> Result<TrustedIssuerKeys, Failure> {
    let mut jwk = key.jwk.clone();
    jwk.as_object_mut()
        .ok_or("fixture JWK must be an object")?
        .insert("kid".into(), key.kid.clone().into());
    let metadata = serde_json::to_vec(&serde_json::json!({
        "issuer": key.issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", key.issuer),
    }))?;
    let jwks = serde_json::to_vec(&serde_json::json!({ "keys": [jwk] }))?;
    Ok(TrustedIssuerKeys::from_documents(
        &key.issuer,
        dwk,
        &metadata,
        &jwks,
    )?)
}

/// Person Server keys the supervision server admits; any other issuer is
/// untrusted, which the native server answers `unsupported_iss`.
struct AdmittedPersonServers(Vec<(String, TrustedIssuerKeys)>);
impl AgentKeyResolver for AdmittedPersonServers {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        match self.0.iter().find(|(known, _)| known == issuer) {
            Some((_, keys)) => keys.key(issuer, dwk, kid),
            None => Err(TokenError::UntrustedIssuer),
        }
    }
}

/// Fixed host policy: connect the accepted Person Servers and refuse the
/// others; allow token and mission acts and a permission named
/// fixture.allow, deny fixture.deny, ask for fixture.ask and defer
/// fixture.defer until a host control resolves it.
struct FixtureSupervisorPolicy {
    accepted: Vec<String>,
}
impl Policy for FixtureSupervisorPolicy {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        if self.accepted.contains(&request.ps) {
            ConnectAnswer::Connected
        } else {
            ConnectAnswer::Refused
        }
    }
    fn decide(&self, case: &Case) -> Verdict {
        match case.act {
            Act::MissionProposal => {
                let description = case
                    .request
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                Verdict::Allow(Allowance {
                    mission: Some(MissionTerms::described(description)),
                    ..Allowance::default()
                })
            }
            Act::Permission => match case.action() {
                Some("fixture.deny") => Verdict::Deny(Some("Fixture denial.".into())),
                Some("fixture.ask") => Verdict::Ask(Ask {
                    summary: Some("Fixture question for the person.".into()),
                    ..Ask::default()
                }),
                Some("fixture.defer") => Verdict::Defer,
                _ => Verdict::Allow(Allowance::default()),
            },
            _ => Verdict::Allow(Allowance::default()),
        }
    }
}

fn respond(incoming: tiny_http::Request, response: &Response<Vec<u8>>) -> Result<(), Failure> {
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

fn control(status: u16, value: serde_json::Value) -> Response<Vec<u8>> {
    let mut response = Response::new(value.to_string().into_bytes());
    *response.status_mut() = http::StatusCode::from_u16(status).unwrap_or_default();
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
}

fn listen(ready_path: &str) -> Result<tiny_http::Server, Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{ready_path}")})
    );
    std::io::stdout().flush()?;
    Ok(server)
}

fn is_control(incoming: &tiny_http::Request) -> bool {
    incoming.url() == "/__fixture/supervision"
}

fn control_body(incoming: &mut tiny_http::Request) -> Result<serde_json::Value, Failure> {
    let mut body = Vec::new();
    incoming.as_reader().take(16385).read_to_end(&mut body)?;
    if body.len() > 16384 {
        return Err("control body limit".into());
    }
    Ok(serde_json::from_slice(&body)?)
}

/// Launch the native supervision server for `supervision.server`.
pub(crate) fn run_server(config: Bootstrap) -> Result<(), Failure> {
    let extension: ServerExtension = serde_json::from_value(config.extension.clone())?;
    let mut admitted = Vec::new();
    let mut accepted = Vec::new();
    for ps in &extension.person_servers {
        admitted.push((ps.issuer.clone(), trusted(ps, "aauth-person.json")?));
        if ps.accept {
            accepted.push(ps.issuer.clone());
        }
    }
    let now = config.now;
    let server = SupervisionServer::new(
        Config::new(&extension.supervisor.issuer).with_signing(
            &extension.supervisor.kid,
            SigningKey::from_seed(seed(&extension.supervisor.seed_hex)?),
        ),
        AdmittedPersonServers(admitted),
        FixtureSupervisorPolicy {
            accepted: accepted.clone(),
        },
        MemoryContinuations::new(10_000),
        move || now,
    )?;
    let listener = listen("/.well-known/aauth-supervisor.json")?;
    let mut rate_limited = false;
    for mut incoming in listener.incoming_requests() {
        if is_control(&incoming) {
            let answer = match control_body(&mut incoming) {
                Err(error) => control(400, serde_json::json!({"error": error.to_string()})),
                Ok(body) if body["rate_limit"] == true => {
                    rate_limited = true;
                    control(200, serde_json::json!({"rate_limited": true}))
                }
                Ok(body) if body["resolve"]["verdict"] == "allow" => {
                    let sdi = body["resolve"]["sdi"].as_str().unwrap_or_default();
                    let resolved = accepted.iter().try_for_each(|ps| {
                        server.decide_pending(ps, sdi, Verdict::Allow(Allowance::default()))
                    });
                    match resolved {
                        Ok(()) => control(200, serde_json::json!({"resolved": true})),
                        Err(error) => control(409, serde_json::json!({"error": error.to_string()})),
                    }
                }
                Ok(_) => control(400, serde_json::json!({"error": "unknown host control"})),
            };
            respond(incoming, &answer)?;
            continue;
        }
        let request = person_request(&mut incoming)?;
        let path = request.uri().path().to_owned();
        let supervised = path == "/decision" || path == "/event" || path.starts_with("/mission");
        let response = if rate_limited && supervised {
            // The host's own limit, answered with the library's rate_limited
            // response; the server itself never limits a Person Server.
            rate_limited = false;
            SupervisionError::RateLimited.response(Some(30))
        } else {
            server.handle(&request)
        };
        respond(incoming, &response)?;
    }
    Ok(())
}

/// Keys of the supervised Person Server: Agent Provider, Resource and the
/// fixture supervisors under `aauth-supervisor.json`.
struct SupervisedKeys {
    person: PersonKeys,
    supervisors: Vec<(String, TrustedIssuerKeys)>,
}
impl AgentKeyResolver for SupervisedKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if dwk == aauth_rust_core::supervision::SUPERVISOR_DOCUMENT {
            return match self.supervisors.iter().find(|(known, _)| known == issuer) {
                Some((_, keys)) => keys.key(issuer, dwk, kid),
                None => Err(TokenError::UntrustedIssuer),
            };
        }
        self.person.key(issuer, dwk, kid)
    }
}

/// Routes every Agent to the harness supervisor and carries the Person
/// Server's signed requests to its loopback transport unchanged.
struct FixtureSupervision {
    supervisor: String,
    subject: String,
    transport: String,
}
impl Supervision for FixtureSupervision {
    fn route(&self, _: &str, _: &AgentIdentity) -> Option<String> {
        Some(self.supervisor.clone())
    }
    fn subject(&self, _: &str, _: &str) -> String {
        self.subject.clone()
    }
    fn metadata(&self, supervisor: &str) -> Result<Vec<u8>, SupervisionUnavailable> {
        if supervisor != self.supervisor {
            return Err(SupervisionUnavailable);
        }
        fetch(&self.transport, "/.well-known/aauth-supervisor.json")
            .map_err(|_| SupervisionUnavailable)
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, SupervisionUnavailable> {
        let origin = format!(
            "{}://{}",
            request.uri().scheme_str().unwrap_or_default(),
            request
                .uri()
                .authority()
                .map(|a| a.as_str())
                .unwrap_or_default()
        );
        if origin != self.supervisor {
            return Err(SupervisionUnavailable);
        }
        exchange(&self.transport, request).map_err(|_| SupervisionUnavailable)
    }
}

/// One loopback HTTP/1.1 exchange carrying exactly the signed method,
/// target, headers and body; the response must be Content-Length framed.
fn exchange(base: &str, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
    let address: SocketAddr = base
        .strip_prefix("http://")
        .ok_or("expected loopback HTTP")?
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("supervisor transport must be loopback".into());
    }
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let target = request
        .uri()
        .path_and_query()
        .ok_or("missing request path")?;
    write!(socket, "{} {} HTTP/1.1\r\n", request.method(), target)?;
    for (name, value) in request.headers() {
        write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
    }
    if !request.headers().contains_key("host") {
        let authority = request.uri().authority().ok_or("missing authority")?;
        write!(socket, "Host: {authority}\r\n")?;
    }
    if !request.headers().contains_key("content-length") {
        write!(socket, "Content-Length: {}\r\n", request.body().len())?;
    }
    write!(socket, "Connection: close\r\n\r\n")?;
    socket.write_all(request.body())?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("supervisor response exceeds fixture limit".into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let offset = match parsed.parse(&bytes)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err("incomplete supervisor response".into()),
    };
    let mut response = Response::builder().status(parsed.code.ok_or("missing status")?);
    let mut length = None;
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported supervisor response framing".into());
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            length = Some(std::str::from_utf8(header.value)?.parse::<usize>()?);
        }
        response = response.header(header.name, header.value);
    }
    if length.unwrap_or(0) != bytes.len() - offset {
        return Err("supervisor response body length mismatch".into());
    }
    Ok(response.body(bytes[offset..].to_vec())?)
}

/// Launch the native supervised Person Server for `supervision.person-server`.
pub(crate) fn run_person_server(config: Bootstrap) -> Result<(), Failure> {
    let extension: PersonExtension = serde_json::from_value(config.extension.clone())?;
    let ap = AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?;
    let mut resource_jwk = config.resource_jwk.clone();
    resource_jwk
        .as_object_mut()
        .ok_or("Resource JWK must be an object")?
        .insert("kid".into(), config.resource_kid.clone().into());
    let resource = trusted(
        &TrustedKey {
            issuer: extension.resource.clone(),
            kid: config.resource_kid.clone(),
            jwk: resource_jwk,
            accept: true,
        },
        "aauth-resource.json",
    )?;
    let mut supervisors = Vec::new();
    for key in &extension.supervisor_keys {
        supervisors.push((
            key.issuer.clone(),
            trusted(key, aauth_rust_core::supervision::SUPERVISOR_DOCUMENT)?,
        ));
    }
    let mut person_config = PersonConfig::new(
        &config.person_server,
        &config.person_kid,
        SigningKey::from_seed(seed(&config.person_seed_hex)?),
    );
    person_config.person_lifetime = config.person_lifetime;
    let policy = FixturePolicy {
        subject: config.person_subject.clone(),
        scopes: config.permitted_scopes.clone(),
        auth_lifetime: config.auth_lifetime,
    };
    let sequence = AtomicU64::new(0);
    let now = config.now;
    let host = FixtureSupervision {
        supervisor: extension.supervisor.clone(),
        subject: extension.supervisor_subject.clone(),
        transport: extension.supervisor_transport.clone(),
    };
    let sut = PersonServer::new(
        person_config,
        SupervisedKeys {
            person: PersonKeys { ap, resource },
            supervisors,
        },
        MemoryStore::default(),
        policy,
        move || now,
        move || format!("fixture-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1),
    )?
    // Missions are enabled so a supervised Agent can propose one; the
    // supervisor approves it, never the host policy.
    .with_missions()
    .with_supervision(SupervisionConfig::new(
        host,
        MemoryContinuations::new(10_000),
    ))?;
    let listener = listen("/person")?;
    let mut held: Option<String> = None;
    for mut incoming in listener.incoming_requests() {
        if is_control(&incoming) {
            let answer = match control_body(&mut incoming) {
                Err(error) => control(400, serde_json::json!({"error": error.to_string()})),
                Ok(body) if body["deliver"] == true => match sut.deliver_supervision() {
                    Ok(waiting) => control(200, serde_json::json!({"undelivered_pairs": waiting})),
                    Err(error) => control(409, serde_json::json!({"error": error.to_string()})),
                },
                Ok(body) if body["advance"] == true || body["resolve"] == "allow" => {
                    match held.as_deref() {
                        None => control(409, serde_json::json!({"error": "no held act"})),
                        Some(reference) if body["advance"] == true => {
                            match sut.advance_supervision(reference) {
                                Ok(hold) => control(
                                    200,
                                    serde_json::json!({"reference": hold.reference, "sdi": hold.sdi}),
                                ),
                                Err(error) => {
                                    control(409, serde_json::json!({"error": error.to_string()}))
                                }
                            }
                        }
                        // The person answers without a reason, which the draft never requires.
                        Some(reference) => match sut
                            .resolve_supervision(reference, PersonAnswer::once(Answer::Allow))
                        {
                            Ok(()) => control(200, serde_json::json!({"reference": reference})),
                            Err(error) => {
                                control(409, serde_json::json!({"error": error.to_string()}))
                            }
                        },
                    }
                }
                Ok(_) => control(400, serde_json::json!({"error": "unknown host control"})),
            };
            respond(incoming, &answer)?;
            continue;
        }
        let request = person_request(&mut incoming)?;
        let response = sut.handle(&request);
        if let Some(hold) = response.extensions().get::<SupervisionHold>() {
            held = Some(hold.reference.clone());
        }
        respond(incoming, &response)?;
    }
    Ok(())
}
