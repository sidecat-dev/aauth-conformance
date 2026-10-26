//! Test transport and fixed host configuration around unmodified Rust APIs.
#[cfg(feature = "deferred")]
mod deferred;
#[cfg(feature = "federation")]
mod federation;
use aauth_rust_core::{
    AgentKeyResolver, AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAgentToken,
};
use aauth_rust_person_server::{
    AuthorizationRequest, Config as PersonConfig, Grant, MemoryStore, Person, PersonRequest,
    PersonServer, Policy, PolicyError,
};
use aauth_rust_resource::AgentIdentityResource;
use http::Request;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Deserialize)]
struct AgentProviderTrust {
    issuer: String,
    transport: String,
}

#[derive(Deserialize)]
struct Bootstrap {
    #[serde(default)]
    additional_agent_providers: Vec<AgentProviderTrust>,
    #[serde(default)]
    person_direct: bool,
    #[cfg(feature = "federation")]
    #[serde(default)]
    access_server: String,
    #[cfg(feature = "federation")]
    #[serde(default)]
    access_seed_hex: String,
    #[cfg(feature = "federation")]
    #[serde(default)]
    access_kid: String,
    #[cfg(feature = "federation")]
    #[serde(default)]
    resource_seed_hex: String,
    #[cfg(feature = "federation")]
    #[serde(default)]
    federation_transport: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    agent_seed_hex: String,
    version: u32,
    now: i64,
    issuer: String,
    resource: String,
    ap_transport: String,
    #[serde(default)]
    person_server: String,
    #[serde(default)]
    person_seed_hex: String,
    #[serde(default)]
    person_kid: String,
    #[serde(default)]
    person_subject: String,
    #[serde(default)]
    person_lifetime: i64,
    #[serde(default)]
    auth_lifetime: i64,
    #[serde(default)]
    permitted_scopes: Vec<String>,
    #[serde(default)]
    resource_kid: String,
    #[serde(default)]
    resource_jwk: serde_json::Value,
}

// The harness's bounded fixture AP explicitly sends Content-Length and closes.
// This is not a production discovery client or TLS/egress-admission test.
fn fetch(base: &str, path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let address: SocketAddr = base
        .strip_prefix("http://")
        .ok_or("expected loopback HTTP")?
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("AP fixture must be loopback".into());
    }
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("AP response too large".into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let offset = match response.parse(&bytes)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err("incomplete AP response".into()),
    };
    if response.code != Some(200) {
        return Err("AP response must be 200".into());
    }
    let length = response
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .ok_or("AP fixture needs Content-Length")?
        .value;
    let length: usize = std::str::from_utf8(length)?.parse()?;
    if response
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        || bytes.len() - offset != length
    {
        return Err("invalid AP framing".into());
    }
    Ok(bytes[offset..].to_vec())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: Bootstrap = serde_json::from_reader(std::io::stdin().lock())?;
    if config.version != 1 {
        return Err("bootstrap version must be 1".into());
    }
    if config.role == "authorization.subagent" {
        #[cfg(feature = "subagent")]
        return federation::run(config);
        #[cfg(not(feature = "subagent"))]
        return Err("rebuild this launcher for authorization.subagent".into());
    }
    if config.role == "authorization.deferred" {
        #[cfg(feature = "deferred")]
        return federation::run(config);
        #[cfg(not(feature = "deferred"))]
        return Err("rebuild this launcher for authorization.deferred".into());
    }
    if config.role == "authorization.federated" {
        #[cfg(feature = "federation")]
        return federation::run(config);
        #[cfg(not(feature = "federation"))]
        return Err("rebuild this launcher for authorization.federated".into());
    }
    if config.role == "person-server.direct" {
        return run_person_server(config);
    }
    if config.role == "agent.signing" {
        return run_agent(config);
    }
    let keys = AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?;
    let resource = AgentIdentityResource::new(
        &config.resource,
        keys,
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    let target: http::Uri = config.resource.parse()?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{}",target.path())})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let host = incoming
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str())
            .ok_or("missing Host")?
            .to_owned();
        let mut request = Request::builder()
            .method(incoming.method().as_str())
            .uri(format!("https://{host}{}", incoming.url()));
        for header in incoming.headers() {
            request = request.header(header.field.as_str().as_str(), header.value.as_str());
        }
        let mut body = Vec::new();
        incoming.as_reader().take(1025).read_to_end(&mut body)?;
        if body.len() > 1024 {
            incoming
                .respond(tiny_http::Response::from_string("body limit").with_status_code(413))?;
            continue;
        }
        let request = request.body(body)?;
        let response = match resource.authorize(&request, config.now).into_result() {
            Ok((token, ())) => http::Response::builder()
                .header("content-type", "application/json")
                .body(serde_json::to_vec(
                    &serde_json::json!({"sub":token.claims().sub}),
                )?)?,
            Err(response) => *response,
        };
        let mut wire = tiny_http::Response::from_data(response.body().clone())
            .with_status_code(response.status().as_u16());
        for (name, value) in response.headers() {
            wire.add_header(
                tiny_http::Header::from_bytes(name.as_str().as_bytes(), value.as_bytes())
                    .map_err(|_| "invalid response header")?,
            );
        }
        incoming.respond(wire)?;
    }
    Ok(())
}

// Trusted snapshots are host configuration, never a credential decision made
// by the adapter. The native PS handles all HTTP proof/JWT verification.
struct PersonKeys {
    ap: AgentProviderKeys,
    resource: TrustedIssuerKeys,
}
impl AgentKeyResolver for PersonKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<aauth_rust_jose::Jwk, TokenError> {
        if dwk == "aauth-agent.json" {
            self.ap.key(issuer, dwk, kid)
        } else {
            self.resource.key(issuer, dwk, kid)
        }
    }
}
struct FixturePolicy {
    subject: String,
    scopes: Vec<String>,
    auth_lifetime: i64,
}
impl Policy for FixturePolicy {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "conformance-internal-person".into(),
            subject: self.subject.clone(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        if request
            .scopes
            .iter()
            .any(|scope| !self.scopes.contains(scope))
        {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: self.auth_lifetime,
        })
    }
}

// Preserve actual received Host, method, path, headers and body. Logical HTTPS
// is the only transport reconstruction; configured PS authority is never used
// to replace an incoming authority or repair a proof.
fn person_request(
    incoming: &mut tiny_http::Request,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let host = incoming
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"))
        .map(|header| header.value.as_str())
        .ok_or("missing Host")?;
    let mut request = Request::builder()
        .method(incoming.method().as_str())
        .uri(format!("https://{host}{}", incoming.url()));
    for header in incoming.headers() {
        request = request.header(header.field.as_str().as_str(), header.value.as_str());
    }
    let mut body = Vec::new();
    // One byte above the native limit lets the SUT classify oversize requests.
    incoming
        .as_reader()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut body)?;
    Ok(request.body(body)?)
}

fn run_person_server(config: Bootstrap) -> Result<(), Box<dyn std::error::Error>> {
    if config.person_seed_hex.len() != 64 {
        return Err("Person Server seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&config.person_seed_hex[i * 2..i * 2 + 2], 16)?;
    }
    let ap = AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?;
    let target: http::Uri = config.resource.parse()?;
    let resource_issuer = format!(
        "{}://{}",
        target.scheme_str().ok_or("missing Resource scheme")?,
        target.authority().ok_or("missing Resource authority")?
    );
    let metadata = serde_json::to_vec(&serde_json::json!({
        "issuer":resource_issuer,
        "jwks_uri":format!("{resource_issuer}/.well-known/jwks.json")
    }))?;
    let mut resource_jwk = config.resource_jwk;
    resource_jwk
        .as_object_mut()
        .ok_or("Resource JWK must be an object")?
        .insert("kid".into(), config.resource_kid.into());
    let jwks = serde_json::to_vec(&serde_json::json!({"keys":[resource_jwk]}))?;
    let resource = TrustedIssuerKeys::from_documents(
        &resource_issuer,
        "aauth-resource.json",
        &metadata,
        &jwks,
    )?;
    let mut person_config = PersonConfig::new(
        &config.person_server,
        &config.person_kid,
        aauth_rust_jose::SigningKey::from_seed(seed),
    );
    person_config.person_lifetime = config.person_lifetime;
    let policy = FixturePolicy {
        subject: config.person_subject,
        scopes: config.permitted_scopes,
        auth_lifetime: config.auth_lifetime,
    };
    let sequence = AtomicU64::new(0);
    let now = config.now;
    let sut = PersonServer::new(
        person_config,
        PersonKeys { ap, resource },
        MemoryStore::default(),
        policy,
        move || now,
        move || format!("fixture-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1),
    )?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}/person")})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let response = sut.handle(&request);
        let mut wire = tiny_http::Response::from_data(response.body().clone())
            .with_status_code(response.status().as_u16());
        for (name, value) in response.headers() {
            wire.add_header(
                tiny_http::Header::from_bytes(name.as_str().as_bytes(), value.as_bytes())
                    .map_err(|_| "invalid response header")?,
            );
        }
        incoming.respond(wire)?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct AgentJob {
    method: String,
    url: String,
    headers: std::collections::BTreeMap<String, String>,
    token: String,
    transport: String,
}

fn send_signed(base: &str, request: &Request<Vec<u8>>) -> Result<u16, Box<dyn std::error::Error>> {
    if !request.body().is_empty() {
        return Err("bodyless profile: SUT added a body after signing".into());
    }
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
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n",
        request.method(),
        path,
        host
    )?;
    for (name, value) in request.headers() {
        write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
    }
    write!(socket, "\r\n")?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("peer response too large".into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if !response.parse(&bytes)?.is_complete() {
        return Err("incomplete response".into());
    }
    response.code.ok_or("missing response status".into())
}

fn run_agent(config: Bootstrap) -> Result<(), Box<dyn std::error::Error>> {
    if config.agent_seed_hex.len() != 64 {
        return Err("Agent seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&config.agent_seed_hex[i * 2..i * 2 + 2], 16)?;
    }
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}/control")})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let operation = (|| -> Result<u16, Box<dyn std::error::Error>> {
            let mut body = Vec::new();
            incoming.as_reader().take(16385).read_to_end(&mut body)?;
            if body.len() > 16384 {
                return Err("control body limit".into());
            }
            let job: AgentJob = serde_json::from_slice(&body)?;
            let agent = aauth_rust_agent::Agent::new(
                aauth_rust_jose::SigningKey::from_seed(seed),
                job.token,
            )?;
            let mut builder = Request::builder()
                .method(job.method.as_str())
                .uri(job.url.as_str());
            for (name, value) in job.headers {
                builder = builder.header(name, value);
            }
            let mut request = builder.body(Vec::new())?;
            agent.sign(&mut request, config.now)?;
            send_signed(&job.transport, &request)
        })();
        let (status, body) = match operation {
            Ok(status) => (200, serde_json::json!({"status":status})),
            Err(error) => (422, serde_json::json!({"error":error.to_string()})),
        };
        incoming
            .respond(tiny_http::Response::from_string(body.to_string()).with_status_code(status))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, sync::mpsc, thread};

    #[test]
    fn person_bridge_preserves_received_authority_body_and_proof_fields() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let body = br#"{"resource":"https://resource.conformance.test"}"#;
        let worker = thread::spawn(move || {
            let mut incoming = server.recv().unwrap();
            let request = person_request(&mut incoming).unwrap();
            incoming.respond(tiny_http::Response::empty(200)).unwrap();
            request
        });
        let mut socket = TcpStream::connect(address).unwrap();
        write!(socket, "POST /person HTTP/1.1\r\nHost: foreign.example\r\nSignature-Key: sig=jwt;jwt=\"unchanged\"\r\nSignature-Input: sig=(\"@authority\" \"content-digest\");created=1800000000\r\nSignature: sig=:AQID:\r\nContent-Type: application/json\r\nContent-Digest: sha-256=:AQID:\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        socket.write_all(body).unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        let request = worker.join().unwrap();
        assert_eq!(request.uri().to_string(), "https://foreign.example/person");
        assert_eq!(request.method(), "POST");
        assert_eq!(request.body(), body);
        assert_eq!(
            request.headers()["signature-key"],
            "sig=jwt;jwt=\"unchanged\""
        );
        assert_eq!(
            request.headers()["signature-input"],
            "sig=(\"@authority\" \"content-digest\");created=1800000000"
        );
        assert_eq!(request.headers()["signature"], "sig=:AQID:");
        assert_eq!(request.headers()["content-digest"], "sha-256=:AQID:");
    }

    #[test]
    fn nonempty_signed_output_cannot_become_a_successful_empty_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (done, stopped) = mpsc::channel::<()>();
        let peer = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut received = Vec::new();
                        let mut byte = [0u8; 1];
                        while !received.ends_with(b"\r\n\r\n") {
                            if socket.read(&mut byte).unwrap() == 0 {
                                break;
                            }
                            received.push(byte[0]);
                        }
                        socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                        return received;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.try_recv() == Err(mpsc::TryRecvError::Disconnected) {
                            return Vec::new();
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("peer accept: {error}"),
                }
            }
        });
        let request = Request::builder()
            .method("POST")
            .uri("https://resource.conformance.test/operations/run")
            .body(b"unexpected-signer-body".to_vec())
            .unwrap();
        let result = send_signed(&base, &request);
        drop(done);
        let received = peer.join().unwrap();
        assert!(
            result.is_err(),
            "nonempty SUT output became a successful empty-body request: {received:?}"
        );
        assert!(
            received.is_empty(),
            "bodyless profile must reject before transport"
        );
    }
}
