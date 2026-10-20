//! Fixed trust/policy and loopback transport around the native PS, AS and Resource.
//! No token or HTTP proof is parsed, accepted or minted by this adapter.
use super::{Bootstrap, FixturePolicy, fetch, person_request};
use aauth_rust_access_server::{
    AccessServer, AuthorizationRequest as AccessRequest, Config as AccessConfig, Decision,
    PolicyError as AccessPolicyError,
};
use aauth_rust_core::{
    AgentKeyResolver, AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config as PersonConfig, Federation, FederationError, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use http::{Request, Response};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

type Failure = Box<dyn std::error::Error>;

#[derive(Clone)]
struct Keys {
    ap: AgentProviderKeys,
    roles: Vec<(String, String, TrustedIssuerKeys)>,
}
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if dwk == "aauth-agent.json" {
            return self.ap.key(issuer, dwk, kid);
        }
        self.roles
            .iter()
            .find(|(id, role, _)| id == issuer && role == dwk)
            .ok_or(TokenError::UntrustedIssuer)?
            .2
            .key(issuer, dwk, kid)
    }
}

struct ConsentPolicy(FixturePolicy);
impl Policy for ConsentPolicy {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.bind_person(request)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.0.authorize(request)
    }
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}

struct Transport {
    issuer: String,
    physical: String,
}
impl Federation for Transport {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        if issuer != self.issuer {
            return Err(FederationError);
        }
        Ok(format!("{issuer}/token"))
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        if request.uri().to_string() != format!("{}/token", self.issuer) {
            return Err(FederationError);
        }
        send(&self.physical, request).map_err(|_| FederationError)
    }
}

fn signing_key(hex: &str) -> Result<SigningKey, Failure> {
    if !hex.is_ascii() || hex.len() != 64 {
        return Err("fixture seed must be 32-byte hex".into());
    }
    let mut seed = [0; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)?;
    }
    Ok(SigningKey::from_seed(seed))
}

fn trusted(
    issuer: &str,
    role: &str,
    kid: &str,
    key: &SigningKey,
) -> Result<(String, String, TrustedIssuerKeys), Failure> {
    let metadata = serde_json::to_vec(&serde_json::json!({
        "issuer":issuer, "jwks_uri":format!("{issuer}/.well-known/jwks.json")
    }))?;
    let mut jwk = serde_json::to_value(key.public_jwk())?;
    jwk["kid"] = serde_json::json!(kid);
    let jwks = serde_json::to_vec(&serde_json::json!({"keys":[jwk]}))?;
    Ok((
        issuer.into(),
        role.into(),
        TrustedIssuerKeys::from_documents(issuer, role, &metadata, &jwks)?,
    ))
}

fn ids(prefix: &'static str) -> impl Fn() -> String + Send + Sync {
    let counter = AtomicU64::new(0);
    move || format!("{prefix}-{}", counter.fetch_add(1, Ordering::Relaxed) + 1)
}

pub(super) fn run(config: Bootstrap) -> Result<(), Failure> {
    let target: http::Uri = config.resource.parse()?;
    let resource_issuer = format!(
        "https://{}",
        target.authority().ok_or("missing Resource authority")?
    );
    let ps_key = signing_key(&config.person_seed_hex)?;
    let as_key = signing_key(&config.access_seed_hex)?;
    let resource_key = signing_key(&config.resource_seed_hex)?;
    let keys = Keys {
        ap: AgentProviderKeys::from_documents(
            &config.issuer,
            &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
            &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
        )?,
        roles: vec![
            trusted(
                &config.person_server,
                "aauth-person.json",
                &config.person_kid,
                &ps_key,
            )?,
            trusted(
                &config.access_server,
                "aauth-access.json",
                &config.access_kid,
                &as_key,
            )?,
            trusted(
                &resource_issuer,
                "aauth-resource.json",
                &config.resource_kid,
                &resource_key,
            )?,
        ],
    };
    let mut ps_config = PersonConfig::new(&config.person_server, &config.person_kid, ps_key);
    ps_config.person_lifetime = config.person_lifetime;
    let now = config.now;
    let ps = PersonServer::new(
        ps_config,
        keys.clone(),
        MemoryStore::default(),
        ConsentPolicy(FixturePolicy {
            subject: config.person_subject.clone(),
            scopes: config.permitted_scopes.clone(),
            auth_lifetime: config.auth_lifetime,
        }),
        move || now,
        ids("person"),
    )?
    .with_federation(Transport {
        issuer: config.access_server.clone(),
        physical: config.federation_transport,
    });
    let permitted_ps = config.person_server.clone();
    let permitted_scopes = config.permitted_scopes.clone();
    let lifetime = config.auth_lifetime;
    let access = AccessServer::new(
        AccessConfig::new(&config.access_server, &config.access_kid, as_key),
        keys.clone(),
        move |request: &AccessRequest| {
            if request.person_server != permitted_ps
                || request
                    .scopes
                    .iter()
                    .any(|scope| !permitted_scopes.contains(scope))
            {
                return Err(AccessPolicyError::Denied);
            }
            Ok(Decision {
                scopes: request.scopes.clone(),
                lifetime,
            })
        },
        move || now,
        ids("access"),
    )?;
    let subject = config.person_subject;
    let person_server = config.person_server.clone();
    let resource = PsAuthorizationResource::new_federated(
        PsAuthorizationConfig {
            issuer: resource_issuer.clone(),
            signed_origin: resource_issuer,
            kid: config.resource_kid,
            signing_key: resource_key,
            scopes: config.permitted_scopes,
        },
        &config.access_server,
        keys,
        move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            token.claims().sub == subject && token.claims().ps == person_server
        },
    )?;
    let ps = Arc::new(ps);
    let access = Arc::new(access);
    let resource = Arc::new(resource);
    let resource_path = Arc::new(target.path().to_owned());
    let ps_authority = Arc::new(
        config
            .person_server
            .parse::<http::Uri>()?
            .authority()
            .ok_or("PS authority")?
            .to_string(),
    );
    let as_authority = Arc::new(
        config
            .access_server
            .parse::<http::Uri>()?
            .authority()
            .ok_or("AS authority")?
            .to_string(),
    );
    let resource_authority = Arc::new(target.authority().ok_or("Resource authority")?.to_string());
    let next_id = Arc::new(ids("resource"));
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{}",target.path())})
    );
    std::io::stdout().flush()?;
    // A PS request waits for a second request to this listener at the AS host.
    // Separate workers preserve that native synchronous exchange without a mock.
    for mut incoming in server.incoming_requests() {
        let (ps, access, resource) = (ps.clone(), access.clone(), resource.clone());
        let (ps_host, as_host, resource_host) = (
            ps_authority.clone(),
            as_authority.clone(),
            resource_authority.clone(),
        );
        let (path, next_id) = (resource_path.clone(), next_id.clone());
        std::thread::spawn(move || {
            let result = (|| -> Result<(), Failure> {
                let request = person_request(&mut incoming)?;
                let host = request
                    .uri()
                    .authority()
                    .ok_or("missing actual Host")?
                    .as_str();
                let response = if host == ps_host.as_str() {
                    ps.handle(&request)
                } else if host == as_host.as_str() {
                    access.handle(&request)
                } else if host == resource_host.as_str() && request.uri().path() == path.as_str() {
                    match resource.authorize(&request, now, &next_id()).into_result() {
                        Ok((token, ())) => Response::builder()
                            .header("content-type", "application/json")
                            .body(serde_json::to_vec(
                                &serde_json::json!({"sub":token.claims().sub}),
                            )?)?,
                        Err(response) => *response,
                    }
                } else {
                    Response::builder().status(404).body(Vec::new())?
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
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("adapter transport failed: {error}");
            }
        });
    }
    Ok(())
}

// The relay is local test infrastructure. Preserve the logical target and signed
// bytes while changing only the socket destination; no TLS/discovery claim.
fn send(base: &str, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
    let address: SocketAddr = base
        .strip_prefix("http://")
        .ok_or("expected loopback HTTP")?
        .parse()?;
    if !address.ip().is_loopback() || request.headers().contains_key("transfer-encoding") {
        return Err("unsupported fixture transport".into());
    }
    if let Some(length) = request.headers().get("content-length")
        && length.to_str()?.parse::<usize>()? != request.body().len()
    {
        return Err("native request body length mismatch".into());
    }
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        socket,
        "{} {} HTTP/1.1\r\n",
        request.method(),
        request
            .uri()
            .path_and_query()
            .ok_or("missing request path")?
    )?;
    for (name, value) in request.headers() {
        write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
    }
    if !request.headers().contains_key("host") {
        write!(
            socket,
            "Host: {}\r\n",
            request
                .uri()
                .authority()
                .ok_or("missing request authority")?
        )?;
    }
    if !request.headers().contains_key("content-length") {
        write!(socket, "Content-Length: {}\r\n", request.body().len())?;
    }
    if !request.headers().contains_key("connection") {
        write!(socket, "Connection: close\r\n")?;
    }
    socket.write_all(b"\r\n")?;
    socket.write_all(request.body())?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("AS response exceeds fixture limit".into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let offset = match parsed.parse(&bytes)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err("incomplete AS response".into()),
    };
    let mut response = Response::builder().status(parsed.code.ok_or("missing AS status")?);
    let mut length = None;
    for header in parsed.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported AS response framing".into());
        }
        if header.name.eq_ignore_ascii_case("content-length")
            && length
                .replace(std::str::from_utf8(header.value)?.parse::<usize>()?)
                .is_some()
        {
            return Err("duplicate AS response length".into());
        }
        response = response.header(header.name, header.value);
    }
    if length != Some(bytes.len() - offset) {
        return Err("AS response body length mismatch".into());
    }
    Ok(response.body(bytes[offset..].to_vec())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn transport_preserves_signed_host_headers_body_and_refusal_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let body = br#"{"presented_token":"exact.token.bytes"}"#.to_vec();
        let body_len = body.len();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "no transport connection");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut captured = Vec::new();
            let mut byte = [0; 1];
            while !captured.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                captured.push(byte[0]);
            }
            let mut received_body = vec![0; body_len];
            socket.read_exact(&mut received_body).unwrap();
            captured.extend_from_slice(&received_body);
            let response = br#"{"error":"invalid_resource_token"}"#;
            write!(
                socket,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            ).unwrap();
            socket.write_all(response).unwrap();
            captured
        });
        let request = Request::builder()
            .method("POST")
            .uri("https://access.conformance.test/token")
            .header("host", "explicit-signed.conformance.test")
            .header("signature-key", "sig=jwks_uri")
            .header("content-type", "application/json")
            .header("content-digest", "sha-256=:AQID:")
            .body(body.clone())
            .unwrap();
        let response = send(&address, &request).expect("bounded response");
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
        assert_eq!(response.body(), br#"{"error":"invalid_resource_token"}"#);
        let bytes = worker.join().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(text.contains("host: explicit-signed.conformance.test\r\n"));
        assert!(text.contains("content-digest: sha-256=:AQID:\r\n"));
        assert!(text.contains("signature-key: sig=jwks_uri\r\n"));
        assert!(text.ends_with(std::str::from_utf8(&body).unwrap()));
    }
}
