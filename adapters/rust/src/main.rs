//! Test transport and fixed host configuration around the unmodified Rust Resource.
use aauth_rust_core::{AgentProviderKeys, VerifiedAgentToken};
use aauth_rust_resource::AgentIdentityResource;
use http::Request;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[derive(Deserialize)]
struct Bootstrap {
    version: u32,
    now: i64,
    issuer: String,
    resource: String,
    ap_transport: String,
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
