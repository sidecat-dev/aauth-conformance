//! Test transport and fixed host configuration around unmodified Rust APIs.
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
    #[serde(default)]
    role: String,
    #[serde(default)]
    agent_seed_hex: String,
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
    fn nonempty_signed_output_cannot_become_a_successful_empty_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (done, stopped) = mpsc::channel::<()>();
        let peer = thread::spawn(move || loop {
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
