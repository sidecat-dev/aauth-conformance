//! Blocking HTTPS for this deployment: a thread-per-connection server and a
//! client that connects each host:port name to a configured address.
use http::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

pub type Failure = Box<dyn std::error::Error + Send + Sync>;

/// Largest request or response this deployment reads.
const LIMIT: usize = 1024 * 1024 + 65536;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Serve `handler` over TLS on `listen`, one thread per connection.
pub fn serve<H>(listen: &str, cert: &str, key: &str, handler: H) -> Result<(), Failure>
where
    H: Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync + 'static,
{
    let chain = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, PrivateKeyDer::from_pem_file(key)?)?,
    );
    let handler = Arc::new(handler);
    for socket in TcpListener::bind(listen)?.incoming() {
        let (socket, config, handler) = (socket?, config.clone(), handler.clone());
        std::thread::spawn(move || {
            if let Err(error) = connection(socket, config, &*handler) {
                eprintln!("connection: {error}");
            }
        });
    }
    Ok(())
}

fn connection<H>(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    handler: &H,
) -> Result<(), Failure>
where
    H: Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
{
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, socket);
    let (head, rest) = read_head(&mut stream)?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed.parse(&head)?;
    let mut request = Request::builder().method(parsed.method.ok_or("no method")?);
    let mut host = None;
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            host = Some(std::str::from_utf8(header.value)?.to_owned());
        }
        request = request.header(header.name, header.value);
    }
    let host = host.ok_or("no Host")?;
    let body = read_body(&mut stream, rest, content_length(parsed.headers)?.unwrap_or(0))?;
    let request = request
        .uri(format!("https://{host}{}", parsed.path.ok_or("no path")?))
        .body(body)?;
    let response = handler(request);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    )?;
    write_message(&mut stream, response.headers(), response.body())?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(())
}

/// An HTTPS client that trusts one CA file and connects each host:port to
/// its address in `resolve`, like curl --resolve. Other names are refused.
pub struct Client {
    config: Arc<rustls::ClientConfig>,
    resolve: BTreeMap<String, String>,
}

impl Client {
    pub fn new(ca: &str, resolve: BTreeMap<String, String>) -> Result<Self, Failure> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(ca)? {
            roots.add(certificate?)?;
        }
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
            resolve,
        })
    }

    /// GET a document; anything but 200 is an error.
    pub fn get(&self, url: &str) -> Result<Vec<u8>, Failure> {
        let response = self.send(&Request::builder().uri(url).body(Vec::new())?)?;
        if response.status() != 200 {
            return Err(format!("GET {url}: HTTP {}", response.status()).into());
        }
        Ok(response.into_body())
    }

    /// Send these exact bytes and return the response, without redirects.
    pub fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
        let uri = request.uri();
        let host = uri.host().ok_or("no host")?;
        if uri.scheme_str() != Some("https") {
            return Err("HTTPS only".into());
        }
        let name = format!("{host}:{}", uri.port_u16().unwrap_or(443));
        let address: SocketAddr = self
            .resolve
            .get(&name)
            .ok_or_else(|| format!("no route to {name}"))?
            .parse()?;
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let tls = rustls::ClientConnection::new(
            self.config.clone(),
            ServerName::try_from(host.to_owned())?,
        )?;
        let mut stream = rustls::StreamOwned::new(tls, socket);
        let target = uri.path_and_query().map_or("/", |p| p.as_str());
        write!(stream, "{} {target} HTTP/1.1\r\n", request.method())?;
        if !request.headers().contains_key(http::header::HOST) {
            write!(stream, "Host: {}\r\n", uri.authority().ok_or("no authority")?)?;
        }
        write_message(&mut stream, request.headers(), request.body())?;
        let (head, rest) = read_head(&mut stream)?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        parsed.parse(&head)?;
        let mut response = Response::builder().status(parsed.code.ok_or("no status")?);
        for header in parsed.headers.iter() {
            response = response.header(header.name, header.value);
        }
        let body = match content_length(parsed.headers)? {
            Some(length) => read_body(&mut stream, rest, length)?,
            None => read_to_close(&mut stream, rest)?,
        };
        Ok(response.body(body)?)
    }
}

/// Write headers with this body's own framing, then the body.
fn write_message(
    stream: &mut impl Write,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Result<(), Failure> {
    for (name, value) in headers {
        if !matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            stream.write_all(name.as_str().as_bytes())?;
            stream.write_all(b": ")?;
            stream.write_all(value.as_bytes())?;
            stream.write_all(b"\r\n")?;
        }
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// Read up to the blank line; return the head and any bytes read past it.
fn read_head(stream: &mut impl Read) -> Result<(Vec<u8>, Vec<u8>), Failure> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buffer.split_off(end + 4);
            return Ok((buffer, rest));
        }
        if buffer.len() > 65536 {
            return Err("header section too large".into());
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err("connection closed before the header section ended".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

fn content_length(headers: &[httparse::Header]) -> Result<Option<usize>, Failure> {
    if headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err("chunked messages are not supported".into());
    }
    match headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        Some(header) => Ok(Some(std::str::from_utf8(header.value)?.trim().parse()?)),
        None => Ok(None),
    }
}

fn read_body(stream: &mut impl Read, mut body: Vec<u8>, length: usize) -> Result<Vec<u8>, Failure> {
    if length > LIMIT || body.len() > length {
        return Err("message body exceeds its framing or this deployment's limit".into());
    }
    let start = body.len();
    body.resize(length, 0);
    stream.read_exact(&mut body[start..])?;
    Ok(body)
}

/// Read an unframed response body until the peer closes the connection.
fn read_to_close(stream: &mut impl Read, mut body: Vec<u8>) -> Result<Vec<u8>, Failure> {
    match stream.take(LIMIT as u64).read_to_end(&mut body) {
        // A peer may close without TLS close_notify after the whole body.
        Err(error) if error.kind() != std::io::ErrorKind::UnexpectedEof => Err(error.into()),
        _ => Ok(body),
    }
}
