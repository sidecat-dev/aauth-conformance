//! Signature-Key roles: a native Resource that also accepts the schemes AAuth
//! does not use, and the native request signer. The crate never fetches; as
//! its documentation requires, this host fetches the fixture documents the
//! verified member names and passes their bytes. Parsing, issuer checks, key
//! selection, algorithm determination and every proof decision are
//! aauth-rust's.
use super::{Bootstrap, fetch, person_request};
use aauth_rust_core::{
    AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAgentToken, metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::{AgentIdentityResource, Decision, SignatureFailure};
use aauth_rust_signature_key::{Error as ProofError, KeyMaterial, PreparedRequest, sign_request};
use http::{Request, Response};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct Extension {
    #[serde(default)]
    verifier: String,
    agent_provider: String,
    signer: String,
    signer_dwk: String,
    jwks_url: String,
    self_jwt_typ: String,
    #[serde(default)]
    documents: BTreeMap<String, String>,
}

/// Discovery bytes the host fetched once from the fixture transports.
struct Documents {
    ap_metadata: Vec<u8>,
    ap_jwks: Vec<u8>,
    signer_metadata: Vec<u8>,
    signer_jwks: Vec<u8>,
    direct_jwks: Vec<u8>,
}

/// Fetch one logical HTTPS URL from the loopback transport serving its origin.
fn fetch_logical(documents: &BTreeMap<String, String>, target: &str) -> Result<Vec<u8>, Failure> {
    let uri: http::Uri = target.parse()?;
    let origin = format!("https://{}", uri.authority().ok_or("URL without authority")?);
    let transport = documents.get(&origin).ok_or("no fixture transport for origin")?;
    fetch(transport, uri.path())
}

fn discover(ext: &Extension) -> Result<Documents, Failure> {
    let ap_metadata = fetch_logical(
        &ext.documents,
        &format!("{}/.well-known/aauth-agent.json", ext.agent_provider),
    )?;
    let signer_metadata = fetch_logical(
        &ext.documents,
        &format!("{}/.well-known/{}", ext.signer, ext.signer_dwk),
    )?;
    // The documents' own jwks_uri, as the crate validates it, names the key sets.
    let ap_jwks = fetch_logical(
        &ext.documents,
        &metadata_jwks_uri(&ext.agent_provider, &ap_metadata)?,
    )?;
    let signer_jwks = fetch_logical(
        &ext.documents,
        &metadata_jwks_uri(&ext.signer, &signer_metadata)?,
    )?;
    let direct_jwks = fetch_logical(&ext.documents, &ext.jwks_url)?;
    Ok(Documents {
        ap_metadata,
        ap_jwks,
        signer_metadata,
        signer_jwks,
        direct_jwks,
    })
}

fn json_response(value: serde_json::Value) -> Response<Vec<u8>> {
    Response::builder()
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .unwrap()
}

fn refuse(failure: SignatureFailure) -> Response<Vec<u8>> {
    Decision::<()>::SignatureFailure(failure).into_response()
}

/// Verify one request under the Resource's AAuth jwt path or, for a further
/// scheme, the crate method the prepared member calls for.
fn verify(
    ext: &Extension,
    documents: &Documents,
    request: &Request<Vec<u8>>,
    now: i64,
) -> Result<Response<Vec<u8>>, Failure> {
    let keys = match AgentProviderKeys::from_documents(
        &ext.agent_provider,
        &documents.ap_metadata,
        &documents.ap_jwks,
    ) {
        Ok(keys) => keys,
        Err(error) => return Ok(refuse(SignatureFailure::Token(error))),
    };
    let resource = AgentIdentityResource::new(
        &ext.verifier,
        keys,
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )?
    .with_further_schemes(&["hwk", "jkt-jwt", "self-jwt", "jwks", "jwks_uri"])?;
    Ok(match resource.authorize(request, now) {
        Decision::Granted(authorized) => {
            json_response(serde_json::json!({"scheme":"jwt","sub":authorized.claims().sub}))
        }
        Decision::OtherScheme(prepared) => match further(ext, documents, &prepared, now) {
            Ok((scheme, signer, alg)) => {
                json_response(serde_json::json!({"scheme":scheme,"signer":signer,"alg":alg}))
            }
            Err(failure) => refuse(failure),
        },
        other => other.into_response(),
    })
}

fn further(
    ext: &Extension,
    documents: &Documents,
    prepared: &PreparedRequest,
    now: i64,
) -> Result<(&'static str, String, String), SignatureFailure> {
    let proof = SignatureFailure::Proof;
    match prepared.key() {
        KeyMaterial::Hwk(jwk) => {
            prepared.verify(jwk).map_err(proof)?;
            Ok(("hwk", jwk.thumbprint().unwrap_or_default(), jwk.alg.clone()))
        }
        KeyMaterial::JwksUri { id, dwk, kid } => {
            // Host admission: only the fixture signer's identity is trusted.
            if id != &ext.signer {
                return Err(SignatureFailure::Token(TokenError::UntrustedIssuer));
            }
            let keys = TrustedIssuerKeys::from_documents(
                id,
                dwk,
                &documents.signer_metadata,
                &documents.signer_jwks,
            )
            .map_err(SignatureFailure::Token)?;
            let key = keys.key(id, dwk, kid).map_err(SignatureFailure::Token)?;
            prepared.verify(&key).map_err(proof)?;
            Ok(("jwks_uri", id.clone(), key.alg))
        }
        KeyMaterial::Jwks { url, .. } => {
            // The crate leaves resolution of the exact url and kid to the host.
            let resolve = |presented: &str, kid: &str| -> Result<Jwk, ProofError> {
                if presented != ext.jwks_url {
                    return Err(ProofError::UnknownKey);
                }
                let set: serde_json::Value = serde_json::from_slice(&documents.direct_jwks)
                    .map_err(|_| ProofError::InvalidKey)?;
                let entry = set["keys"]
                    .as_array()
                    .and_then(|keys| keys.iter().find(|key| key["kid"] == kid))
                    .ok_or(ProofError::UnknownKey)?;
                serde_json::from_value(entry.clone()).map_err(|_| ProofError::InvalidKey)
            };
            let identity = prepared.verify_jwks(&resolve).map_err(proof)?;
            Ok(("jwks", url.clone(), identity.key.alg))
        }
        KeyMaterial::SelfJwt { .. } => {
            let resolve = |issuer: &str, dwk: &str, kid: &str| -> Result<Jwk, ProofError> {
                if issuer != ext.signer {
                    return Err(ProofError::UnknownKey);
                }
                TrustedIssuerKeys::from_documents(
                    issuer,
                    dwk,
                    &documents.signer_metadata,
                    &documents.signer_jwks,
                )
                .and_then(|keys| keys.key(issuer, dwk, kid))
                .map_err(|error| match error {
                    TokenError::UnknownKey => ProofError::UnknownKey,
                    _ => ProofError::InvalidKey,
                })
            };
            let assertion = prepared
                .verify_self_jwt(&documents.signer_metadata, &resolve, now, &ext.self_jwt_typ)
                .map_err(proof)?;
            let _ = assertion;
            Ok(("self-jwt", ext.signer.clone(), "Ed25519".into()))
        }
        KeyMaterial::JktJwt { .. } => {
            let delegation = prepared.verify_jkt_jwt(now).map_err(proof)?;
            Ok(("jkt-jwt", delegation.issuer, delegation.confirmation.alg))
        }
        _ => Err(SignatureFailure::Proof(ProofError::UnsupportedScheme)),
    }
}

fn announce(server: &tiny_http::Server, target: &str) -> Result<(), Failure> {
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    let uri: http::Uri = target.parse()?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{}",uri.path())})
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn respond(incoming: tiny_http::Request, response: Response<Vec<u8>>) -> Result<(), Failure> {
    let status = response.status().as_u16();
    let mut reply = tiny_http::Response::from_data(response.body().clone()).with_status_code(status);
    for (name, value) in response.headers() {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_str(), value.as_bytes()) {
            reply.add_header(header);
        }
    }
    incoming.respond(reply)?;
    Ok(())
}

pub fn run_verifier(config: Bootstrap) -> Result<(), Failure> {
    let ext: Extension = serde_json::from_value(config.extension.clone())?;
    let documents = discover(&ext)?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    announce(&server, &ext.verifier)?;
    for mut incoming in server.incoming_requests() {
        let response = match person_request(&mut incoming) {
            Ok(request) => verify(&ext, &documents, &request, config.now),
            Err(error) => Err(error),
        };
        let response = response.unwrap_or_else(|error| {
            Response::builder()
                .status(500)
                .body(error.to_string().into_bytes())
                .unwrap()
        });
        respond(incoming, response)?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct Job {
    scheme: String,
    alg: String,
    kid: String,
    #[serde(default)]
    seed_hex: String,
    #[serde(default)]
    pkcs8_hex: String,
    method: String,
    url: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    jwt: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    dwk: String,
    #[serde(default)]
    jwks_url: String,
    transport: String,
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, Failure> {
    if text.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn signing_key(job: &Job) -> Result<SigningKey, Failure> {
    if !job.seed_hex.is_empty() {
        let seed: [u8; 32] = hex_bytes(&job.seed_hex)?
            .try_into()
            .map_err(|_| "Ed25519 seed must be 32 bytes")?;
        return Ok(SigningKey::from_seed(seed));
    }
    Ok(SigningKey::from_pkcs8_der(&job.alg, &hex_bytes(&job.pkcs8_hex)?)?)
}

fn sign(job: &Job, now: i64) -> Result<Request<Vec<u8>>, Failure> {
    let key = signing_key(job)?;
    let material = match job.scheme.as_str() {
        "hwk" => KeyMaterial::Hwk(key.public_jwk()),
        "jwt" => KeyMaterial::Jwt {
            jwt: job.jwt.clone(),
            cache: false,
        },
        "jwks_uri" => KeyMaterial::JwksUri {
            id: job.id.clone(),
            dwk: job.dwk.clone(),
            kid: job.kid.clone(),
        },
        "jwks" => KeyMaterial::Jwks {
            url: job.jwks_url.clone(),
            kid: job.kid.clone(),
        },
        "self-jwt" => KeyMaterial::SelfJwt {
            jwt: job.jwt.clone(),
        },
        "jkt-jwt" => KeyMaterial::JktJwt {
            jwt: job.jwt.clone(),
            cache: false,
        },
        other => return Err(format!("aauth-rust offers no {other} signer").into()),
    };
    let mut builder = Request::builder()
        .method(job.method.as_str())
        .uri(job.url.as_str());
    if !job.content_type.is_empty() {
        builder = builder.header("content-type", job.content_type.as_str());
    }
    let mut request = builder.body(job.body.clone().into_bytes())?;
    sign_request(&mut request, &key, material, now)?;
    Ok(request)
}

/// Write the signed request unchanged to the loopback transport.
fn send(base: &str, request: &Request<Vec<u8>>) -> Result<u16, Failure> {
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
        if name != "content-length" && name != "host" {
            write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
        }
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

pub fn run_signer(config: Bootstrap) -> Result<(), Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    announce(&server, &config.resource)?;
    for mut incoming in server.incoming_requests() {
        let operation = (|| -> Result<u16, Failure> {
            let mut body = Vec::new();
            incoming.as_reader().take(65537).read_to_end(&mut body)?;
            let job: Job = serde_json::from_slice(&body)?;
            let request = sign(&job, config.now)?;
            send(&job.transport, &request)
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
