//! Signature-Key test vectors. aauth-rust signs a vector's request with
//! `sign_requests`, and verifies a vector with its native
//! `AgentIdentityResource` (further schemes enabled) and, for a
//! `Decision::OtherScheme`, the `PreparedRequest` method the member calls
//! for. The crate never fetches; as its documentation requires, this host
//! passes the bytes of the vector's documents. Parsing, issuer checks, key
//! selection, algorithm determination and every proof decision are
//! aauth-rust's, except selecting the kid of a direct jwks, which the crate
//! leaves to the host.
use super::Bootstrap;
use aauth_rust_core::{
    AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAgentToken, metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::{AgentIdentityResource, Decision, SignatureFailure};
use aauth_rust_signature_key::{
    AssertionCache, Error as ProofError, KeyMaterial, PreparedRequest, RequestSignature,
    sign_requests,
};
use http::{Request, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize, Default)]
struct HttpRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct Part {
    label: String,
    alg: String,
    #[serde(default)]
    seed_hex: String,
    #[serde(default)]
    pkcs8_base64: String,
    scheme: String,
    #[serde(default)]
    kid: String,
    #[serde(default)]
    jwt: String,
    #[serde(default)]
    cache: bool,
    #[serde(default)]
    id: String,
    #[serde(default)]
    dwk: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    x5u: String,
    #[serde(default)]
    x5t_base64: String,
    #[serde(default)]
    cid: String,
}

#[derive(Deserialize, Default)]
struct Document {
    url: String,
    body: String,
}

#[derive(Deserialize, Default)]
struct Verifier {
    resource: String,
    agent_provider: String,
    self_jwt_typ: String,
    #[serde(default)]
    window_seconds: i64,
}

#[derive(Deserialize, Default)]
struct Trust {
    #[serde(default)]
    trust_anchors_der_base64: Vec<String>,
    #[serde(default)]
    crls_der_base64: Vec<String>,
}

#[derive(Deserialize, Default)]
struct Environment {
    verifier: Verifier,
    #[serde(default)]
    documents: Vec<Document>,
    #[serde(default)]
    x509: Trust,
}

#[derive(Deserialize)]
struct Job {
    op: String,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    now: i64,
    #[serde(default)]
    request: HttpRequest,
    #[serde(default)]
    signatures: Vec<Part>,
    #[serde(default)]
    environment: Environment,
    #[serde(default)]
    labels: Vec<String>,
}

pub fn run(config: Bootstrap) -> Result<(), Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    let path = config.resource.parse::<http::Uri>()?.path().to_owned();
    println!(
        "{}",
        json!({"version":1,"url":format!("http://{address}{path}")})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let mut body = Vec::new();
        incoming.as_reader().take(1 << 22).read_to_end(&mut body)?;
        let response = match serde_json::from_slice::<Job>(&body) {
            Ok(job) if job.op == "sign" => match sign(&job) {
                Ok(Ok(headers)) => json_response(200, json!({"headers": headers})),
                Ok(Err(reason)) => json_response(501, json!({"not_offered": reason})),
                Err(error) => json_response(422, json!({"error": error.to_string()})),
            },
            Ok(job) if job.op == "verify" => verify(&job)
                .unwrap_or_else(|error| json_response(422, json!({"error": error.to_string()}))),
            Ok(job) => json_response(400, json!({"error": format!("unknown op {}", job.op)})),
            Err(error) => json_response(400, json!({"error": error.to_string()})),
        };
        let status = response.status().as_u16();
        let mut reply =
            tiny_http::Response::from_data(response.body().clone()).with_status_code(status);
        for (name, value) in response.headers() {
            if let Ok(header) = tiny_http::Header::from_bytes(name.as_str(), value.as_bytes()) {
                reply.add_header(header);
            }
        }
        incoming.respond(reply)?;
    }
    Ok(())
}

fn json_response(status: u16, value: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .unwrap()
}

/// RFC 4648 base64, standard or URL-safe alphabet, padding optional.
fn base64_decode(text: &str) -> Result<Vec<u8>, Failure> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes().filter(|c| *c != b'=') {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return Err("invalid base64".into()),
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Ok(out)
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

fn build_request(spec: &HttpRequest) -> Result<Request<Vec<u8>>, Failure> {
    let mut request = Request::builder()
        .method(spec.method.as_str())
        .uri(spec.url.as_str());
    for (name, value) in &spec.headers {
        request = request.header(name.to_ascii_lowercase(), value.as_str());
    }
    Ok(request.body(spec.body.as_bytes().to_vec())?)
}

fn signing_key(part: &Part) -> Result<SigningKey, Failure> {
    if !part.seed_hex.is_empty() {
        let seed: [u8; 32] = hex_bytes(&part.seed_hex)?
            .try_into()
            .map_err(|_| "Ed25519 seed must be 32 bytes")?;
        return Ok(SigningKey::from_seed(seed));
    }
    Ok(SigningKey::from_pkcs8_der(
        &part.alg,
        &base64_decode(&part.pkcs8_base64)?,
    )?)
}

fn material(part: &Part, key: &SigningKey) -> Result<Result<KeyMaterial, String>, Failure> {
    Ok(Ok(match part.scheme.as_str() {
        "hwk" => KeyMaterial::Hwk(key.public_jwk()),
        "jwt" => KeyMaterial::Jwt {
            jwt: part.jwt.clone(),
            cache: part.cache,
        },
        "jwks_uri" => KeyMaterial::JwksUri {
            id: part.id.clone(),
            dwk: part.dwk.clone(),
            kid: part.kid.clone(),
        },
        "jwks" => KeyMaterial::Jwks {
            url: part.url.clone(),
            kid: part.kid.clone(),
        },
        "self-jwt" => KeyMaterial::SelfJwt {
            jwt: part.jwt.clone(),
        },
        "jkt-jwt" => KeyMaterial::JktJwt {
            jwt: part.jwt.clone(),
            cache: part.cache,
        },
        "x509" => KeyMaterial::X509 {
            x5u: part.x5u.clone(),
            x5t: base64_decode(&part.x5t_base64)?,
        },
        "cached" => KeyMaterial::Cached {
            cid: part.cid.clone(),
        },
        other => return Ok(Err(format!("aauth-rust offers no {other} signer"))),
    }))
}

/// Sign with `sign_requests` at the job's created time and return every
/// header field of the signed request.
fn sign(job: &Job) -> Result<Result<BTreeMap<String, String>, String>, Failure> {
    if !job.nonce.is_empty() {
        return Ok(Err(
            "aauth-rust's signer takes no nonce signature parameter".into(),
        ));
    }
    let keys = job
        .signatures
        .iter()
        .map(signing_key)
        .collect::<Result<Vec<_>, _>>()?;
    let mut parts = Vec::new();
    for (part, key) in job.signatures.iter().zip(&keys) {
        match material(part, key)? {
            Ok(material) => parts.push(RequestSignature {
                label: &part.label,
                key,
                material,
            }),
            Err(reason) => return Ok(Err(reason)),
        }
    }
    let mut request = build_request(&job.request)?;
    sign_requests(&mut request, &parts, job.created)
        .map_err(|error| format!("{} ({error})", error.code()))?;
    let mut headers = BTreeMap::new();
    for name in request.headers().keys() {
        let values = request
            .headers()
            .get_all(name)
            .iter()
            .map(|v| v.to_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        headers.insert(name.as_str().to_owned(), values.join(", "));
    }
    Ok(Ok(headers))
}

struct Documents<'a>(&'a [Document]);

impl Documents<'_> {
    fn get(&self, url: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|d| d.url == url)
            .map(|d| d.body.as_bytes())
    }
}

fn refuse(failure: SignatureFailure) -> Response<Vec<u8>> {
    Decision::<()>::SignatureFailure(failure).into_response()
}

fn verify(job: &Job) -> Result<Response<Vec<u8>>, Failure> {
    let env = &job.environment;
    let documents = Documents(&env.documents);
    let request = build_request(&job.request)?;
    if !job.labels.is_empty() {
        return Ok(verify_labels(job, &documents, &request));
    }
    let ap = &env.verifier.agent_provider;
    let ap_metadata = documents
        .get(&format!("{ap}/.well-known/aauth-agent.json"))
        .ok_or("no Agent Provider metadata")?;
    let ap_jwks = documents
        .get(&metadata_jwks_uri(ap, ap_metadata)?)
        .ok_or("no Agent Provider JWKS")?;
    let keys = match AgentProviderKeys::from_documents(ap, ap_metadata, ap_jwks) {
        Ok(keys) => keys,
        Err(error) => return Ok(refuse(SignatureFailure::Token(error))),
    };
    let resource = AgentIdentityResource::new(
        &env.verifier.resource,
        keys,
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )?
    .with_further_schemes(&[
        "hwk", "jkt-jwt", "self-jwt", "jwks", "jwks_uri", "x509", "cached",
    ])?;
    Ok(match resource.authorize(&request, job.now) {
        Decision::Granted(authorized) => json_response(
            200,
            json!({"scheme":"jwt","sub":authorized.claims().sub}),
        ),
        Decision::OtherScheme(prepared) => match further(env, &documents, &prepared, job.now) {
            Ok((scheme, alg)) => json_response(200, json!({"scheme":scheme,"alg":alg})),
            Err(failure) => refuse(failure),
        },
        other => other.into_response(),
    })
}

/// Verifies every label a multi-signature vector names, each through
/// `PreparedRequest::prepare_with_schemes` with that label and the
/// `PreparedRequest` verifier its member calls for. Answers 200 with each
/// label's scheme when all verify, or the first refusal.
fn verify_labels(
    job: &Job,
    documents: &Documents<'_>,
    request: &Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let env = &job.environment;
    let mut schemes = serde_json::Map::new();
    for label in &job.labels {
        let prepared = match PreparedRequest::prepare_with_schemes(
            request,
            label,
            job.now,
            env.verifier.window_seconds,
            &["hwk", "jwks", "jwks_uri"],
        ) {
            Ok(prepared) => prepared,
            Err(error) => return refuse(SignatureFailure::Proof(error)),
        };
        match further(env, documents, &prepared, job.now) {
            Ok((scheme, _)) => {
                schemes.insert(label.clone(), json!(scheme));
            }
            Err(failure) => return refuse(failure),
        }
    }
    json_response(200, json!({"labels": schemes}))
}

/// The unverified `iss` and `dwk` of a self-jwt, which name the metadata
/// document the host must fetch before the crate can verify it.
fn self_jwt_discovery(jwt: &str) -> Option<(String, String)> {
    let payload = jwt.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&base64_decode(payload).ok()?).ok()?;
    Some((
        claims["iss"].as_str()?.to_owned(),
        claims["dwk"].as_str()?.to_owned(),
    ))
}

fn further(
    env: &Environment,
    documents: &Documents<'_>,
    prepared: &PreparedRequest,
    now: i64,
) -> Result<(&'static str, String), SignatureFailure> {
    let proof = SignatureFailure::Proof;
    // A document the host cannot fetch: the key cannot be obtained.
    let missing = || SignatureFailure::Proof(ProofError::InvalidKey);
    match prepared.key() {
        KeyMaterial::Hwk(jwk) => {
            prepared.verify(jwk).map_err(proof)?;
            Ok(("hwk", jwk.alg.clone()))
        }
        KeyMaterial::JwksUri { id, dwk, kid } => {
            let metadata = documents
                .get(&format!("{id}/.well-known/{dwk}"))
                .ok_or_else(missing)?;
            let jwks_uri = metadata_jwks_uri(id, metadata).map_err(SignatureFailure::Token)?;
            let jwks = documents.get(&jwks_uri).ok_or_else(missing)?;
            let keys = TrustedIssuerKeys::from_documents(id, dwk, metadata, jwks)
                .map_err(SignatureFailure::Token)?;
            let key = keys.key(id, dwk, kid).map_err(SignatureFailure::Token)?;
            prepared.verify(&key).map_err(proof)?;
            Ok(("jwks_uri", key.alg))
        }
        KeyMaterial::Jwks { url, .. } => {
            let set = documents.get(url).ok_or_else(missing)?;
            // The crate leaves resolution of the exact url and kid to the host.
            let resolve = |presented: &str, kid: &str| -> Result<Jwk, ProofError> {
                if presented != url {
                    return Err(ProofError::UnknownKey);
                }
                let set: Value = serde_json::from_slice(set).map_err(|_| ProofError::InvalidKey)?;
                let entry = set["keys"]
                    .as_array()
                    .and_then(|keys| keys.iter().find(|key| key["kid"] == kid))
                    .ok_or(ProofError::UnknownKey)?;
                serde_json::from_value(entry.clone()).map_err(|_| ProofError::InvalidKey)
            };
            let identity = prepared.verify_jwks(&resolve).map_err(proof)?;
            Ok(("jwks", identity.key.alg))
        }
        KeyMaterial::SelfJwt { jwt } => {
            let (issuer, dwk) = self_jwt_discovery(jwt)
                .ok_or(SignatureFailure::Proof(ProofError::InvalidJwt))?;
            let metadata = documents
                .get(&format!("{issuer}/.well-known/{dwk}"))
                .ok_or_else(missing)?;
            let resolve = |issuer: &str, dwk: &str, kid: &str| -> Result<Jwk, ProofError> {
                let jwks_uri =
                    metadata_jwks_uri(issuer, metadata).map_err(|_| ProofError::InvalidKey)?;
                let jwks = documents.get(&jwks_uri).ok_or(ProofError::InvalidKey)?;
                TrustedIssuerKeys::from_documents(issuer, dwk, metadata, jwks)
                    .and_then(|keys| keys.key(issuer, dwk, kid))
                    .map_err(|error| match error {
                        TokenError::UnknownKey => ProofError::UnknownKey,
                        _ => ProofError::InvalidKey,
                    })
            };
            prepared
                .verify_self_jwt(metadata, &resolve, now, &env.verifier.self_jwt_typ)
                .map_err(proof)?;
            Ok(("self-jwt", String::new()))
        }
        KeyMaterial::JktJwt { .. } => {
            let delegation = prepared.verify_jkt_jwt(now).map_err(proof)?;
            Ok(("jkt-jwt", delegation.confirmation.alg))
        }
        KeyMaterial::X509 { x5u, .. } => {
            let chain = documents.get(x5u).ok_or_else(missing)?;
            let chain = std::str::from_utf8(chain).map_err(|_| missing())?;
            let decode = |values: &[String]| -> Result<Vec<Vec<u8>>, SignatureFailure> {
                values
                    .iter()
                    .map(|v| base64_decode(v).map_err(|_| missing()))
                    .collect()
            };
            let anchors = decode(&env.x509.trust_anchors_der_base64)?;
            let crls = decode(&env.x509.crls_der_base64)?;
            let anchors: Vec<&[u8]> = anchors.iter().map(Vec::as_slice).collect();
            let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
            let identity = prepared
                .verify_x509(chain, &anchors, &crls, now)
                .map_err(proof)?;
            Ok(("x509", identity.key.alg))
        }
        // jwt keeps the Resource's own AAuth path and never reaches here.
        KeyMaterial::Jwt { .. } => Err(SignatureFailure::Proof(ProofError::UnsupportedScheme)),
        KeyMaterial::Cached { .. } => {
            // A fresh verifier cache: it has issued nothing.
            let cache = AssertionCache::open([7u8; 32], 16, 4).map_err(proof)?;
            let cached = prepared.verify_cached(&cache, now).map_err(proof)?;
            Ok(("cached", cached.confirmation.alg))
        }
    }
}
