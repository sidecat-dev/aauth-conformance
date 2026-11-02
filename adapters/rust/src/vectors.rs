//! Community test vectors: one native aauth-rust function per vector kind,
//! reported unchanged. The launcher decides nothing and supplies no proof.
use super::Bootstrap;
use aauth_rust_agent::{Requirement, RequirementError};
use aauth_rust_core::continuation::{PendingResponse, Requirement as Pending};
use aauth_rust_core::{
    AgentToken, AuthToken, PersonToken, ResourceToken, TokenError, TrustedIssuerKeys,
    metadata_jwks_uri, validate_agent_identifier, validate_server_identifier,
};
use aauth_rust_jose::Jwk;
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest, parse_signature_error};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};

type Failure = Box<dyn std::error::Error>;

/// Every scheme aauth-rust parses, for the evidence-only scheme report.
const ALL_SCHEMES: &[&str] = &[
    "hwk", "jwt", "jkt-jwt", "jwks_uri", "jwks", "self-jwt", "x509", "cached",
];

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
struct Framing {
    status: u16,
    endpoint: String,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Deserialize)]
struct Input {
    kind: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    jwk: Value,
    #[serde(default)]
    document: String,
    #[serde(default)]
    json: String,
    #[serde(default)]
    header: String,
    #[serde(default)]
    framing: Option<Framing>,
    #[serde(default)]
    label: String,
    #[serde(default)]
    now: i64,
    #[serde(default)]
    request: HttpRequest,
    #[serde(default)]
    typ: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    dwk: String,
    #[serde(default)]
    metadata: String,
    #[serde(default)]
    jwks: String,
    #[serde(default)]
    key: Value,
    #[serde(default)]
    window: i64,
    #[serde(default)]
    required_components: Vec<String>,
}

enum Answer {
    Result(Value),
}

pub fn run(_config: Bootstrap) -> Result<(), Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        json!({"version":1,"url":format!("http://{address}/vector")})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let mut body = Vec::new();
        incoming.as_reader().take(1 << 20).read_to_end(&mut body)?;
        let (status, value) = match serde_json::from_slice::<Input>(&body) {
            Ok(input) => match handle(&input) {
                Ok(Answer::Result(value)) => (200, value),
                Err(error) => (422, json!({"error": error.to_string()})),
            },
            Err(error) => (400, json!({"error": error.to_string()})),
        };
        let response = tiny_http::Response::from_data(serde_json::to_vec(&value)?)
            .with_status_code(status)
            .with_header(
                tiny_http::Header::from_bytes("Content-Type", "application/json")
                    .map_err(|_| "header")?,
            );
        incoming.respond(response)?;
    }
    Ok(())
}

fn refused(error: impl std::fmt::Display) -> Value {
    json!({"accepted": false, "error": error.to_string()})
}

fn refused_with_code(code: &str, error: impl std::fmt::Display) -> Value {
    json!({"accepted": false, "code": code, "error": error.to_string()})
}

fn handle(input: &Input) -> Result<Answer, Failure> {
    let value = match input.kind.as_str() {
        "agent-identifier" => match validate_agent_identifier(&input.input) {
            Ok(()) => json!({"accepted": true}),
            Err(error) => refused(error),
        },
        "server-identifier" => match validate_server_identifier(&input.input) {
            Ok(()) => json!({"accepted": true}),
            Err(error) => refused(error),
        },
        "jwk-thumbprint" => match serde_json::from_value::<Jwk>(input.jwk.clone()) {
            Ok(key) => match key.thumbprint() {
                Ok(thumbprint) => json!({"accepted": true, "thumbprint": thumbprint}),
                Err(error) => refused(error),
            },
            Err(error) => refused(error),
        },
        "metadata" => {
            // The verifier-side check every discovery document passes: issuer,
            // display URLs and jwks_uri.
            let issuer = serde_json::from_str::<Value>(&input.json)?
                .get("issuer")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            match metadata_jwks_uri(&issuer, input.json.as_bytes()) {
                Ok(_) => json!({"accepted": true}),
                Err(error) => refused_with_code(error.code(), error),
            }
        }
        "signature-error" => match parse_signature_error(&input.header) {
            Ok(error) => match error.required_input {
                Some(required) => {
                    json!({"accepted": true, "code": error.code, "required_input": required})
                }
                None => json!({"accepted": true, "code": error.code}),
            },
            Err(error) => refused_with_code(error.code(), error),
        },
        "requirement" => requirement(input)?,
        "signature-key" => signature_key(input)?,
        "jwt" => jwt(input),
        "http-signature" => http_signature(input)?,
        other => return Err(format!("unknown vector kind {other}").into()),
    };
    Ok(Answer::Result(value))
}

fn requirement(input: &Input) -> Result<Value, Failure> {
    let header = http::HeaderValue::from_str(&input.header)?;
    match Requirement::parse(&header) {
        Ok(Requirement::AgentToken) => Ok(json!({"accepted": true, "requirement": "agent-token"})),
        Ok(Requirement::PersonToken) => {
            Ok(json!({"accepted": true, "requirement": "person-token"}))
        }
        Ok(Requirement::AuthToken { resource_token }) => Ok(
            json!({"accepted": true, "requirement": "auth-token", "resource_token": resource_token}),
        ),
        // The Agent's immediate parser leaves deferred values to the pending
        // response parser, which reads them inside a 202's framing.
        Err(RequirementError::Unsupported(value)) => {
            let Some(framing) = &input.framing else {
                return Ok(json!({"accepted": false, "requirement": value}));
            };
            let mut response = http::Response::builder()
                .status(framing.status)
                .header("aauth-requirement", &input.header);
            for (name, value) in &framing.headers {
                response = response.header(name.as_str(), value.as_str());
            }
            let response = response.body(framing.body.as_bytes().to_vec())?;
            match PendingResponse::parse(&framing.endpoint, &response) {
                Ok(pending) => Ok(match pending.requirement {
                    Pending::Interaction { url, code } => {
                        json!({"accepted": true, "requirement": "interaction", "url": url, "interaction_code": code})
                    }
                    Pending::Approval => json!({"accepted": true, "requirement": "approval"}),
                    other => json!({"accepted": true, "requirement": format!("{other:?}")}),
                }),
                Err(error) => Ok(
                    json!({"accepted": false, "requirement": value, "error": format!("{error:?}")}),
                ),
            }
        }
        Err(error) => Ok(refused(error)),
    }
}

fn build_request(spec: &HttpRequest) -> Result<http::Request<Vec<u8>>, Failure> {
    let mut request = http::Request::builder()
        .method(spec.method.as_str())
        .uri(spec.url.as_str());
    for (name, value) in &spec.headers {
        request = request.header(name.to_ascii_lowercase(), value.as_str());
    }
    Ok(request.body(spec.body.as_bytes().to_vec())?)
}

fn scheme_name(key: &KeyMaterial) -> &'static str {
    match key {
        KeyMaterial::Hwk(_) => "hwk",
        KeyMaterial::Jwt { .. } => "jwt",
        KeyMaterial::JwksUri { .. } => "jwks_uri",
        KeyMaterial::JktJwt { .. } => "jkt-jwt",
        KeyMaterial::SelfJwt { .. } => "self-jwt",
        KeyMaterial::Jwks { .. } => "jwks",
        KeyMaterial::X509 { .. } => "x509",
        KeyMaterial::Cached { .. } => "cached",
    }
}

/// Prepare the request under the AAuth agent profile (`jwt` only) for the
/// selected label. No key is verified; the placeholder signature only lets
/// aauth-rust reach its Signature-Key processing.
fn signature_key(input: &Input) -> Result<Value, Failure> {
    let request = build_request(&input.request)?;
    let mut result = serde_json::Map::new();
    if let Ok(prepared) =
        PreparedRequest::prepare_with_schemes(&request, &input.label, input.now, 60, ALL_SCHEMES)
    {
        result.insert("scheme".into(), scheme_name(prepared.key()).into());
    }
    match PreparedRequest::prepare_with_schemes(&request, &input.label, input.now, 60, &["jwt"]) {
        Ok(prepared) => {
            result.insert("accepted".into(), true.into());
            if let KeyMaterial::Jwt { jwt, .. } = prepared.key() {
                result.insert("jwt".into(), jwt.clone().into());
            }
        }
        Err(error) => {
            result.insert("accepted".into(), false.into());
            result.insert("code".into(), error.code().into());
            result.insert("error".into(), error.to_string().into());
        }
    }
    Ok(Value::Object(result))
}

fn token_refusal(error: TokenError) -> Value {
    refused_with_code(error.code(), error)
}

fn jwt(input: &Input) -> Value {
    let keys = match TrustedIssuerKeys::from_documents(
        &input.issuer,
        &input.dwk,
        input.metadata.as_bytes(),
        input.jwks.as_bytes(),
    ) {
        Ok(keys) => keys,
        Err(error) => {
            let mut value = token_refusal(error);
            value["stage"] = "trust".into();
            return value;
        }
    };
    let verified = match input.typ.as_str() {
        "aa-agent+jwt" => {
            AgentToken::parse(&input.token).and_then(|t| t.verify(&keys, input.now).map(|_| ()))
        }
        "aa-person+jwt" => {
            PersonToken::parse(&input.token).and_then(|t| t.verify(&keys, input.now).map(|_| ()))
        }
        "aa-resource+jwt" => {
            ResourceToken::parse(&input.token).and_then(|t| t.verify(&keys, input.now).map(|_| ()))
        }
        "aa-auth+jwt" => {
            AuthToken::parse(&input.token).and_then(|t| t.verify(&keys, input.now).map(|_| ()))
        }
        other => return json!({"accepted": false, "error": format!("no verifier for typ {other}")}),
    };
    match verified {
        Ok(()) => json!({"accepted": true}),
        Err(error) => token_refusal(error),
    }
}

/// Verify the request with the vector's public key under the AAuth agent
/// profile, the given clock and window, and the components the vector's
/// server requires. aauth-rust always requires covered Content-Digest and
/// Content-Type on a body carrying Content-Type, which covers the vectors'
/// PS-endpoint case.
fn http_signature(input: &Input) -> Result<Value, Failure> {
    let request = build_request(&input.request)?;
    let key: Jwk = match serde_json::from_value(input.key.clone()) {
        Ok(key) => key,
        Err(error) => {
            return Ok(json!({"accepted": false, "stage": "key", "error": error.to_string()}));
        }
    };
    let required: Vec<&str> = input
        .required_components
        .iter()
        .map(String::as_str)
        .collect();
    let prepared = match PreparedRequest::prepare_with_components(
        &request,
        &input.label,
        input.now,
        input.window,
        &["jwt"],
        &required,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(refused_with_code(error.code(), error)),
    };
    Ok(match prepared.verify(&key) {
        Ok(()) => json!({"accepted": true}),
        Err(error) => refused_with_code(error.code(), error),
    })
}
