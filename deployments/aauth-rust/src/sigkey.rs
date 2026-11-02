//! Serves the Signature-Key verifier Resource for remote mode: an
//! agent-identity Resource at `/verify` that also accepts the further schemes
//! (hwk, jkt-jwt, self-jwt, jwks and jwks_uri). As the crate requires, this
//! host fetches the documents a verified member names, for each request and
//! only from the deployment's trusted parties, and passes their bytes;
//! parsing, issuer checks, key selection, algorithm determination and every
//! proof decision are aauth-rust's. A verified request is answered with the
//! scheme and the verified identity, as the launcher answers it.
//!
//! Name: `names.sigkey_verifier`, the verifier's issuer. Test profile:
//! self-jwt assertions carry `typ` `conformance-self+jwt`.
use crate::https::{Client, Failure};
use crate::{Env, Route, json, now};
use aauth_rust_core::{
    AgentKeyResolver, AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAgentToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::Jwk;
use aauth_rust_resource::{AgentIdentityResource, Decision, SignatureFailure};
use aauth_rust_signature_key::{Error as ProofError, KeyMaterial, PreparedRequest};
use http::{Request, Response};
use std::sync::Arc;

const SELF_JWT_TYP: &str = "conformance-self+jwt";

/// Fetches a trusted party's documents afresh for each request.
#[derive(Clone)]
struct Documents {
    trusted: Arc<Vec<String>>,
    client: Arc<Client>,
}

impl Documents {
    /// Whether `url` is a trusted party's origin or lies under it.
    fn admitted(&self, url: &str) -> bool {
        self.trusted
            .iter()
            .any(|party| url == party || url.starts_with(&format!("{party}/")))
    }

    /// An issuer's metadata document and the JWKS its jwks_uri names.
    fn issuer(&self, issuer: &str, dwk: &str) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        if !self.admitted(issuer) {
            return Err(format!("{issuer} is not a trusted party").into());
        }
        let metadata = self.client.get(&format!("{issuer}/.well-known/{dwk}"))?;
        let jwks = self.client.get(&metadata_jwks_uri(issuer, &metadata)?)?;
        Ok((metadata, jwks))
    }
}

/// The Agent Provider keys of the token's issuer, from its documents.
impl AgentKeyResolver for Documents {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if !self.admitted(issuer) {
            return Err(TokenError::UntrustedIssuer);
        }
        let (metadata, jwks) = self.issuer(issuer, dwk).map_err(|error| {
            eprintln!("sigkey verifier: discovering {issuer}: {error}");
            TokenError::InvalidKey
        })?;
        AgentProviderKeys::from_documents(issuer, &metadata, &jwks)?.key(issuer, dwk, kid)
    }
}

/// The unverified `iss` of a compact JWT, which names the documents to fetch;
/// the crate verifies the assertion against them.
fn unverified_issuer(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();
    for c in payload.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims["iss"].as_str().map(str::to_owned)
}

fn refuse(failure: SignatureFailure) -> Response<Vec<u8>> {
    Decision::<()>::SignatureFailure(failure).into_response()
}

fn echo(value: serde_json::Value) -> Response<Vec<u8>> {
    json(200, value.to_string().into_bytes())
}

fn further(
    documents: &Documents,
    prepared: &PreparedRequest,
    now: i64,
) -> Result<(&'static str, String, String), SignatureFailure> {
    let proof = SignatureFailure::Proof;
    let unavailable = |error: Failure| {
        eprintln!("sigkey verifier: {error}");
        SignatureFailure::Token(TokenError::InvalidKey)
    };
    match prepared.key() {
        KeyMaterial::Hwk(jwk) => {
            prepared.verify(jwk).map_err(proof)?;
            Ok(("hwk", jwk.thumbprint().unwrap_or_default(), jwk.alg.clone()))
        }
        KeyMaterial::JwksUri { id, dwk, kid } => {
            // Host admission: only the deployment's trusted parties.
            if !documents.admitted(id) {
                return Err(SignatureFailure::Token(TokenError::UntrustedIssuer));
            }
            let (metadata, jwks) = documents.issuer(id, dwk).map_err(unavailable)?;
            let keys = TrustedIssuerKeys::from_documents(id, dwk, &metadata, &jwks)
                .map_err(SignatureFailure::Token)?;
            let key = keys.key(id, dwk, kid).map_err(SignatureFailure::Token)?;
            prepared.verify(&key).map_err(proof)?;
            Ok(("jwks_uri", id.clone(), key.alg))
        }
        KeyMaterial::Jwks { url, .. } => {
            // The crate leaves resolution of the exact url and kid to the host.
            let resolve = |presented: &str, kid: &str| -> Result<Jwk, ProofError> {
                if !documents.admitted(presented) {
                    return Err(ProofError::UnknownKey);
                }
                let body = documents.client.get(presented).map_err(|error| {
                    eprintln!("sigkey verifier: {error}");
                    ProofError::UnknownKey
                })?;
                let set: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| ProofError::InvalidKey)?;
                let entry = set["keys"]
                    .as_array()
                    .and_then(|keys| keys.iter().find(|key| key["kid"] == kid))
                    .ok_or(ProofError::UnknownKey)?;
                serde_json::from_value(entry.clone()).map_err(|_| ProofError::InvalidKey)
            };
            let identity = prepared.verify_jwks(&resolve).map_err(proof)?;
            Ok(("jwks", url.clone(), identity.key.alg))
        }
        KeyMaterial::SelfJwt { jwt } => {
            let issuer = unverified_issuer(jwt)
                .ok_or(SignatureFailure::Proof(ProofError::InvalidKey))?;
            let dwk = "aauth-resource.json";
            let (metadata, jwks) = documents.issuer(&issuer, dwk).map_err(unavailable)?;
            let resolve = |named: &str, dwk: &str, kid: &str| -> Result<Jwk, ProofError> {
                if named != issuer {
                    return Err(ProofError::UnknownKey);
                }
                TrustedIssuerKeys::from_documents(named, dwk, &metadata, &jwks)
                    .and_then(|keys| keys.key(named, dwk, kid))
                    .map_err(|error| match error {
                        TokenError::UnknownKey => ProofError::UnknownKey,
                        _ => ProofError::InvalidKey,
                    })
            };
            prepared
                .verify_self_jwt(&metadata, &resolve, now, SELF_JWT_TYP)
                .map_err(proof)?;
            Ok(("self-jwt", issuer, "Ed25519".into()))
        }
        KeyMaterial::JktJwt { .. } => {
            let delegation = prepared.verify_jkt_jwt(now).map_err(proof)?;
            Ok(("jkt-jwt", delegation.issuer, delegation.confirmation.alg))
        }
        _ => Err(SignatureFailure::Proof(ProofError::UnsupportedScheme)),
    }
}

/// The routes this module serves; none until its name is configured.
pub fn routes(env: &Env) -> Result<Vec<Route>, Failure> {
    let Some(issuer) = env.c.names.get("sigkey_verifier") else {
        return Ok(Vec::new());
    };
    let documents = Documents {
        trusted: env.keys.trusted.clone(),
        client: env.client.clone(),
    };
    let resource = AgentIdentityResource::new(
        &format!("{issuer}/verify"),
        documents.clone(),
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )?
    .with_further_schemes(&["hwk", "jkt-jwt", "self-jwt", "jwks", "jwks_uri"])?;
    Ok(vec![Route::new(issuer, "/verify", move |request| {
        if request.uri().path() != "/verify" {
            return json(404, Vec::new());
        }
        let now = now();
        match resource.authorize(&request, now) {
            Decision::Granted(authorized) => {
                echo(serde_json::json!({"scheme":"jwt","sub":authorized.claims().sub}))
            }
            Decision::OtherScheme(prepared) => match further(&documents, &prepared, now) {
                Ok((scheme, signer, alg)) => {
                    echo(serde_json::json!({"scheme":scheme,"signer":signer,"alg":alg}))
                }
                Err(failure) => refuse(failure),
            },
            other => other.into_response(),
        }
    })])
}
