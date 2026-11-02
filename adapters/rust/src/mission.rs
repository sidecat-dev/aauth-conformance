//! Mission roles: the native Person Server with its mission endpoint and
//! governance, and the four-party bundle for the Resource's challenge.
//! Approval, update and completion decisions are host inputs; every protocol
//! answer, digest and token comes from the native Person Server.
use super::{Bootstrap, FixturePolicy, PersonKeys, fetch, person_request};
use aauth_rust_core::{AgentProviderKeys, ApprovedMission, TrustedIssuerKeys};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AgentIdentity, Config as PersonConfig, Governance, MemoryStore, MissionRecord, MissionState,
    PersonServer, PolicyError, Store,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde::Deserialize;
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};

type Failure = Box<dyn std::error::Error>;

pub(super) fn run(config: Bootstrap) -> Result<(), Failure> {
    if config.role == "mission.resource" {
        return super::federation::run(config);
    }
    run_mission_server(config)
}

/// The fixture person allows every permission and answers every question.
struct FixtureGovernance;
impl Governance for FixtureGovernance {
    fn answer(&self, _question: &str) -> Result<String, PolicyError> {
        Ok("Fixture answer.".into())
    }
    fn permit(&self, _action: &str) -> Result<bool, PolicyError> {
        Ok(true)
    }
}

#[derive(Deserialize)]
struct Install {
    s256: String,
    agent: String,
}

/// Loopback host input. `approve` is the person's approval of a pending
/// proposal; `install` records an approved mission for issuance, which this
/// crate leaves to the host (`with_missions` does not install the record).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    now_offset: Option<i64>,
    expires_in: Option<i64>,
    approve: Option<String>,
    install: Option<Install>,
}

fn seed(hex: &str) -> Result<[u8; 32], Failure> {
    if hex.len() != 64 {
        return Err("Person Server seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(seed)
}

fn run_mission_server(config: Bootstrap) -> Result<(), Failure> {
    let seed = seed(&config.person_seed_hex)?;
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
    let mut resource_jwk = config.resource_jwk.clone();
    resource_jwk
        .as_object_mut()
        .ok_or("Resource JWK must be an object")?
        .insert("kid".into(), config.resource_kid.clone().into());
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
        SigningKey::from_seed(seed),
    );
    person_config.person_lifetime = config.person_lifetime;
    let policy = FixturePolicy {
        subject: config.person_subject.clone(),
        scopes: config.permitted_scopes.clone(),
        auth_lifetime: config.auth_lifetime,
    };
    let offset = Arc::new(AtomicI64::new(0));
    // The expiry the host was told to set at the person's next approval.
    let expires_in = AtomicI64::new(0);
    let clock_offset = offset.clone();
    let now = config.now;
    let clock = move || now + clock_offset.load(Ordering::SeqCst);
    let sequence = AtomicU64::new(0);
    let store = MemoryStore::default();
    let sut = PersonServer::new(
        person_config,
        PersonKeys { ap, resource },
        store.clone(),
        policy,
        clock.clone(),
        move || format!("mission-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1),
    )?
    .with_missions()
    .with_governance(FixtureGovernance);
    let approver = SigningKey::from_seed(seed);
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    // Only the announced physical origin is used; the path satisfies the
    // runner's readiness check.
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{}", target.path())})
    );
    std::io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let response = if request.uri().path() == "/__fixture/mission" && request.method() == "POST"
        {
            let outcome = (|| -> Result<serde_json::Value, Failure> {
                let control: Control = serde_json::from_slice(request.body())?;
                if let Some(seconds) = control.now_offset {
                    if !(-3600..=3600).contains(&seconds) {
                        return Err("clock offset out of range".into());
                    }
                    offset.store(seconds, Ordering::SeqCst);
                }
                let mut reply = serde_json::Map::new();
                if let Some(seconds) = control.expires_in {
                    if !(1..=3600).contains(&seconds) {
                        return Err("expires_in out of range".into());
                    }
                    expires_in.store(seconds, Ordering::SeqCst);
                }
                if let Some(location) = control.approve {
                    // The person's approval: a POST signed as this Person
                    // Server under jwks_uri, as the native approval requires,
                    // with the expiry the host was told to set.
                    let mut decision = serde_json::json!({"decision": "approve"});
                    let seconds = expires_in.load(Ordering::SeqCst);
                    if seconds > 0 {
                        decision["expires_at"] = rfc3339(clock() + seconds).into();
                    }
                    let mut approval = Request::builder()
                        .method("POST")
                        .uri(format!("{location}/approval"))
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(&decision)?)?;
                    sign_request(
                        &mut approval,
                        &approver,
                        KeyMaterial::JwksUri {
                            id: config.person_server.clone(),
                            dwk: "aauth-person.json".into(),
                            kid: config.person_kid.clone(),
                        },
                        clock(),
                    )?;
                    let answer = sut.handle(&approval);
                    if answer.status() != 200 {
                        return Err(format!("native approval answered {}", answer.status()).into());
                    }
                    reply.insert("approved".into(), true.into());
                }
                if let Some(install) = control.install {
                    // Bind the approved document the native endpoint retained
                    // to the fixture person, for mission-bound issuance.
                    let owner = AgentIdentity {
                        issuer: config.issuer.clone(),
                        subject: install.agent,
                    };
                    let audit = store
                        .read_mission_audit(
                            &config.person_server,
                            &owner.issuer,
                            &owner.subject,
                            &install.s256,
                        )?
                        .ok_or("no approved mission is retained under that digest")?;
                    let document = ApprovedMission::decode(&audit.s256, &audit.encoded)
                        .map_err(|_| "retained mission does not decode")?;
                    store
                        .install_approved_mission(MissionRecord {
                            person_server: config.person_server.clone(),
                            owner,
                            person_id: "conformance-internal-person".into(),
                            document,
                            state: MissionState::Active,
                        })
                        .map_err(|e| e.to_string())?;
                    reply.insert("installed".into(), true.into());
                }
                Ok(serde_json::Value::Object(reply))
            })();
            let (status, body) = match outcome {
                Ok(body) => (200u16, body),
                Err(error) => (409u16, serde_json::json!({"error":error.to_string()})),
            };
            http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&body)?)?
        } else {
            sut.handle(&request)
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

/// Unix seconds as an RFC 3339 UTC time, such as `2026-11-02T08:30:00Z`.
fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}
