//! Serves the supervision server for remote mode, built with
//! `aauth-rust-supervision-server` at `names["supervision_server"]`. It signs
//! its decisions with a key generated at start and discovers each Person
//! Server's keys over HTTPS. Policy follows the remote-mode test profile: it
//! connects the Person Servers in `person_servers` and refuses every other
//! one whose signature verifies; it allows token and mission acts and the
//! permission `fixture.allow`, denies `fixture.deny`, asks for `fixture.ask`
//! and defers `fixture.defer` until the host control resolves it. Host
//! controls are served at `names["control"]/supervision.server/__fixture/supervision`:
//! `{"resolve": {"sdi", "verdict": "allow"}}` settles a deferred decision and
//! `{"rate_limit": true}` turns the next supervision request away.
use crate::https::Failure;
use crate::{Env, Route, json, now};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::{Act, Allowance, Ask, MissionTerms, SupervisionError};
use aauth_rust_jose::SigningKey;
use aauth_rust_supervision_server::{
    Case, Config, ConnectAnswer, ConnectRequest, Policy, SupervisionServer, Verdict,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// The test-profile policy.
struct ProfileSupervisor {
    accepted: Vec<String>,
}

impl Policy for ProfileSupervisor {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        if self.accepted.contains(&request.ps) {
            ConnectAnswer::Connected
        } else {
            ConnectAnswer::Refused
        }
    }
    fn decide(&self, case: &Case) -> Verdict {
        match case.act {
            Act::MissionProposal => {
                let description = case
                    .request
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                Verdict::Allow(Allowance {
                    mission: Some(MissionTerms::described(description)),
                    ..Allowance::default()
                })
            }
            Act::Permission => match case.action() {
                Some("fixture.deny") => Verdict::Deny(Some("Fixture denial.".into())),
                Some("fixture.ask") => Verdict::Ask(Ask {
                    summary: Some("Fixture question for the person.".into()),
                    ..Ask::default()
                }),
                Some("fixture.defer") => Verdict::Defer,
                _ => Verdict::Allow(Allowance::default()),
            },
            _ => Verdict::Allow(Allowance::default()),
        }
    }
}

fn answer(status: u16, value: serde_json::Value) -> http::Response<Vec<u8>> {
    json(status, value.to_string().into_bytes())
}

/// The supervision server's route and its host-control route.
pub fn routes(env: &Env) -> Result<Vec<Route>, Failure> {
    let Some(issuer) = env.c.names.get("supervision_server") else {
        return Ok(Vec::new());
    };
    let accepted = env.c.person_servers.clone();
    let server = Arc::new(
        SupervisionServer::new(
            Config::new(issuer).with_signing("rust-ss", SigningKey::generate()),
            env.keys.clone(),
            ProfileSupervisor {
                accepted: accepted.clone(),
            },
            MemoryContinuations::new(10_000),
            now,
        )
        .map_err(|_| "supervision server configuration")?,
    );
    let limit_next = Arc::new(AtomicBool::new(false));
    let mut routes = Vec::new();
    {
        let (server, limit_next) = (server.clone(), limit_next.clone());
        routes.push(Route::new(issuer, "/", move |request| {
            let path = request.uri().path();
            let supervised =
                path == "/decision" || path == "/event" || path.starts_with("/mission");
            // The host's own limit, answered with the library's rate_limited
            // response; the server itself never limits a Person Server.
            if supervised && limit_next.swap(false, Ordering::SeqCst) {
                return SupervisionError::RateLimited.response(Some(30));
            }
            server.handle(&request)
        }));
    }
    if let Some(control) = env.c.names.get("control") {
        routes.push(Route::new(
            control,
            "/supervision.server/__fixture/supervision",
            move |request| {
                if request.method() != http::Method::POST {
                    return answer(405, serde_json::json!({"error": "POST only"}));
                }
                let body: serde_json::Value = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => return answer(400, serde_json::json!({"error": error.to_string()})),
                };
                if body["rate_limit"] == true {
                    limit_next.store(true, Ordering::SeqCst);
                    return answer(200, serde_json::json!({"rate_limited": true}));
                }
                if body["resolve"]["verdict"] == "allow" {
                    let sdi = body["resolve"]["sdi"].as_str().unwrap_or_default();
                    return match accepted.iter().try_for_each(|ps| {
                        server.decide_pending(ps, sdi, Verdict::Allow(Allowance::default()))
                    }) {
                        Ok(()) => answer(200, serde_json::json!({"resolved": true})),
                        Err(error) => answer(409, serde_json::json!({"error": error.to_string()})),
                    };
                }
                answer(400, serde_json::json!({"error": "unknown host control"}))
            },
        ));
    }
    Ok(routes)
}
