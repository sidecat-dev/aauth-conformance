//! Serves the supervised Person Server for remote mode, the native
//! `PersonServer` with `with_supervision`, at
//! `names["supervised_person_server"]`. It routes every agent to the
//! supervision server at `names["supervisor"]`, which the suite plays, with
//! the person's identifier there `SUPERVISOR_SUBJECT`. It discovers that
//! server's keys over HTTPS and acts only on decisions signed by it. Its own
//! policy never decides: a supervised agent's acts are the supervisor's or
//! the person's. Host controls are served at
//! `names["control"]/supervision.person-server/__fixture/supervision`:
//! `{"deliver": true}` delivers queued events and reports, and
//! `{"resolve": "allow", "pending"}` or `{"advance": true, "pending"}`
//! answers for the person, or polls the supervisor, for the held act whose
//! pending URL is `pending`.
use crate::https::{Client, Failure};
use crate::{Env, PERSON_LIFETIME, Route, SUBJECT, host, ids, json, now};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::Answer;
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonAnswer,
    PersonRequest, PersonServer, Policy, PolicyError, Supervision, SupervisionConfig,
    SupervisionUnavailable,
};
use http::{Request, Response};
use std::sync::Arc;

/// The person's directed identifier at the supervisor, the fixture's.
const SUPERVISOR_SUBJECT: &str = "ss-directed-person-1";

/// Binds the profile person and decides nothing: every act of a routed
/// agent is the supervisor's.
struct NeverDecides;
impl Policy for NeverDecides {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "profile-person".into(),
            subject: SUBJECT.into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

/// Routes every agent to the one supervisor and reaches it over HTTPS.
struct ToSupervisor {
    supervisor: String,
    client: Arc<Client>,
}
impl Supervision for ToSupervisor {
    fn route(&self, _: &str, _: &AgentIdentity) -> Option<String> {
        Some(self.supervisor.clone())
    }
    fn subject(&self, _: &str, _: &str) -> String {
        SUPERVISOR_SUBJECT.into()
    }
    fn metadata(&self, supervisor: &str) -> Result<Vec<u8>, SupervisionUnavailable> {
        if supervisor != self.supervisor {
            return Err(SupervisionUnavailable);
        }
        self.client
            .get(&format!("{supervisor}/.well-known/aauth-supervisor.json"))
            .map_err(|error| {
                eprintln!("supervisor metadata: {error}");
                SupervisionUnavailable
            })
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, SupervisionUnavailable> {
        if request.uri().scheme_str() != Some("https")
            || request.uri().host() != Some(host(&self.supervisor))
            || request.uri().port().is_some()
        {
            return Err(SupervisionUnavailable);
        }
        self.client.send(request).map_err(|error| {
            eprintln!("supervisor: {error}");
            SupervisionUnavailable
        })
    }
}

fn answer(status: u16, value: serde_json::Value) -> Response<Vec<u8>> {
    json(status, value.to_string().into_bytes())
}

/// The supervised Person Server's route and its host-control route.
pub fn routes(env: &Env) -> Result<Vec<Route>, Failure> {
    let (Some(issuer), Some(supervisor)) = (
        env.c.names.get("supervised_person_server"),
        env.c.names.get("supervisor"),
    ) else {
        return Ok(Vec::new());
    };
    let mut config = Config::new(issuer, "rust-supervised-ps", SigningKey::generate());
    config.person_lifetime = PERSON_LIFETIME;
    let sut = Arc::new(
        PersonServer::new(
            config,
            env.keys.clone(),
            MemoryStore::default(),
            NeverDecides,
            now,
            ids("supervised"),
        )?
        // Missions are enabled so a supervised agent can propose one; the
        // supervisor approves it, never this policy.
        .with_missions()
        .with_supervision(SupervisionConfig::new(
            ToSupervisor {
                supervisor: supervisor.clone(),
                client: env.client.clone(),
            },
            MemoryContinuations::new(10_000),
        ))
        .map_err(|_| "supervision configuration")?,
    );
    let mut routes = Vec::new();
    {
        let sut = sut.clone();
        routes.push(Route::new(issuer, "/", move |request| sut.handle(&request)));
    }
    if let Some(control) = env.c.names.get("control") {
        let pending_prefix = format!("{issuer}/pending/");
        routes.push(Route::new(
            control,
            "/supervision.person-server/__fixture/supervision",
            move |request| {
                if request.method() != http::Method::POST {
                    return answer(405, serde_json::json!({"error": "POST only"}));
                }
                let body: serde_json::Value = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => {
                        return answer(400, serde_json::json!({"error": error.to_string()}));
                    }
                };
                if body["deliver"] == true {
                    return match sut.deliver_supervision() {
                        Ok(waiting) => answer(200, serde_json::json!({"undelivered_pairs": waiting})),
                        Err(error) => answer(409, serde_json::json!({"error": error.to_string()})),
                    };
                }
                if body["resolve"] != "allow" && body["advance"] != true {
                    return answer(400, serde_json::json!({"error": "unknown host control"}));
                }
                let Some(reference) = body["pending"]
                    .as_str()
                    .and_then(|pending| pending.strip_prefix(&pending_prefix))
                    .filter(|reference| !reference.is_empty() && !reference.contains('/'))
                else {
                    return answer(
                        400,
                        serde_json::json!({"error": "pending must be a held act's URL on this server"}),
                    );
                };
                let outcome = if body["advance"] == true {
                    sut.advance_supervision(reference).map(|_| ())
                } else {
                    // The person answers without a reason, which the draft never requires.
                    sut.resolve_supervision(reference, PersonAnswer::once(Answer::Allow))
                };
                match outcome {
                    Ok(()) => answer(200, serde_json::json!({"reference": reference})),
                    Err(error) => answer(409, serde_json::json!({"error": error.to_string()})),
                }
            },
        ));
    }
    Ok(routes)
}
