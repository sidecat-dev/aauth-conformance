//! Serves AAuth Events roles for remote mode, from aauth-rust's native
//! types: the subscription and delivering Resource (`EventsResource`), the
//! Agent Provider's event endpoint (`AgentProvider`, `EventInbox`) and an
//! Agent's event check (`verify_event`). Names keys: "events_resource" and
//! "agent_provider"; the Agent is `aauth:agent@` followed by the Agent
//! Provider's host. Host controls are under `names["control"]`, one path
//! prefix per suite role.
use crate::https::{Client, Failure};
use crate::{Discovery, Env, Route, host, ids, json, now};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{EventInbox, EventStore, MemoryEventStore, SubscribeRequest};
use aauth_rust_core::{AgentClaims, Confirmation, PersonToken};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::events::{
    EventPayload, EventsConfig, EventsResource, MemorySubscriptionStore,
    agent_provider_metadata_url,
};
use http::{Request, Response};
use serde::Deserialize;
use serde_json::{Value, json as value};
use std::sync::Arc;

const SUBSCRIPTION_PATH: &str = "/events/subscribe";
const TICKET_PATH: &str = "/events/tickets/";

type Resource = EventsResource<Discovery, MemorySubscriptionStore>;
type Inbox = EventInbox<Discovery, MemoryEventStore>;

fn failure(error: impl std::fmt::Display) -> Failure {
    error.to_string().into()
}

/// Answers a host control: its JSON result, or 422 with the error.
fn control<T: for<'de> Deserialize<'de>>(
    request: &Request<Vec<u8>>,
    run: impl FnOnce(T) -> Result<Value, Failure>,
) -> Response<Vec<u8>> {
    match serde_json::from_slice::<T>(request.body())
        .map_err(failure)
        .and_then(run)
    {
        Ok(result) => json(200, result.to_string().into_bytes()),
        Err(error) => json(
            422,
            value!({ "error": error.to_string() }).to_string().into_bytes(),
        ),
    }
}

pub fn routes(env: &Env) -> Result<Vec<Route>, Failure> {
    let mut routes = Vec::new();
    let controls = env.c.names.get("control");
    if let Some(issuer) = env.c.names.get("events_resource") {
        let resource = Arc::new(EventsResource::new(
            EventsConfig {
                issuer: issuer.clone(),
                signed_origin: issuer.clone(),
                kid: "rust-events-resource".into(),
                signing_key: SigningKey::generate(),
                ticket_path: TICKET_PATH.into(),
                max_ticket_lifetime: 300,
            },
            env.keys.clone(),
            MemorySubscriptionStore::new(),
        )?);
        let served = resource.clone();
        let metadata = value!({ "issuer": issuer, "jwks_uri": format!("{issuer}/.well-known/jwks.json") });
        routes.push(Route::new(issuer, "/", move |request| {
            match request.uri().path() {
                "/.well-known/aauth-resource.json" => json(200, metadata.to_string().into_bytes()),
                "/.well-known/jwks.json" => match served.jwks() {
                    Ok(body) => json(200, body),
                    Err(_) => json(500, Vec::new()),
                },
                SUBSCRIPTION_PATH => served.register(&request, now(), |_| Ok(Vec::new())).into_response(),
                path if path.starts_with(TICKET_PATH) => served
                    .register_with_ticket(&request, now(), |_| Ok(Vec::new()))
                    .into_response(),
                _ => json(404, Vec::new()),
            }
        }));
        if let Some(control_origin) = controls {
            routes.push(ticket_control(control_origin, resource.clone(), env.keys.clone()));
            routes.push(fire_control(
                control_origin,
                resource,
                env.client.clone(),
                env.c.agent_providers.clone(),
            ));
        }
    }
    if let Some(issuer) = env.c.names.get("agent_provider") {
        let provider = Arc::new(
            AgentProvider::new(issuer, "rust-ap", SigningKey::generate())?
                .with_event_endpoint(&format!("{issuer}/events"))?,
        );
        let inbox = Arc::new(EventInbox::new(&provider, env.keys.clone(), MemoryEventStore::new())?);
        let agent = format!("aauth:agent@{}", host(issuer));
        let (served, receiving) = (provider.clone(), inbox.clone());
        routes.push(Route::new(issuer, "/", move |request| {
            match (request.method().as_str(), request.uri().path()) {
                ("GET", "/.well-known/aauth-agent.json") => match served.metadata() {
                    Ok(body) => json(200, body),
                    Err(_) => json(500, Vec::new()),
                },
                ("GET", "/.well-known/jwks.json") => match served.jwks() {
                    Ok(body) => json(200, body),
                    Err(_) => json(500, Vec::new()),
                },
                (_, "/events") => receiving.receive(&request, now()).into_response(),
                _ => json(404, Vec::new()),
            }
        }));
        if let Some(control_origin) = controls {
            routes.extend(provider_controls(
                control_origin,
                issuer.clone(),
                provider,
                inbox,
                agent.clone(),
            ));
            routes.push(agent_control(control_origin, env.keys.clone(), agent));
        }
    }
    Ok(routes)
}

/// Protected Subscriptions step 2: the Resource issues a ticket while
/// serving a request verified with a person token; the control verifies the
/// token natively and issues the ticket from it.
fn ticket_control(origin: &str, resource: Arc<Resource>, keys: Discovery) -> Route {
    #[derive(Deserialize)]
    struct Job {
        person_token: String,
    }
    Route::new(origin, "/events.subscription/__fixture/ticket", move |request| {
        control(&request, |job: Job| {
            let person = PersonToken::parse(&job.person_token)
                .map_err(failure)?
                .verify(&keys, now())
                .map_err(failure)?;
            let ticket = resource
                .issue_ticket(&person, b"conformance fixture", 120, now())
                .map_err(failure)?;
            Ok(value!({ "url": ticket.url }))
        })
    })
}

/// Event Delivery: the native Resource prepares and signs one event; the
/// host resolves the AP's metadata and sends the request unchanged.
fn fire_control(
    origin: &str,
    resource: Arc<Resource>,
    client: Arc<Client>,
    providers: Vec<String>,
) -> Route {
    #[derive(Deserialize)]
    struct Fire {
        agent_provider: String,
        eid: String,
        body: bool,
    }
    Route::new(origin, "/events.delivery/__fixture/fire", move |request| {
        control(&request, |job: Fire| {
            if !providers.contains(&job.agent_provider) {
                return Err("not a trusted Agent Provider".into());
            }
            let payload = job.body.then_some(EventPayload {
                content_type: "application/json",
                body: br#"{"event_type":"slot.available"}"#,
            });
            let at = now();
            let event = resource
                .prepare_event(&job.agent_provider, &job.eid, payload, at + 300, at)
                .map_err(failure)?;
            let metadata = client.get(&agent_provider_metadata_url(&job.agent_provider))?;
            let delivery = resource
                .delivery_request(&event, &metadata, at)
                .map_err(failure)?;
            let response = client.send(&delivery)?;
            Ok(value!({ "status": response.status().as_u16() }))
        })
    })
}

/// Subscribe token acquisition is AP-internal (Events, Protocol Overview):
/// the subscribe control stands for the Agent's request and names its key;
/// the pending control is the AP-to-Agent read path.
fn provider_controls(
    origin: &str,
    issuer: String,
    provider: Arc<AgentProvider>,
    inbox: Arc<Inbox>,
    agent: String,
) -> Vec<Route> {
    #[derive(Deserialize)]
    struct Subscribe {
        max_uses: u64,
        agent: String,
        agent_jwk: Jwk,
        resource: String,
    }
    #[derive(Deserialize)]
    struct Pending {
        agent: String,
    }
    let token_ids = ids("events-agent-token");
    let (issuing, issued_into, own) = (provider, inbox.clone(), agent.clone());
    let subscribe = Route::new(origin, "/events.agent-provider/__fixture/subscribe", move |request| {
        control(&request, |job: Subscribe| {
            if job.agent != own {
                return Err(format!("this Agent Provider serves only {own}").into());
            }
            let at = now();
            // The Agent token native issuance requires; its key is the Agent's.
            let agent_token = issuing
                .issue(&AgentClaims {
                    iss: issuer.clone(),
                    dwk: "aauth-agent.json".into(),
                    sub: job.agent.clone(),
                    jti: token_ids(),
                    iat: at - 10,
                    exp: at + 3600,
                    cnf: Confirmation { jwk: job.agent_jwk },
                    ps: None,
                    parent_agent: None,
                    nbf: None,
                    extra: Default::default(),
                })
                .map_err(failure)?;
            let issued = issuing
                .issue_subscribe_token(
                    issued_into.store(),
                    &SubscribeRequest {
                        agent_token: &agent_token,
                        resource: &job.resource,
                        expires_at: at + 600,
                        max_uses: (job.max_uses > 0).then_some(job.max_uses),
                        subscription_expires_at: None,
                    },
                    at,
                )
                .map_err(failure)?;
            Ok(value!({ "token": issued.token }))
        })
    });
    let pending = Route::new(origin, "/events.agent-provider/__fixture/pending", move |request| {
        control(&request, |job: Pending| {
            if job.agent != agent {
                return Err(format!("this Agent Provider serves only {agent}").into());
            }
            let events = inbox
                .store()
                .pending(&job.agent)
                .map_err(failure)?
                .into_iter()
                .map(|event| {
                    Ok(value!({
                        "event_token": event.event_token,
                        "body": String::from_utf8(event.body).map_err(failure)?,
                    }))
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            Ok(value!({ "events": events }))
        })
    });
    vec![subscribe, pending]
}

/// The Agent's native event check on one AP-forwarded token and body.
fn agent_control(origin: &str, keys: Discovery, agent: String) -> Route {
    #[derive(Deserialize)]
    struct Job {
        event_token: String,
        body: String,
    }
    Route::new(origin, "/events.agent/__fixture/event", move |request| {
        control(&request, |job: Job| {
            Ok(
                match aauth_rust_agent::verify_event(&job.event_token, job.body.as_bytes(), &agent, &keys, now()) {
                    Ok(_) => value!({ "accepted": true }),
                    Err(error) => value!({ "accepted": false, "error": error.to_string() }),
                },
            )
        })
    })
}
