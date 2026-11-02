//! Serves the R3 Resource of each topology and the three-party R3 issuer
//! for remote mode. Names come from the roles file
//! (deployments/roles/r3.json):
//!
//! - `r3_resource`: four-party R3 Resource; its Access Server is
//!   `suite_access_server`.
//! - `r3_direct_resource`: three-party R3 Resource; its Person Servers are
//!   `person_servers`.
//! - `r3_person_server`: three-party Person Server issuing R3 Auth tokens.
//!
//! aauth-rust's Access Server offers no R3 issuance, so there is no
//! four-party R3 issuer here. Policy follows the remote mode test profile:
//! the person directed-person-1, the read scope, the MCP tools
//! records.read, records.export and records.delete, of which records.read
//! and records.export are granted. `GET
//! /r3.resource/__fixture/r3/executions` on the control origin reports how
//! often each tool executed, across both Resources.
use crate::https::{Client, Failure};
use crate::{Env, ProfilePolicy, Route, SUBJECT, ids, json, now};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    Config as PersonConfig, MemoryStore, PersonServer, PolicyError, R3AuthorizationRequest,
    R3Decision, R3IssuerConfig,
};
use aauth_rust_r3::{
    DefinitionRegistry, Display, FetchBody, FetchLimits, FetchResponse, FetchTransport,
    GrantedOperations, IssuanceError, IssuanceRecord, IssuanceStore, McpCodec, Operation,
    Parameter, Parameters, PresentedParameter, ProposalDisplay, ToolsListPage, ToolsListSnapshot,
    standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, PsAuthorizationConfig, PsAuthorizationResource, R3CallDescription, R3CallResult,
    R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord, R3DocumentStore, R3HostError,
    R3PerCallConfig, R3ProposalRecord, R3StoreError, R3Vocabulary,
};
use aauth_rust_core::VerifiedAuthToken;
use http::{Request, Response};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

const TOOLS: [&str; 3] = ["records.read", "records.export", "records.delete"];
const GRANTABLE: [&str; 2] = ["records.read", "records.export"];

type Executions = Arc<Mutex<BTreeMap<String, u64>>>;

/// The routes this module serves; none until its names are configured.
pub fn routes(env: &Env) -> Result<Vec<Route>, Failure> {
    let names = &env.c.names;
    let mut routes = Vec::new();
    let executions = Executions::default();
    for (key, federated) in [("r3_resource", true), ("r3_direct_resource", false)] {
        if let Some(issuer) = names.get(key) {
            routes.push(resource(env, issuer, federated, executions.clone())?);
        }
    }
    if let Some(control) = names.get("control")
        && (names.contains_key("r3_resource") || names.contains_key("r3_direct_resource"))
    {
        routes.push(Route::new(
            control,
            "/r3.resource/__fixture/r3/executions",
            move |_: Request<Vec<u8>>| match executions.lock() {
                Ok(counts) => json(200, serde_json::json!(*counts).to_string().into_bytes()),
                Err(_) => json(500, Vec::new()),
            },
        ));
    }
    if let Some(issuer) = names.get("r3_person_server") {
        routes.push(issuer_route(env, issuer)?);
    }
    Ok(routes)
}

fn mcp(tool: &str) -> Result<Operation, R3HostError> {
    let vocabulary = McpCodec::vocabulary().map_err(|e| R3HostError::new(e.to_string()))?;
    let raw = serde_json::to_vec(&serde_json::json!({ "tool": tool }))
        .map_err(|e| R3HostError::new(e.to_string()))?;
    Operation::new(&vocabulary, &raw).map_err(|e| R3HostError::new(e.to_string()))
}

fn resource(
    env: &Env,
    issuer: &str,
    federated: bool,
    executions: Executions,
) -> Result<Route, Failure> {
    let tools: Vec<serde_json::Value> = TOOLS
        .iter()
        .map(|tool| serde_json::json!({"name": tool, "inputSchema": {"type": "object"}}))
        .collect();
    let tools_json = serde_json::to_vec(&serde_json::json!({ "tools": tools }))?;
    let config = PsAuthorizationConfig {
        issuer: issuer.to_owned(),
        signed_origin: issuer.to_owned(),
        kid: if federated { "rust-r3-resource" } else { "rust-r3-direct-resource" }.into(),
        signing_key: SigningKey::generate(),
        scopes: vec!["read".into()],
        scope_descriptions: [("read".into(), "Fixture scope read".into())].into(),
    };
    let people = env.c.person_servers.clone();
    let policy = move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
        people.contains(&token.claims().ps) && token.claims().sub == SUBJECT
    };
    let native = if federated {
        let access = env
            .c
            .names
            .get("suite_access_server")
            .ok_or("r3_resource needs suite_access_server")?;
        PsAuthorizationResource::new_federated(config, access, env.keys.clone(), policy)?
    } else {
        PsAuthorizationResource::new(config, env.keys.clone(), policy)?
    };
    let native = native.with_authorization_endpoint().with_r3(R3Config {
        registry: standard_registry()?,
        definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
        vocabularies: vec![R3Vocabulary {
            definition: McpCodec::parse_definition(
                &format!("{issuer}/mcp"),
                &ToolsListSnapshot::new(vec![ToolsListPage::initial(&tools_json)]),
            )?,
            display: Some(Box::new(|_: &aauth_rust_r3::OperationSet| {
                Display::new(
                    "Use fixture records",
                    Some("Records may be exported"),
                    Some("Record contents"),
                    Some("Exported copies cannot be recalled"),
                )
                .map_err(|e| R3HostError::new(e.to_string()))
            })),
        }],
        documents: Arc::new(MemoryDocuments::default()),
        operation_for_request: Box::new(|request: &Request<Vec<u8>>| {
            match request.uri().path().strip_prefix("/op/") {
                Some(tool) if TOOLS.contains(&tool) => mcp(tool).map(Some),
                _ => Ok(None),
            }
        }),
        require_core_scope: false,
    })?;
    // Per-call proposals run on the four-party composition, as in Go.
    let native = if federated {
        native.with_r3_per_call(per_call_config())?
    } else {
        native
    };
    let jti = ids(if federated { "r3" } else { "r3-direct" });
    Ok(Route::new(issuer, "/", move |request: Request<Vec<u8>>| {
        let path = request.uri().path().to_owned();
        match path.as_str() {
            "/.well-known/aauth-resource.json" => match native.metadata() {
                Ok(body) => json(200, body),
                Err(_) => json(500, Vec::new()),
            },
            "/.well-known/jwks.json" => match native.jwks() {
                Ok(body) => json(200, body),
                Err(_) => json(500, Vec::new()),
            },
            "/authorize" => native
                .authorize_endpoint(&request, now(), &jti())
                .into_response(),
            p if p.starts_with("/r3/") => native.r3_document(&request, now()),
            p if p.starts_with("/op/") => match native.authorize(&request, now(), &jti()) {
                AuthDecision::Granted(admitted) => {
                    let tool = p.trim_start_matches("/op/").to_owned();
                    if let Ok(mut counts) = executions.lock() {
                        *counts.entry(tool.clone()).or_default() += 1;
                    }
                    let produced = json(
                        200,
                        serde_json::json!({"operation": tool, "sub": admitted.token().claims().sub})
                            .to_string()
                            .into_bytes(),
                    );
                    // A per-call completion keeps its one result for replay.
                    match admitted.r3_grant() {
                        Some(grant) if grant.is_per_call() => native.r3_retain(grant, produced),
                        _ => produced,
                    }
                }
                other => other.into_response(),
            },
            _ => json(404, Vec::new()),
        }
    }))
}

fn issuer_route(env: &Env, issuer: &str) -> Result<Route, Failure> {
    let mut config = PersonConfig::new(issuer, "rust-r3-ps", SigningKey::generate());
    config.person_lifetime = crate::PERSON_LIFETIME;
    let prefixes: Vec<String> = env.c.resources.iter().map(|r| format!("{r}/r3/")).collect();
    let native = PersonServer::new(
        config,
        env.keys.clone(),
        MemoryStore::default(),
        ProfilePolicy,
        now,
        ids("r3-ps"),
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(move |uri: &str, _deadline: Instant| -> io::Result<()> {
            if prefixes.iter().any(|prefix| uri.starts_with(prefix)) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "R3 document endpoint is not admitted",
                ))
            }
        }),
        transport: Box::new(HttpsFetch(env.client.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(
            |request: &R3AuthorizationRequest<'_>| -> Result<R3Decision, PolicyError> {
                if !crate::read_only(&request.core.scopes) {
                    return Err(PolicyError::Denied);
                }
                let mut chosen = Vec::new();
                for operation in request
                    .document
                    .operation_set()
                    .operations()
                    .map_err(unavailable)?
                {
                    let value: serde_json::Value =
                        serde_json::from_slice(&operation.json().map_err(unavailable)?)
                            .map_err(unavailable)?;
                    if value["tool"]
                        .as_str()
                        .is_some_and(|tool| GRANTABLE.contains(&tool))
                    {
                        chosen.push(operation);
                    }
                }
                let vocabulary = McpCodec::vocabulary().map_err(unavailable)?;
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocabulary, &chosen).map_err(unavailable)?,
                    per_call: None,
                    scopes: request.core.scopes.clone(),
                    lifetime: crate::AUTH_LIFETIME,
                })
            },
        ),
        audit: Arc::new(MemoryAudit::default()),
    })?;
    Ok(Route::new(issuer, "/", move |request: Request<Vec<u8>>| {
        native.handle(&request)
    }))
}

fn unavailable<E>(_: E) -> PolicyError {
    PolicyError::Unavailable
}

/// The PS's signed R3 fetch over this deployment's HTTPS client, unchanged.
struct HttpsFetch(Arc<Client>);
struct Buffered(Vec<u8>, usize);
impl FetchBody for Buffered {
    fn read(&mut self, output: &mut [u8], deadline: Instant) -> io::Result<usize> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let count = (self.0.len() - self.1).min(output.len());
        output[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
        self.1 += count;
        Ok(count)
    }
}
impl FetchTransport for HttpsFetch {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let response = self
            .0
            .send(&request)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

/// In-memory document custody with the exact-repeat and conflict contract.
#[derive(Default)]
struct MemoryDocuments(Mutex<BTreeMap<String, R3DocumentRecord>>);
impl R3DocumentStore for MemoryDocuments {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        let mut records = self.0.lock().map_err(poisoned)?;
        match records.get(record.reference.uri()) {
            Some(existing) if existing == record => Ok(()),
            Some(_) => Err(R3StoreError::Conflict),
            None => {
                records.insert(record.reference.uri().into(), record.clone());
                Ok(())
            }
        }
    }
    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError> {
        Ok(self.0.lock().map_err(poisoned)?.get(uri).cloned())
    }
}

fn poisoned<T>(_: T) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new("poisoned"))
}

/// In-memory proposal custody: each URI is created once; the first claim by a
/// token gets one fenced execution and the same token later replays the
/// retained result. Release gating is not configured, so nothing is held.
#[derive(Default)]
struct MemoryCalls(Mutex<CallState>);
#[derive(Default)]
struct CallState {
    records: BTreeMap<String, CallEntry>,
    fences: u64,
}
struct CallEntry {
    record: R3ProposalRecord,
    token: Option<R3CallToken>,
    fence: Option<String>,
    result: Option<R3CallResult>,
}
impl R3CallStore for MemoryCalls {
    fn commit(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError> {
        let mut state = self.0.lock().map_err(poisoned)?;
        if state.records.contains_key(record.reference.uri()) {
            return Err(R3StoreError::Conflict);
        }
        state.records.insert(
            record.reference.uri().into(),
            CallEntry {
                record: record.clone(),
                token: None,
                fence: None,
                result: None,
            },
        );
        Ok(())
    }
    fn load(&self, uri: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        let state = self.0.lock().map_err(poisoned)?;
        Ok(state.records.get(uri).map(|entry| entry.record.clone()))
    }
    fn load_pending(&self, pending_id: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        let state = self.0.lock().map_err(poisoned)?;
        Ok(state
            .records
            .values()
            .find(|entry| {
                entry
                    .record
                    .held
                    .as_ref()
                    .is_some_and(|held| held.pending_id == pending_id)
            })
            .map(|entry| entry.record.clone()))
    }
    fn claim(&self, uri: &str, token: &R3CallToken, now: i64) -> Result<R3Claim, R3StoreError> {
        let mut state = self.0.lock().map_err(poisoned)?;
        state.fences += 1;
        let fence = format!("r3-fence-{}", state.fences);
        let entry = state
            .records
            .get_mut(uri)
            .ok_or_else(|| R3StoreError::Unavailable(R3HostError::new("unknown proposal")))?;
        if entry.token.is_none() {
            entry.token = Some(token.clone());
            entry.fence = Some(fence.clone());
            return Ok(R3Claim::Execute { fence });
        }
        let bound = entry.token.as_ref().expect("token bound above");
        if bound.compact_sha256 != token.compact_sha256 {
            return Ok(R3Claim::DifferentToken);
        }
        Ok(match &entry.result {
            Some(_) if now >= bound.retain_until => R3Claim::Expired,
            Some(result) => R3Claim::Replay(result.clone()),
            None => R3Claim::Unfinished,
        })
    }
    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> Result<R3CallResult, R3StoreError> {
        let mut state = self.0.lock().map_err(poisoned)?;
        let entry = state.records.get_mut(uri).ok_or(R3StoreError::Conflict)?;
        if entry.fence.as_deref() != Some(fence) || entry.result.is_some() {
            return Err(R3StoreError::Conflict);
        }
        entry.result = Some(result.clone());
        Ok(result.clone())
    }
    fn held_releases(
        &self,
        _: &str,
        _: &str,
        _: i64,
    ) -> Result<Vec<R3ProposalRecord>, R3StoreError> {
        Ok(Vec::new())
    }
    fn supersede(&self, _: &str, _: &R3ProposalRecord, _: i64) -> Result<(), R3StoreError> {
        Err(R3StoreError::Conflict)
    }
}

/// The call's concrete parameter: its body's record value, as exact JSON.
fn record_parameter(request: &Request<Vec<u8>>) -> Result<Vec<u8>, R3HostError> {
    let body: serde_json::Value = serde_json::from_slice(request.body())
        .map_err(|_| R3HostError::new("call body must be JSON"))?;
    let record = body
        .get("record")
        .ok_or_else(|| R3HostError::new("call body needs a record"))?;
    serde_json::to_vec(record).map_err(|e| R3HostError::new(e.to_string()))
}

fn per_call_config() -> R3PerCallConfig {
    let host = |e: aauth_rust_r3::Error| R3HostError::new(e.to_string());
    R3PerCallConfig {
        present: Box::new(move |request: &Request<Vec<u8>>, _: &Operation| {
            let presented =
                PresentedParameter::inline(&record_parameter(request)?).map_err(host)?;
            Ok(BTreeMap::from([("record".to_owned(), presented)]))
        }),
        describe: Box::new(
            move |_: &Operation,
                  presented: &BTreeMap<String, PresentedParameter>,
                  _: Option<&str>| {
                let record = presented
                    .get("record")
                    .and_then(PresentedParameter::inline_json)
                    .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                let parameters = Parameters::new([(
                    "record".to_owned(),
                    Parameter::inline(&record).map_err(host)?,
                )])
                .map_err(host)?;
                let shown = String::from_utf8_lossy(&record).into_owned();
                let display = ProposalDisplay::new(
                    &Display::new(
                        format!("Delete fixture record {shown}"),
                        Some("The record is removed"),
                        None,
                        Some("Deletion cannot be undone"),
                    )
                    .map_err(host)?,
                    Some("## Action\nDelete a fixture record"),
                )
                .map_err(host)?;
                Ok(R3CallDescription {
                    parameters,
                    display: Some(display),
                })
            },
        ),
        calls: Arc::new(MemoryCalls::default()),
        hold: false,
        release: None,
        held_result_lifetime: 0,
    }
}

/// Volatile R3 audit log with the exact-repeat and conflict contract.
#[derive(Default)]
struct MemoryAudit(Mutex<Vec<IssuanceRecord>>);
impl IssuanceStore for MemoryAudit {
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError> {
        let mut records = self
            .0
            .lock()
            .map_err(|_| IssuanceError::Store("audit lock poisoned".into()))?;
        match records.iter().find(|existing| {
            existing.auth_token_issuer == record.auth_token_issuer
                && existing.auth_token_jti == record.auth_token_jti
        }) {
            Some(existing) if existing == record => Ok(()),
            Some(_) => Err(IssuanceError::Conflict),
            None => {
                records.push(record.clone());
                Ok(())
            }
        }
    }
}
