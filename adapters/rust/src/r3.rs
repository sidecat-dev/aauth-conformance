//! R3 launchers: a native Resource with class R3, and a native three-party
//! Person Server issuing R3 Auth tokens. Trust and policy are fixed host
//! configuration; no token, proof or R3 document is parsed, minted or
//! repaired here.
use super::{Bootstrap, FixturePolicy, PersonKeys, fetch, person_request};
use aauth_rust_core::{
    AgentKeyResolver, AgentProviderKeys, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
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
    AuthDecision, PsAuthorizationConfig, PsAuthorizationResource, R3CallDescription,
    R3CallResult, R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord, R3DocumentStore,
    R3HostError, R3PerCallConfig, R3ProposalRecord, R3StoreError, R3Vocabulary,
};
use http::{Request, Response};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct Extension {
    #[serde(default)]
    topology: String,
    #[serde(default)]
    resource_seed_hex: String,
    resource_kid: String,
    resource_jwk: serde_json::Value,
    person_server: String,
    #[serde(default)]
    person_seed_hex: String,
    person_kid: String,
    person_jwk: serde_json::Value,
    person_subject: String,
    person_lifetime: i64,
    auth_lifetime: i64,
    permitted_scopes: Vec<String>,
    access_server: String,
    access_kid: String,
    access_jwk: serde_json::Value,
    other_server: String,
    other_kid: String,
    other_jwk: serde_json::Value,
    tools: Vec<String>,
    grantable: Vec<String>,
    #[serde(default)]
    r3_transport: String,
}

pub(super) fn run(config: Bootstrap) -> Result<(), Failure> {
    let extension: Extension = serde_json::from_value(config.extension.clone())?;
    if config.role == "r3.issuer" {
        return run_issuer(&config, extension);
    }
    run_resource(&config, extension)
}

/// Trusted snapshots of the AP and of each server role this launcher admits.
struct R3Keys {
    ap: AgentProviderKeys,
    roles: Vec<(String, String, TrustedIssuerKeys)>,
}
impl AgentKeyResolver for R3Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if dwk == "aauth-agent.json" {
            return self.ap.key(issuer, dwk, kid);
        }
        self.roles
            .iter()
            .find(|(id, role, _)| id == issuer && role == dwk)
            .ok_or(TokenError::UntrustedIssuer)?
            .2
            .key(issuer, dwk, kid)
    }
}

fn trusted(
    issuer: &str,
    role: &str,
    kid: &str,
    jwk: &serde_json::Value,
) -> Result<(String, String, TrustedIssuerKeys), Failure> {
    let metadata = serde_json::to_vec(&serde_json::json!({
        "issuer":issuer, "jwks_uri":format!("{issuer}/.well-known/jwks.json")
    }))?;
    let mut jwk = jwk.clone();
    jwk.as_object_mut()
        .ok_or("JWK must be an object")?
        .insert("kid".into(), kid.into());
    let jwks = serde_json::to_vec(&serde_json::json!({"keys":[jwk]}))?;
    Ok((
        issuer.into(),
        role.into(),
        TrustedIssuerKeys::from_documents(issuer, role, &metadata, &jwks)?,
    ))
}

fn signing_key(hex: &str) -> Result<SigningKey, Failure> {
    if !hex.is_ascii() || hex.len() != 64 {
        return Err("fixture seed must be 32-byte hex".into());
    }
    let mut seed = [0; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)?;
    }
    Ok(SigningKey::from_seed(seed))
}

fn origin(resource: &str) -> Result<String, Failure> {
    let target: http::Uri = resource.parse()?;
    Ok(format!(
        "{}://{}",
        target.scheme_str().ok_or("missing Resource scheme")?,
        target.authority().ok_or("missing Resource authority")?
    ))
}

fn agent_provider(config: &Bootstrap) -> Result<AgentProviderKeys, Failure> {
    Ok(AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?)
}

fn mcp(tool: &str) -> Result<Operation, R3HostError> {
    let vocabulary = McpCodec::vocabulary().map_err(|e| R3HostError::new(e.to_string()))?;
    let raw = serde_json::to_vec(&serde_json::json!({ "tool": tool }))
        .map_err(|e| R3HostError::new(e.to_string()))?;
    Operation::new(&vocabulary, &raw).map_err(|e| R3HostError::new(e.to_string()))
}

/// In-memory document custody for one launcher process. It keeps the
/// exact-repeat and conflict contract; durability is outside this test.
#[derive(Default)]
struct MemoryDocuments(Mutex<BTreeMap<String, R3DocumentRecord>>);
impl R3DocumentStore for MemoryDocuments {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        let mut records = self
            .0
            .lock()
            .map_err(|_| R3StoreError::Unavailable(R3HostError::new("poisoned")))?;
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
        Ok(self
            .0
            .lock()
            .map_err(|_| R3StoreError::Unavailable(R3HostError::new("poisoned")))?
            .get(uri)
            .cloned())
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
        match &entry.token {
            None => {
                entry.token = Some(token.clone());
                entry.fence = Some(fence.clone());
                Ok(R3Claim::Execute { fence })
            }
            Some(bound) if bound.compact_sha256 != token.compact_sha256 => {
                Ok(R3Claim::DifferentToken)
            }
            Some(bound) => match &entry.result {
                Some(_) if now >= bound.retain_until => Ok(R3Claim::Expired),
                Some(result) => Ok(R3Claim::Replay(result.clone())),
                None => Ok(R3Claim::Unfinished),
            },
        }
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
            let presented = PresentedParameter::inline(&record_parameter(request)?).map_err(host)?;
            Ok(BTreeMap::from([("record".to_owned(), presented)]))
        }),
        describe: Box::new(
            move |_: &Operation, presented: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
                let record = presented
                    .get("record")
                    .and_then(PresentedParameter::inline_json)
                    .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                let parameters =
                    Parameters::new([("record".to_owned(), Parameter::inline(&record).map_err(host)?)])
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

fn respond(incoming: tiny_http::Request, response: Response<Vec<u8>>) -> Result<(), Failure> {
    let mut wire = tiny_http::Response::from_data(response.body().clone())
        .with_status_code(response.status().as_u16());
    for (name, value) in response.headers() {
        wire.add_header(
            tiny_http::Header::from_bytes(name.as_str().as_bytes(), value.as_bytes())
                .map_err(|_| "invalid response header")?,
        );
    }
    incoming.respond(wire)?;
    Ok(())
}

fn json_response(status: u16, value: serde_json::Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .expect("static response")
}

fn listen(config: &Bootstrap) -> Result<tiny_http::Server, Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    let target: http::Uri = config.resource.parse()?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{}",target.path())})
    );
    std::io::stdout().flush()?;
    Ok(server)
}

fn run_resource(config: &Bootstrap, x: Extension) -> Result<(), Failure> {
    let resource_issuer = origin(&config.resource)?;
    let resource_key = signing_key(&x.resource_seed_hex)?;
    let own = serde_json::to_value(resource_key.public_jwk())?;
    // The Resource's own key, the PS and AS it trusts, and one further trusted
    // server that no document entitles.
    let keys = R3Keys {
        ap: agent_provider(config)?,
        roles: vec![
            trusted(&resource_issuer, "aauth-resource.json", &x.resource_kid, &own)?,
            trusted(&x.person_server, "aauth-person.json", &x.person_kid, &x.person_jwk)?,
            trusted(&x.access_server, "aauth-access.json", &x.access_kid, &x.access_jwk)?,
            trusted(&x.other_server, "aauth-access.json", &x.other_kid, &x.other_jwk)?,
        ],
    };
    let tools: Vec<serde_json::Value> = x
        .tools
        .iter()
        .map(|tool| serde_json::json!({"name": tool, "inputSchema": {"type": "object"}}))
        .collect();
    let tools_json = serde_json::to_vec(&serde_json::json!({ "tools": tools }))?;
    let resource_config = PsAuthorizationConfig {
        issuer: resource_issuer.clone(),
        signed_origin: resource_issuer.clone(),
        kid: x.resource_kid.clone(),
        signing_key: resource_key,
        scopes: x.permitted_scopes.clone(),
        scope_descriptions: x
            .permitted_scopes
            .iter()
            .map(|scope| (scope.clone(), format!("Fixture scope {scope}")))
            .collect(),
    };
    let person_server = x.person_server.clone();
    let policy = move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
        token.claims().ps == person_server
    };
    let resource = if x.topology == "three-party" {
        PsAuthorizationResource::new(resource_config, keys, policy)?
    } else {
        PsAuthorizationResource::new_federated(resource_config, &x.access_server, keys, policy)?
    };
    let known = x.tools.clone();
    let resource = resource.with_authorization_endpoint().with_r3(R3Config {
        registry: standard_registry()?,
        definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
        vocabularies: vec![R3Vocabulary {
            definition: McpCodec::parse_definition(
                &format!("{resource_issuer}/mcp"),
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
        operation_for_request: Box::new(move |request: &Request<Vec<u8>>| {
            match request.uri().path().strip_prefix("/op/") {
                Some(tool) if known.iter().any(|known| known == tool) => mcp(tool).map(Some),
                _ => Ok(None),
            }
        }),
        require_core_scope: false,
    })?;
    // Per-call proposals run on the four-party composition, as in Go.
    let resource = if x.topology == "three-party" {
        resource
    } else {
        resource.with_r3_per_call(per_call_config())?
    };
    let server = listen(config)?;
    let sequence = AtomicU64::new(0);
    let mut executions: BTreeMap<String, u64> = BTreeMap::new();
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let jti = format!("r3-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1);
        let path = request.uri().path().to_owned();
        let response = match path.as_str() {
            "/.well-known/aauth-resource.json" => match resource.metadata() {
                Ok(bytes) => Response::builder()
                    .header("content-type", "application/json")
                    .body(bytes)?,
                Err(_) => json_response(500, serde_json::json!({"error":"server_error"})),
            },
            "/authorize" => resource
                .authorize_endpoint(&request, config.now, &jti)
                .into_response(),
            p if p.starts_with("/r3/") => resource.r3_document(&request, config.now),
            "/__fixture/r3/executions" if request.method() == http::Method::GET => {
                json_response(200, serde_json::json!(executions))
            }
            p if p.starts_with("/op/") => match resource.authorize(&request, config.now, &jti) {
                AuthDecision::Granted(admitted) => {
                    let tool = p.trim_start_matches("/op/").to_owned();
                    *executions.entry(tool.clone()).or_default() += 1;
                    let produced = json_response(
                        200,
                        serde_json::json!({
                            "operation": tool,
                            "sub": admitted.token().claims().sub,
                        }),
                    );
                    // A per-call completion keeps its one result for replay.
                    match admitted.r3_grant() {
                        Some(grant) if grant.is_per_call() => resource.r3_retain(grant, produced),
                        _ => produced,
                    }
                }
                other => other.into_response(),
            },
            _ => json_response(404, serde_json::json!({"error":"not_found"})),
        };
        respond(incoming, response)?;
    }
    Ok(())
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

/// Sends the PS's already signed fetch to the harness Resource on loopback,
/// changing only the socket destination.
struct RelayFetch {
    origin: String,
    physical: String,
}
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
impl FetchTransport for RelayFetch {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let destination = origin(&request.uri().to_string()).map_err(|e| io::Error::other(e.to_string()))?;
        if destination != self.origin {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected R3 fetch destination",
            ));
        }
        let response =
            relay(&self.physical, &request).map_err(|error| io::Error::other(error.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

fn relay(base: &str, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
    let address: SocketAddr = base
        .strip_prefix("http://")
        .ok_or("expected loopback HTTP")?
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("R3 relay must be loopback".into());
    }
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        socket,
        "{} {} HTTP/1.1\r\n",
        request.method(),
        request
            .uri()
            .path_and_query()
            .ok_or("missing request path")?
    )?;
    for (name, value) in request.headers() {
        write!(socket, "{}: {}\r\n", name, value.to_str()?)?;
    }
    if !request.headers().contains_key("host") {
        write!(
            socket,
            "Host: {}\r\n",
            request.uri().authority().ok_or("missing authority")?
        )?;
    }
    write!(
        socket,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        request.body().len()
    )?;
    socket.write_all(request.body())?;
    let mut bytes = Vec::new();
    socket.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("R3 response exceeds fixture limit".into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let offset = match parsed.parse(&bytes)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err("incomplete R3 response".into()),
    };
    let mut response = Response::builder().status(parsed.code.ok_or("missing status")?);
    for header in parsed.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported R3 response framing".into());
        }
        response = response.header(header.name, header.value);
    }
    Ok(response.body(bytes[offset..].to_vec())?)
}

fn unavailable<E>(_: E) -> PolicyError {
    PolicyError::Unavailable
}

fn run_issuer(config: &Bootstrap, x: Extension) -> Result<(), Failure> {
    let resource_issuer = origin(&config.resource)?;
    let (_, _, resource) = trusted(
        &resource_issuer,
        "aauth-resource.json",
        &x.resource_kid,
        &x.resource_jwk,
    )?;
    let mut person_config = PersonConfig::new(
        &x.person_server,
        &x.person_kid,
        signing_key(&x.person_seed_hex)?,
    );
    person_config.person_lifetime = x.person_lifetime;
    let permitted = x.permitted_scopes.clone();
    let grantable = x.grantable.clone();
    let lifetime = x.auth_lifetime;
    let prefix = format!("{resource_issuer}/r3/");
    let sequence = AtomicU64::new(0);
    let now = config.now;
    let sut = PersonServer::new(
        person_config,
        PersonKeys {
            ap: agent_provider(config)?,
            resource,
        },
        MemoryStore::default(),
        FixturePolicy {
            subject: x.person_subject.clone(),
            scopes: x.permitted_scopes.clone(),
            auth_lifetime: x.auth_lifetime,
        },
        move || now,
        move || format!("r3-ps-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1),
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(move |uri: &str, _deadline: Instant| -> io::Result<()> {
            if uri.starts_with(&prefix) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "R3 document endpoint is not admitted",
                ))
            }
        }),
        transport: Box::new(RelayFetch {
            origin: resource_issuer.clone(),
            physical: x.r3_transport.clone(),
        }),
        limits: FetchLimits::default(),
        // Fixed host consent: the requested permitted scopes, and every
        // document operation the fixture lists as grantable.
        policy: Box::new(
            move |request: &R3AuthorizationRequest<'_>| -> Result<R3Decision, PolicyError> {
                if request
                    .core
                    .scopes
                    .iter()
                    .any(|scope| !permitted.contains(scope))
                {
                    return Err(PolicyError::Denied);
                }
                let mut chosen = Vec::new();
                for operation in request.document.operation_set().operations().map_err(unavailable)? {
                    let value: serde_json::Value =
                        serde_json::from_slice(&operation.json().map_err(unavailable)?)
                            .map_err(unavailable)?;
                    if value["tool"]
                        .as_str()
                        .is_some_and(|tool| grantable.iter().any(|g| g == tool))
                    {
                        chosen.push(operation);
                    }
                }
                let vocabulary = McpCodec::vocabulary().map_err(unavailable)?;
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocabulary, &chosen).map_err(unavailable)?,
                    per_call: None,
                    scopes: request.core.scopes.clone(),
                    lifetime,
                })
            },
        ),
        audit: Arc::new(MemoryAudit::default()),
    })?;
    let server = listen(config)?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let response = sut.handle(&request);
        respond(incoming, response)?;
    }
    Ok(())
}
