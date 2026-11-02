//! Bootstrap roles: the native hosted Agent Provider (`BootstrapService`),
//! the native enrolling Agent (`BootstrapClient`) and a self-hosted domain's
//! native issuance (`AgentProvider::issue_to` and `issue_subagent_to`). Host
//! policy, fixed clocks and fixture controls only; every proof, enrollment,
//! refresh and token decision belongs to aauth-rust.
use super::{Bootstrap, exchange, fetch, person_request};
use aauth_rust_agent::{Agent, BootstrapClient};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::bootstrap::{
    AgentGrant, BootstrapEndpoints, BootstrapPolicy, BootstrapService, Denial, EnrollmentApproval,
    EnrollmentRequest, MemoryBootstrapStore, RefreshRequest, SubagentRequest,
    thumbprint_local_part,
};
use aauth_rust_core::AgentProviderKeys;
use aauth_rust_jose::{Jwk, SigningKey};
use serde::Deserialize;
use std::io::{Read, Write};

type Failure = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct Extension {
    #[serde(default)]
    ap_seed_hex: String,
    #[serde(default)]
    ap_kid: String,
    #[serde(default)]
    enrollment_path: String,
    #[serde(default)]
    refresh_path: String,
    #[serde(default)]
    single_key_refresh_path: String,
    #[serde(default)]
    subagent_path: String,
    #[serde(default)]
    issue_path: String,
    #[serde(default)]
    agent_lifetime: i64,
    #[serde(default)]
    person_server: String,
}

pub fn run(config: Bootstrap) -> Result<(), Failure> {
    let extension: Extension = serde_json::from_value(config.extension.clone())?;
    match config.role.as_str() {
        "bootstrap.agent-provider" => run_provider(config, extension),
        "bootstrap.agent" => run_agent(config, extension),
        "bootstrap.self-hosted" => run_self_hosted(config, extension),
        other => Err(format!("unknown Bootstrap role {other}").into()),
    }
}

fn seed(hex: &str) -> Result<[u8; 32], Failure> {
    if hex.len() != 64 {
        return Err("signing seed must be 32-byte hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(seed)
}

fn provider(config: &Bootstrap, extension: &Extension) -> Result<AgentProvider, Failure> {
    Ok(AgentProvider::new(
        &config.issuer,
        &extension.ap_kid,
        SigningKey::from_seed(seed(&extension.ap_seed_hex)?),
    )?)
}

fn announce(path: &str) -> Result<tiny_http::Server, Failure> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| e.to_string())?;
    let address = server.server_addr().to_ip().ok_or("expected IP listener")?;
    println!(
        "{}",
        serde_json::json!({"version":1,"url":format!("http://{address}{path}")})
    );
    std::io::stdout().flush()?;
    Ok(server)
}

fn respond(incoming: tiny_http::Request, response: http::Response<Vec<u8>>) -> Result<(), Failure> {
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

fn reply(status: u16, value: serde_json::Value) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .expect("fixed control response")
}

// Serves the provider's published metadata and JWKS; None for other requests.
fn discovery(
    provider: &AgentProvider,
    request: &http::Request<Vec<u8>>,
) -> Option<Result<http::Response<Vec<u8>>, Failure>> {
    let body = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/.well-known/aauth-agent.json") => provider.metadata(),
        ("GET", "/.well-known/jwks.json") => provider.jwks(),
        _ => return None,
    };
    Some(body.map_err(Into::into).and_then(|body| {
        Ok(http::Response::builder()
            .header("content-type", "application/json")
            .body(body)?)
    }))
}

/// The suite's host policy: every enrollment approved with an identifier
/// derived from its durable key, every refresh granted the fixture lifetime
/// and the Person Server the agent names, every sub-agent of a top-level
/// agent approved for the fixture lifetime.
struct FixturePolicy {
    lifetime: i64,
}
impl BootstrapPolicy for FixturePolicy {
    fn enroll(&self, request: &EnrollmentRequest<'_>) -> Result<EnrollmentApproval, Denial> {
        Ok(EnrollmentApproval {
            local: thumbprint_local_part(request),
            account: None,
        })
    }
    fn refresh(&self, request: &RefreshRequest<'_>) -> Result<AgentGrant, Denial> {
        let grant = AgentGrant::new(self.lifetime);
        Ok(match request.ps {
            Some(ps) => grant.with_ps(ps),
            None => grant,
        })
    }
    fn subagent(&self, _: &SubagentRequest<'_>) -> Result<i64, Denial> {
        Ok(self.lifetime)
    }
}

/// Native hosted Agent Provider: metadata and JWKS, and `BootstrapService`
/// at the fixture's enrollment, refresh, single-key refresh and sub-agent paths.
fn run_provider(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let endpoint = |path: &str| format!("{}{path}", config.issuer);
    let service = BootstrapService::new(
        provider(&config, &extension)?,
        BootstrapEndpoints {
            enrollment: endpoint(&extension.enrollment_path),
            refresh: endpoint(&extension.refresh_path),
            single_key_refresh: Some(endpoint(&extension.single_key_refresh_path)),
            subagent: Some(endpoint(&extension.subagent_path)),
        },
        MemoryBootstrapStore::new(),
        FixturePolicy {
            lifetime: extension.agent_lifetime,
        },
    )?;
    let now = config.now;
    let server = announce("/.well-known/aauth-agent.json")?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let response = match discovery(service.provider(), &request) {
            Some(published) => published?,
            None => service.handle(&request, now).into_response(),
        };
        respond(incoming, response)?;
    }
    Ok(())
}

/// One control job for the enrolling Agent.
#[derive(Deserialize)]
struct AgentJob {
    operation: String,
    #[serde(default)]
    jwk: Option<Jwk>,
    #[serde(default)]
    discriminator: Option<String>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    transport: String,
}

/// The enrolling Agent: a `BootstrapClient` holding a durable key it
/// generated, configured with the fixture AP. Each control job runs one native
/// operation; requests go to the fixture AP or Resource with the logical Host.
struct EnrollingAgent {
    config: Bootstrap,
    extension: Extension,
    keys: AgentProviderKeys,
    client: BootstrapClient,
    agent: Option<Agent>,
}

impl EnrollingAgent {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.issuer)
    }
    fn current(&self) -> Result<&Agent, Failure> {
        self.agent
            .as_ref()
            .ok_or_else(|| "no Agent token yet: refresh first".into())
    }
    fn run(&mut self, job: AgentJob) -> Result<u16, Failure> {
        let now = self.config.now;
        let transport = self.config.ap_transport.clone();
        match job.operation.as_str() {
            "enroll" => {
                let request = self.client.enrollment_request(
                    &self.url(&self.extension.enrollment_path),
                    &serde_json::json!({}),
                    now,
                )?;
                Ok(exchange(&transport, &request)?.status().as_u16())
            }
            "refresh" => {
                let ps = (!self.extension.person_server.is_empty())
                    .then_some(self.extension.person_server.as_str());
                let pending = self.client.refresh_request(
                    &self.url(&self.extension.refresh_path),
                    ps,
                    &serde_json::json!({}),
                    now,
                )?;
                let response = exchange(&transport, pending.request())?;
                let status = response.status().as_u16();
                self.agent = Some(
                    self.client
                        .complete_refresh(pending, &response, &self.keys, now)?,
                );
                Ok(status)
            }
            "subagent" => {
                let key = job.jwk.as_ref().ok_or("subagent job needs jwk")?;
                let request = self.current()?.subagent_request(
                    &self.url(&self.extension.subagent_path),
                    key,
                    job.discriminator.as_deref(),
                    now,
                )?;
                Ok(exchange(&transport, &request)?.status().as_u16())
            }
            "call" => {
                let mut request = http::Request::builder()
                    .method(job.method.as_str())
                    .uri(job.url.as_str())
                    .body(Vec::new())?;
                self.current()?.sign(&mut request, now)?;
                Ok(exchange(&job.transport, &request)?.status().as_u16())
            }
            other => Err(format!("unknown operation {other}").into()),
        }
    }
}

fn run_agent(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let keys = AgentProviderKeys::from_documents(
        &config.issuer,
        &fetch(&config.ap_transport, "/.well-known/aauth-agent.json")?,
        &fetch(&config.ap_transport, "/.well-known/jwks.json")?,
    )?;
    let client = BootstrapClient::new(SigningKey::generate(), &config.issuer)?;
    let mut agent = EnrollingAgent {
        config,
        extension,
        keys,
        client,
        agent: None,
    };
    let server = announce("/control")?;
    for mut incoming in server.incoming_requests() {
        let outcome = (|| -> Result<u16, Failure> {
            let mut body = Vec::new();
            incoming.as_reader().take(16385).read_to_end(&mut body)?;
            if body.len() > 16384 {
                return Err("control body limit".into());
            }
            agent.run(serde_json::from_slice(&body)?)
        })();
        let response = match outcome {
            Ok(status) => reply(200, serde_json::json!({ "status": status })),
            Err(error) => reply(422, serde_json::json!({ "error": error.to_string() })),
        };
        respond(incoming, response)?;
    }
    Ok(())
}

/// One issue request to the self-hosted domain's token-issuing process.
#[derive(Deserialize)]
struct IssueJob {
    jwk: Jwk,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    ps: Option<String>,
    #[serde(default)]
    parent_token: Option<String>,
    #[serde(default)]
    discriminator: Option<String>,
}

/// Self-hosted domain: the provider's metadata and JWKS, and the
/// token-issuing process behind the fixture's issue control.
fn run_self_hosted(config: Bootstrap, extension: Extension) -> Result<(), Failure> {
    let provider = provider(&config, &extension)?;
    let now = config.now;
    let lifetime = extension.agent_lifetime;
    let server = announce("/.well-known/aauth-agent.json")?;
    for mut incoming in server.incoming_requests() {
        let request = person_request(&mut incoming)?;
        let response = if let Some(published) = discovery(&provider, &request) {
            published?
        } else if request.method() == "POST" && request.uri().path() == extension.issue_path {
            let issued = serde_json::from_slice::<IssueJob>(request.body())
                .map_err(|error| error.to_string())
                .and_then(|job| {
                    let issued = match (&job.parent_token, &job.agent) {
                        (Some(parent), _) => provider.issue_subagent_to(
                            parent,
                            &job.jwk,
                            job.discriminator.as_deref().unwrap_or_default(),
                            lifetime,
                            now,
                        ),
                        (None, Some(agent)) => {
                            let grant = AgentGrant::new(lifetime);
                            let grant = match &job.ps {
                                Some(ps) => grant.with_ps(ps),
                                None => grant,
                            };
                            provider.issue_to(agent, &job.jwk, &grant, now)
                        }
                        (None, None) => {
                            return Err("an issue names an agent or a parent token".to_owned());
                        }
                    };
                    issued.map_err(|error| error.code().to_owned())
                });
            match issued {
                Ok(issued) => reply(200, serde_json::json!({ "agent_token": issued.token })),
                Err(error) => reply(400, serde_json::json!({ "error": error })),
            }
        } else {
            reply(404, serde_json::json!({"error":"no such fixture path"}))
        };
        respond(incoming, response)?;
    }
    Ok(())
}
