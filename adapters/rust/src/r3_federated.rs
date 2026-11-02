//! Four-party R3 launcher: a native federated Person Server and a native
//! Access Server. The AS issues the R3 Auth token from its own signed fetch;
//! the PS consents to the document and verifies the delivery. Both fetches
//! reach the harness Resource with only the socket changed, and the PS's
//! signed AS request reaches the AS in this process unchanged.
use super::{
    Bootstrap, Extension, Failure, FixturePolicy, MemoryAudit, R3Keys, RelayFetch, agent_provider,
    grantable_operations, listen, origin, person_consent, person_request, r3_egress, respond,
    signing_key, trusted,
};
use aauth_rust_access_server::{
    AccessServer, AuthorizationRequest as AccessRequest, Config as AccessConfig, Decision,
    PolicyError as AccessPolicyError, R3AuthorizationRequest as AccessR3Request,
    R3Decision as AccessR3Decision, R3IssuerConfig as AccessR3Config,
};
use aauth_rust_person_server::{
    Config as PersonConfig, Federation, FederationError, MemoryStore, PersonServer, R3IssuerConfig,
};
use aauth_rust_r3::{FetchLimits, standard_registry};
use http::{Request, Response};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Hands the Person Server's signed token request to the native Access
/// Server in this process: same target, headers and body.
struct InProcess<A> {
    issuer: String,
    handle: A,
}
impl<A: Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync> Federation for InProcess<A> {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        if issuer != self.issuer {
            return Err(FederationError);
        }
        Ok(format!("{issuer}/token"))
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        if request.uri().to_string() != format!("{}/token", self.issuer) {
            return Err(FederationError);
        }
        Ok((self.handle)(request))
    }
}

fn ids(prefix: &'static str) -> impl Fn() -> String + Send + Sync {
    let sequence = AtomicU64::new(0);
    move || format!("{prefix}-{}", sequence.fetch_add(1, Ordering::Relaxed) + 1)
}

pub(super) fn run(config: &Bootstrap, x: Extension) -> Result<(), Failure> {
    let resource_issuer = origin(&config.resource)?;
    // The Resource, and each server's own published key, as both servers see them.
    let keys = R3Keys {
        ap: agent_provider(config)?,
        roles: vec![
            trusted(
                &resource_issuer,
                "aauth-resource.json",
                &x.resource_kid,
                &x.resource_jwk,
            )?,
            trusted(
                &x.person_server,
                "aauth-person.json",
                &x.person_kid,
                &x.person_jwk,
            )?,
            trusted(
                &x.access_server,
                "aauth-access.json",
                &x.access_kid,
                &x.access_jwk,
            )?,
        ],
    };
    let now = config.now;
    let permitted = x.permitted_scopes.clone();
    let person_server = x.person_server.clone();
    let lifetime = x.auth_lifetime;
    // Fixed host policy: the requested permitted scopes, and every document
    // operation the fixture lists as grantable.
    let core_scopes = permitted.clone();
    let authorize = move |request: &AccessRequest| {
        if request.person_server != person_server
            || request
                .scopes
                .iter()
                .any(|scope| !core_scopes.contains(scope))
        {
            return Err(AccessPolicyError::Denied);
        }
        Ok(Decision {
            scopes: request.scopes.clone(),
            lifetime,
        })
    };
    let grantable = x.grantable.clone();
    let access = AccessServer::new(
        AccessConfig::new(
            &x.access_server,
            &x.access_kid,
            signing_key(&x.access_seed_hex)?,
        ),
        keys.clone(),
        authorize,
        move || now,
        ids("r3-access"),
    )?
    .with_r3(AccessR3Config {
        registry: standard_registry()?,
        egress: r3_egress(&resource_issuer),
        transport: Box::new(RelayFetch {
            origin: resource_issuer.clone(),
            physical: x.r3_transport.clone(),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(
            move |request: &AccessR3Request<'_>| -> Result<AccessR3Decision, AccessPolicyError> {
                if request
                    .core
                    .scopes
                    .iter()
                    .any(|scope| !permitted.contains(scope))
                {
                    return Err(AccessPolicyError::Denied);
                }
                Ok(AccessR3Decision {
                    granted: grantable_operations(request.document, &grantable)
                        .map_err(|_| AccessPolicyError::Unavailable)?,
                    scopes: request.core.scopes.clone(),
                    lifetime,
                })
            },
        ),
        audit: Arc::new(MemoryAudit::default()),
    })?;
    let mut person_config = PersonConfig::new(
        &x.person_server,
        &x.person_kid,
        signing_key(&x.person_seed_hex)?,
    );
    person_config.person_lifetime = x.person_lifetime;
    let sut = PersonServer::new(
        person_config,
        keys,
        MemoryStore::default(),
        FixturePolicy {
            subject: x.person_subject.clone(),
            scopes: x.permitted_scopes.clone(),
            auth_lifetime: x.auth_lifetime,
        },
        move || now,
        ids("r3-ps"),
    )?
    .with_federation(InProcess {
        issuer: x.access_server.clone(),
        handle: move |request: &Request<Vec<u8>>| access.handle(request),
    })
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: r3_egress(&resource_issuer),
        transport: Box::new(RelayFetch {
            origin: resource_issuer.clone(),
            physical: x.r3_transport.clone(),
        }),
        limits: FetchLimits::default(),
        policy: person_consent(&x),
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
