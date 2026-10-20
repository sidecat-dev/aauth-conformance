//! Fixed host policy inputs. Native AS/PS code owns every wire continuation.
use aauth_rust_access_server::PolicyError;
use aauth_rust_core::continuation::Requirement;
use http::{Request, Response};
use serde::Deserialize;
use std::sync::atomic::{AtomicI32, Ordering};

#[derive(Default)]
pub(super) struct HostControl(AtomicI32);

#[derive(Deserialize)]
struct Command {
    #[serde(default)]
    stage: i32,
    #[serde(default)]
    reference: String,
}

impl HostControl {
    pub(super) fn requirement(&self) -> Result<Option<Requirement>, PolicyError> {
        match self.0.load(Ordering::SeqCst) {
            -1 => Err(PolicyError::Denied),
            0 => Ok(Some(Requirement::Payment {
                authenticate: "Payment id=\"fixture-bill\", method=\"example\"".into(),
            })),
            1 => Ok(Some(Requirement::Approval)),
            _ => Ok(None),
        }
    }

    pub(super) fn handle(
        &self,
        request: &Request<Vec<u8>>,
        advance: impl FnOnce(&str) -> Result<(), String>,
    ) -> Response<Vec<u8>> {
        if request.method() != "POST" {
            return response(405, "POST required");
        }
        let command: Command = match serde_json::from_slice(request.body()) {
            Ok(command) if request.body().len() <= 4096 => command,
            _ => return response(400, "invalid host control"),
        };
        if !(-1..=2).contains(&command.stage) {
            return response(400, "invalid host control");
        }
        // This host change never creates a token or treats payment as settled
        // automatically. A reference triggers exactly one native signed PS poll.
        self.0.store(command.stage, Ordering::SeqCst);
        if !command.reference.is_empty()
            && let Err(error) = advance(&command.reference)
        {
            return response(500, &error);
        }
        response(204, "")
    }
}

fn response(status: u16, body: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .body(body.as_bytes().to_vec())
        .expect("fixed host response")
}
