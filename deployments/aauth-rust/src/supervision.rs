//! Serves the Supervision Server for remote mode.
use crate::{Env, Route};
use crate::https::Failure;

/// The routes this module serves; none until its names are configured.
pub fn routes(_env: &Env) -> Result<Vec<Route>, Failure> {
    Ok(Vec::new())
}
