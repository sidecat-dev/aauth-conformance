# aauth-rust reference deployment

Serves aauth-rust's native roles over HTTPS for remote mode. The
[deployments README](../README.md) lists the five names and roles.

Measured against aauth-rust `v0.1.0-alpha.19` (`1b4059e`).

The roles are built with `AgentIdentityResource`, `PersonServer` (with and
without `with_federation`), `AccessServer` and
`PsAuthorizationResource::new_federated`. A small key resolver fetches each
trusted issuer's metadata and JWKS over HTTPS on first use and builds
`TrustedIssuerKeys` from them. Person tokens are kept in `MemoryStore`.
`src/https.rs` is a blocking rustls server and client, one thread per
connection, with Content-Length framing only.

## Build and run

`library` must link to the aauth-rust checkout to deploy.
`rust-toolchain.toml` pins the toolchain that checkout pins:

```sh
ln -s /path/to/aauth-rust library
cargo build --release
target/release/aauth-rust-deployment deployment.json
```
