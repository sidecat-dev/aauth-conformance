# aauth-go reference deployment

Serves aauth-go's native roles over HTTPS for remote mode. The
[deployments README](../README.md) lists the five names and roles.

Measured against aauth-go `3deb5b7`.

The roles are built with `resource.NewAgentIdentity`,
`personserver.NewPSAuthorization`, `personserver.NewFederatedAuthorization`,
`accessserver.New` and `resource.NewFederatedAuthorization`. Keys come from
`signaturekey.NewHTTPKeyResolver`, which admits only the configured issuers.
Person tokens are kept in `testutil.NewMissionStore`, which holds them in
memory.

## Build and run

`library` must link to the aauth-go checkout to deploy:

```sh
ln -s /path/to/aauth-go library
go build -o aauth-go-deployment .
./aauth-go-deployment -config deployment.json
```
