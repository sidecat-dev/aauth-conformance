# aauth-go reference deployment

Serves aauth-go's native roles over HTTPS for remote mode. The
[deployments README](../README.md) lists the names and roles.

Measured against aauth-go `da8b14b` (main).

The roles are built with `resource.NewAgentIdentity`,
`personserver.NewPSAuthorization`, `personserver.NewFederatedAuthorization`,
`accessserver.New` and `resource.NewFederatedAuthorization`. Keys come from
`signaturekey.NewHTTPKeyResolver`, which admits only the configured issuers.
Person tokens are kept in `testutil.NewMissionStore`, which holds them in
memory.

The further roles are in their own files, each appending to `extensions`:
`events.go` (Agent Provider, Events Resource and Agent), `supervision.go`
(`supervisionserver.New`), `r3.go` (R3 Resources and issuers) and
`sigkey.go` (the Signature-Key verifier). Each file's comment names its
`names` keys, its policy and its host controls.

## Build and run

`library` must link to the aauth-go checkout to deploy:

```sh
ln -s /path/to/aauth-go library
go build -o aauth-go-deployment .
./aauth-go-deployment -config deployment.json
```
