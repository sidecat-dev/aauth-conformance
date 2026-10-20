# Agent signing report

Suite SHA-256: `67c30015bb2b73eae38a50e671d0640e7635ae2b73045186084d5826df4fc1fe`

Verifier clock: `1800000000` Unix seconds

Execution: **passed**.

Pass means only the listed assertions passed, not the entire section. `adapter-contract` rows specify the test application's response. Loopback HTTP transport does not measure TLS, enrollment or discovery security.

| Clause | Scope | aauth-go (`e93fd538022040ab963676b9291db7ee5cef3668`) | aauth-rust (`934217d0c43bf52399d996be012d82c57fc8f1f9`) |
| --- | --- | --- | --- |
| [agent.input-profile](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#signing-agent) | adapter-contract | pass (3 pass, 0 fail, 0 error, 0 unexercised) | pass (3 pass, 0 fail, 0 error, 0 unexercised) |
| [core.agent-signing](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#signing-agent) | protocol | pass (3 pass, 0 fail, 0 error, 0 unexercised) | pass (3 pass, 0 fail, 0 error, 0 unexercised) |
| [core.agent-coverage](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#covered-components) | protocol | pass (3 pass, 0 fail, 0 error, 0 unexercised) | pass (3 pass, 0 fail, 0 error, 0 unexercised) |
| [core.agent-created](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#signature-parameters) | protocol | pass (3 pass, 0 fail, 0 error, 0 unexercised) | pass (3 pass, 0 fail, 0 error, 0 unexercised) |
| [core.agent-presentation](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#agent-token-usage) | protocol | pass (3 pass, 0 fail, 0 error, 0 unexercised) | pass (3 pass, 0 fail, 0 error, 0 unexercised) |
| [agent.additional-coverage](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#covered-components) | adapter-contract | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [agent.person-flow](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#requirement-person-token) | out-of-slice | not_claimed (0 pass, 0 fail, 0 error, 0 unexercised) | not_claimed (0 pass, 0 fail, 0 error, 0 unexercised) |

## Assertion evidence

### aauth-go

- `agent-get/input` — `agent.input-profile`: **pass**
- `agent-get/proof` — `core.agent-signing`: **pass**
- `agent-get/coverage` — `core.agent-coverage`: **pass**
- `agent-get/created` — `core.agent-created`: **pass**
- `agent-get/agent-token` — `core.agent-presentation`: **pass**
- `agent-post/input` — `agent.input-profile`: **pass**
- `agent-post/proof` — `core.agent-signing`: **pass**
- `agent-post/coverage` — `core.agent-coverage`: **pass**
- `agent-post/created` — `core.agent-created`: **pass**
- `agent-post/agent-token` — `core.agent-presentation`: **pass**
- `agent-query-authorization/input` — `agent.input-profile`: **pass**
- `agent-query-authorization/proof` — `core.agent-signing`: **pass**
- `agent-query-authorization/coverage` — `core.agent-coverage`: **pass**
- `agent-query-authorization/created` — `core.agent-created`: **pass**
- `agent-query-authorization/agent-token` — `core.agent-presentation`: **pass**
- `agent-query-authorization/extra-coverage` — `agent.additional-coverage`: **pass**

### aauth-rust

- `agent-get/input` — `agent.input-profile`: **pass**
- `agent-get/proof` — `core.agent-signing`: **pass**
- `agent-get/coverage` — `core.agent-coverage`: **pass**
- `agent-get/created` — `core.agent-created`: **pass**
- `agent-get/agent-token` — `core.agent-presentation`: **pass**
- `agent-post/input` — `agent.input-profile`: **pass**
- `agent-post/proof` — `core.agent-signing`: **pass**
- `agent-post/coverage` — `core.agent-coverage`: **pass**
- `agent-post/created` — `core.agent-created`: **pass**
- `agent-post/agent-token` — `core.agent-presentation`: **pass**
- `agent-query-authorization/input` — `agent.input-profile`: **pass**
- `agent-query-authorization/proof` — `core.agent-signing`: **pass**
- `agent-query-authorization/coverage` — `core.agent-coverage`: **pass**
- `agent-query-authorization/created` — `core.agent-created`: **pass**
- `agent-query-authorization/agent-token` — `core.agent-presentation`: **pass**
- `agent-query-authorization/extra-coverage` — `agent.additional-coverage`: **pass**

