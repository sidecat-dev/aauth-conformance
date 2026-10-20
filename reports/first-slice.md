# Resource agent-identity report

Suite SHA-256: `67c30015bb2b73eae38a50e671d0640e7635ae2b73045186084d5826df4fc1fe`

Verifier clock: `1800000000` Unix seconds

Execution: **passed**.

Pass means only the listed assertions passed, not the entire section. `adapter-contract` rows specify the test application's response. Loopback HTTP transport does not measure TLS, enrollment or discovery security.

| Clause | Scope | aauth-go (`e93fd538022040ab963676b9291db7ee5cef3668`) | aauth-rust (`934217d0c43bf52399d996be012d82c57fc8f1f9`) |
| --- | --- | --- | --- |
| [core.agent-token-required](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#requirement-agent-token) | protocol | pass (2 pass, 0 fail, 0 error, 0 unexercised) | pass (2 pass, 0 fail, 0 error, 0 unexercised) |
| [core.agent-identity](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#overview-identity-access) | adapter-contract | pass (2 pass, 0 fail, 0 error, 0 unexercised) | pass (2 pass, 0 fail, 0 error, 0 unexercised) |
| [core.verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#verification) | protocol | pass (5 pass, 0 fail, 0 error, 0 unexercised) | pass (5 pass, 0 fail, 0 error, 0 unexercised) |
| [key.invalid-signature](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md#invalid_signature) | protocol | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [key.expired-jwt](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md#expired_jwt) | protocol | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [key.invalid-input](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md#invalid_input) | protocol | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [key.clock-skew](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md#clock_skew) | protocol | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [key.response-body](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md#response-body) | protocol | pass (4 pass, 0 fail, 0 error, 0 unexercised) | pass (4 pass, 0 fail, 0 error, 0 unexercised) |
| [core.person-token-required](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#requirement-person-token) | out-of-slice | not_claimed (0 pass, 0 fail, 0 error, 0 unexercised) | not_claimed (0 pass, 0 fail, 0 error, 0 unexercised) |

## Assertion evidence

### aauth-go

- `unsigned/status` — `core.agent-token-required`: **pass**
- `unsigned/requirement` — `core.agent-token-required`: **pass**
- `valid/status` — `core.agent-identity`: **pass**
- `valid/subject` — `core.agent-identity`: **pass**
- `tampered/status` — `core.verification`: **pass**
- `tampered/error` — `key.invalid-signature`: **pass**
- `tampered/problem-type` — `key.response-body`: **pass**
- `expired/status` — `core.verification`: **pass**
- `expired/error` — `key.expired-jwt`: **pass**
- `expired/problem-type` — `key.response-body`: **pass**
- `uncovered-signature-key/status` — `core.verification`: **pass**
- `uncovered-signature-key/error` — `key.invalid-input`: **pass**
- `uncovered-signature-key/problem-type` — `key.response-body`: **pass**
- `uncovered-signature-key/required-coverage` — `core.verification`: **pass**
- `future-created/status` — `core.verification`: **pass**
- `future-created/error` — `key.clock-skew`: **pass**
- `future-created/problem-type` — `key.response-body`: **pass**

### aauth-rust

- `unsigned/status` — `core.agent-token-required`: **pass**
- `unsigned/requirement` — `core.agent-token-required`: **pass**
- `valid/status` — `core.agent-identity`: **pass**
- `valid/subject` — `core.agent-identity`: **pass**
- `tampered/status` — `core.verification`: **pass**
- `tampered/error` — `key.invalid-signature`: **pass**
- `tampered/problem-type` — `key.response-body`: **pass**
- `expired/status` — `core.verification`: **pass**
- `expired/error` — `key.expired-jwt`: **pass**
- `expired/problem-type` — `key.response-body`: **pass**
- `uncovered-signature-key/status` — `core.verification`: **pass**
- `uncovered-signature-key/error` — `key.invalid-input`: **pass**
- `uncovered-signature-key/problem-type` — `key.response-body`: **pass**
- `uncovered-signature-key/required-coverage` — `core.verification`: **pass**
- `future-created/status` — `core.verification`: **pass**
- `future-created/error` — `key.clock-skew`: **pass**
- `future-created/problem-type` — `key.response-body`: **pass**

