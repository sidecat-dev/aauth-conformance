# Person Server direct authorization report

Suite SHA-256: `85ff645db83ca9f3d29dd4986720879b397249aef6da007cee904b6ace7880af`

Verifier clock: `1800000000` Unix seconds

Execution: **passed**.

Pass means only the listed assertions passed, not the entire section. `adapter-contract` rows specify the test application's response. Loopback HTTP transport does not measure TLS, enrollment or discovery security.

| Clause | Scope | aauth-go (`d914b4fd22e1c2b0740699debae10b364cda581d`) | aauth-rust (`0adca348341bffbad4d8e209efa84fa58465a76a`) |
| --- | --- | --- | --- |
| [ps.person-endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint) | protocol | pass (10 pass, 0 fail, 0 error, 0 unexercised) | pass (10 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.person-structure](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-structure) | protocol | pass (20 pass, 0 fail, 0 error, 0 unexercised) | pass (20 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.person-lifetime](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-structure) | protocol | pass (10 pass, 0 fail, 0 error, 0 unexercised) | pass (10 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.person-no-authorization](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-structure) | protocol | pass (10 pass, 0 fail, 0 error, 0 unexercised) | pass (10 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.auth-endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-token-endpoint) | protocol | pass (2 pass, 0 fail, 0 error, 0 unexercised) | pass (2 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.resource-verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-verification) | protocol | pass (15 pass, 0 fail, 0 error, 0 unexercised) | pass (15 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.auth-structure](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-tokens) | protocol | pass (4 pass, 0 fail, 0 error, 0 unexercised) | pass (4 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.auth-lifetime](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-tokens) | protocol | pass (2 pass, 0 fail, 0 error, 0 unexercised) | pass (2 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.common-verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#common-verification) | protocol | pass (12 pass, 0 fail, 0 error, 0 unexercised) | pass (12 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.errors](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#token-endpoint-error-codes) | protocol | pass (6 pass, 0 fail, 0 error, 0 unexercised) | pass (6 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.proof-verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#verification) | protocol | pass (2 pass, 0 fail, 0 error, 0 unexercised) | pass (2 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.body-integrity](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#covered-components) | protocol | pass (1 pass, 0 fail, 0 error, 0 unexercised) | pass (1 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.host-scope-policy](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-token-endpoint) | adapter-contract | pass (5 pass, 0 fail, 0 error, 0 unexercised) | pass (5 pass, 0 fail, 0 error, 0 unexercised) |
| [ps.host-person-profile](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-structure) | adapter-contract | pass (10 pass, 0 fail, 0 error, 0 unexercised) | pass (10 pass, 0 fail, 0 error, 0 unexercised) |

## Assertion evidence

### aauth-go

- `ps-valid/person-status` — `ps.person-endpoint`: **pass**
- `ps-valid/person-signature` — `ps.common-verification`: **pass**
- `ps-valid/person-identity` — `ps.person-structure`: **pass**
- `ps-valid/person-key` — `ps.person-structure`: **pass**
- `ps-valid/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-valid/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-valid/auth-status` — `ps.auth-endpoint`: **pass**
- `ps-valid/auth-signature` — `ps.common-verification`: **pass**
- `ps-valid/auth-identity` — `ps.auth-structure`: **pass**
- `ps-valid/auth-key` — `ps.auth-structure`: **pass**
- `ps-valid/auth-lifetime` — `ps.auth-lifetime`: **pass**
- `ps-valid/auth-authorization` — `ps.host-scope-policy`: **pass**
- `ps-valid/configured-person` — `ps.host-person-profile`: **pass**
- `ps-proof-tamper/refusal` — `ps.proof-verification`: **pass**
- `ps-proof-tamper/signature-error` — `ps.proof-verification`: **pass**
- `ps-body-tamper/refusal` — `ps.body-integrity`: **pass**
- `ps-wrong-audience/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-audience/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-audience/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-audience/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-audience/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-audience/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-audience/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-audience/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-audience/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-audience/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-key/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-key/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-key/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-key/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-key/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-key/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-key/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-key/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-key/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-key/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-person/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-person/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-person/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-person/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-person/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-person/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-person/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-person/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-person/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-person/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-lineage/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-lineage/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-lineage/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-lineage/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-lineage/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-lineage/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-lineage/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-ps/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-ps/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-ps/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-ps/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-ps/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-ps/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-ps/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-expired-resource/person-status` — `ps.person-endpoint`: **pass**
- `ps-expired-resource/person-signature` — `ps.common-verification`: **pass**
- `ps-expired-resource/person-identity` — `ps.person-structure`: **pass**
- `ps-expired-resource/person-key` — `ps.person-structure`: **pass**
- `ps-expired-resource/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-expired-resource/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-expired-resource/token-refusal` — `ps.errors`: **pass**
- `ps-expired-resource/token-error` — `ps.errors`: **pass**
- `ps-expired-resource/configured-person` — `ps.host-person-profile`: **pass**
- `ps-expired-resource/no-issued-token` — `ps.errors`: **pass**
- `ps-expired-presented/person-status` — `ps.person-endpoint`: **pass**
- `ps-expired-presented/person-signature` — `ps.common-verification`: **pass**
- `ps-expired-presented/person-identity` — `ps.person-structure`: **pass**
- `ps-expired-presented/person-key` — `ps.person-structure`: **pass**
- `ps-expired-presented/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-expired-presented/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-expired-presented/token-refusal` — `ps.errors`: **pass**
- `ps-expired-presented/token-error` — `ps.errors`: **pass**
- `ps-expired-presented/configured-person` — `ps.host-person-profile`: **pass**
- `ps-expired-presented/no-issued-token` — `ps.errors`: **pass**
- `ps-denied-scope/person-status` — `ps.person-endpoint`: **pass**
- `ps-denied-scope/person-signature` — `ps.common-verification`: **pass**
- `ps-denied-scope/person-identity` — `ps.person-structure`: **pass**
- `ps-denied-scope/person-key` — `ps.person-structure`: **pass**
- `ps-denied-scope/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-denied-scope/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-denied-scope/token-refusal` — `ps.host-scope-policy`: **pass**
- `ps-denied-scope/token-error` — `ps.host-scope-policy`: **pass**
- `ps-denied-scope/configured-person` — `ps.host-person-profile`: **pass**
- `ps-denied-scope/no-issued-token` — `ps.host-scope-policy`: **pass**
- `ps-short-parent/person-status` — `ps.person-endpoint`: **pass**
- `ps-short-parent/person-signature` — `ps.common-verification`: **pass**
- `ps-short-parent/person-identity` — `ps.person-structure`: **pass**
- `ps-short-parent/person-key` — `ps.person-structure`: **pass**
- `ps-short-parent/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-short-parent/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-short-parent/auth-status` — `ps.auth-endpoint`: **pass**
- `ps-short-parent/auth-signature` — `ps.common-verification`: **pass**
- `ps-short-parent/auth-identity` — `ps.auth-structure`: **pass**
- `ps-short-parent/auth-key` — `ps.auth-structure`: **pass**
- `ps-short-parent/auth-lifetime` — `ps.auth-lifetime`: **pass**
- `ps-short-parent/auth-authorization` — `ps.host-scope-policy`: **pass**
- `ps-short-parent/configured-person` — `ps.host-person-profile`: **pass**

### aauth-rust

- `ps-valid/person-status` — `ps.person-endpoint`: **pass**
- `ps-valid/person-signature` — `ps.common-verification`: **pass**
- `ps-valid/person-identity` — `ps.person-structure`: **pass**
- `ps-valid/person-key` — `ps.person-structure`: **pass**
- `ps-valid/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-valid/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-valid/auth-status` — `ps.auth-endpoint`: **pass**
- `ps-valid/auth-signature` — `ps.common-verification`: **pass**
- `ps-valid/auth-identity` — `ps.auth-structure`: **pass**
- `ps-valid/auth-key` — `ps.auth-structure`: **pass**
- `ps-valid/auth-lifetime` — `ps.auth-lifetime`: **pass**
- `ps-valid/auth-authorization` — `ps.host-scope-policy`: **pass**
- `ps-valid/configured-person` — `ps.host-person-profile`: **pass**
- `ps-proof-tamper/refusal` — `ps.proof-verification`: **pass**
- `ps-proof-tamper/signature-error` — `ps.proof-verification`: **pass**
- `ps-body-tamper/refusal` — `ps.body-integrity`: **pass**
- `ps-wrong-audience/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-audience/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-audience/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-audience/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-audience/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-audience/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-audience/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-audience/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-audience/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-audience/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-key/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-key/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-key/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-key/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-key/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-key/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-key/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-key/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-key/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-key/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-person/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-person/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-person/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-person/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-person/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-person/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-person/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-person/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-person/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-person/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-lineage/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-lineage/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-lineage/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-lineage/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-lineage/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-lineage/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-lineage/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-lineage/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/person-status` — `ps.person-endpoint`: **pass**
- `ps-wrong-ps/person-signature` — `ps.common-verification`: **pass**
- `ps-wrong-ps/person-identity` — `ps.person-structure`: **pass**
- `ps-wrong-ps/person-key` — `ps.person-structure`: **pass**
- `ps-wrong-ps/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-wrong-ps/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-wrong-ps/token-refusal` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/token-error` — `ps.resource-verification`: **pass**
- `ps-wrong-ps/configured-person` — `ps.host-person-profile`: **pass**
- `ps-wrong-ps/no-issued-token` — `ps.resource-verification`: **pass**
- `ps-expired-resource/person-status` — `ps.person-endpoint`: **pass**
- `ps-expired-resource/person-signature` — `ps.common-verification`: **pass**
- `ps-expired-resource/person-identity` — `ps.person-structure`: **pass**
- `ps-expired-resource/person-key` — `ps.person-structure`: **pass**
- `ps-expired-resource/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-expired-resource/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-expired-resource/token-refusal` — `ps.errors`: **pass**
- `ps-expired-resource/token-error` — `ps.errors`: **pass**
- `ps-expired-resource/configured-person` — `ps.host-person-profile`: **pass**
- `ps-expired-resource/no-issued-token` — `ps.errors`: **pass**
- `ps-expired-presented/person-status` — `ps.person-endpoint`: **pass**
- `ps-expired-presented/person-signature` — `ps.common-verification`: **pass**
- `ps-expired-presented/person-identity` — `ps.person-structure`: **pass**
- `ps-expired-presented/person-key` — `ps.person-structure`: **pass**
- `ps-expired-presented/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-expired-presented/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-expired-presented/token-refusal` — `ps.errors`: **pass**
- `ps-expired-presented/token-error` — `ps.errors`: **pass**
- `ps-expired-presented/configured-person` — `ps.host-person-profile`: **pass**
- `ps-expired-presented/no-issued-token` — `ps.errors`: **pass**
- `ps-denied-scope/person-status` — `ps.person-endpoint`: **pass**
- `ps-denied-scope/person-signature` — `ps.common-verification`: **pass**
- `ps-denied-scope/person-identity` — `ps.person-structure`: **pass**
- `ps-denied-scope/person-key` — `ps.person-structure`: **pass**
- `ps-denied-scope/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-denied-scope/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-denied-scope/token-refusal` — `ps.host-scope-policy`: **pass**
- `ps-denied-scope/token-error` — `ps.host-scope-policy`: **pass**
- `ps-denied-scope/configured-person` — `ps.host-person-profile`: **pass**
- `ps-denied-scope/no-issued-token` — `ps.host-scope-policy`: **pass**
- `ps-short-parent/person-status` — `ps.person-endpoint`: **pass**
- `ps-short-parent/person-signature` — `ps.common-verification`: **pass**
- `ps-short-parent/person-identity` — `ps.person-structure`: **pass**
- `ps-short-parent/person-key` — `ps.person-structure`: **pass**
- `ps-short-parent/person-lifetime` — `ps.person-lifetime`: **pass**
- `ps-short-parent/person-authorization` — `ps.person-no-authorization`: **pass**
- `ps-short-parent/auth-status` — `ps.auth-endpoint`: **pass**
- `ps-short-parent/auth-signature` — `ps.common-verification`: **pass**
- `ps-short-parent/auth-identity` — `ps.auth-structure`: **pass**
- `ps-short-parent/auth-key` — `ps.auth-structure`: **pass**
- `ps-short-parent/auth-lifetime` — `ps.auth-lifetime`: **pass**
- `ps-short-parent/auth-authorization` — `ps.host-scope-policy`: **pass**
- `ps-short-parent/configured-person` — `ps.host-person-profile`: **pass**
