# Deferred four-party authorization report

Suite SHA-256: `5448d4a28d159203e1126943999e089c0eb03090c30bd1cf9020d3f869897440`

Verifier clock: `1800000000` Unix seconds

Execution: **passed**.

Pass means only the listed assertions passed, not the entire section. `adapter-contract` rows specify the test application's response. Loopback HTTP transport does not measure TLS, enrollment or discovery security.

| Clause | Scope | aauth-go (`8c4b727fad3d8a0d373f66d997c86dc7f2af154c`) |
| --- | --- | --- |
| [deferred.pending](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#deferred-responses) | protocol | pass (21 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.payment](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#as-token-endpoint) | protocol | pass (8 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.proof](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#http-message-signatures-profile) | protocol | pass (10 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.forwarding](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-to-as-token-request) | protocol | pass (5 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-token-delivery) | protocol | pass (32 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.gone](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#pending-url-security) | protocol | pass (8 pass, 0 fail, 0 error, 0 unexercised) |
| [deferred.host](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-as-trust-establishment) | adapter-contract | pass (4 pass, 0 fail, 0 error, 0 unexercised) |

## Assertion evidence

### aauth-go

- `deferred-payment/access-status-0` — `deferred.payment`: **pass**
- `deferred-payment/access-deferred-pending-1` — `deferred.payment`: **pass**
- `deferred-payment/access-deferred-proof-2` — `deferred.proof`: **pass**
- `deferred-payment/access-deferred-forwarded-3` — `deferred.forwarding`: **pass**
- `deferred-payment/pending-status-4` — `deferred.pending`: **pass**
- `deferred-payment/pending-deferred-pending-5` — `deferred.pending`: **pass**
- `deferred-payment/pending-ps-no-token-6` — `deferred.delivery`: **pass**
- `deferred-payment/waiting-status-7` — `deferred.pending`: **pass**
- `deferred-payment/waiting-deferred-stable-8` — `deferred.pending`: **pass**
- `deferred-payment/approval-status-9` — `deferred.pending`: **pass**
- `deferred-payment/approval-deferred-pending-10` — `deferred.pending`: **pass**
- `deferred-payment/approval-deferred-stable-11` — `deferred.pending`: **pass**
- `deferred-payment/approval-deferred-proof-12` — `deferred.proof`: **pass**
- `deferred-payment/result-status-13` — `deferred.delivery`: **pass**
- `deferred-payment/result-deferred-proof-14` — `deferred.proof`: **pass**
- `deferred-payment/token-status-15` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-16` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-signature-17` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-identity-18` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-key-19` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-lifetime-20` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-scope-21` — `deferred.delivery`: **pass**
- `deferred-payment/token-ps-jwt-subject-22` — `deferred.delivery`: **pass**
- `deferred-payment/protected-status-23` — `deferred.host`: **pass**
- `deferred-payment/protected-json-member-24` — `deferred.host`: **pass**
- `deferred-payment/gone-status-25` — `deferred.gone`: **pass**
- `deferred-payment/as-gone-status` — `deferred.gone`: **pass**
- `deferred-approval/access-status-0` — `deferred.pending`: **pass**
- `deferred-approval/access-deferred-pending-1` — `deferred.pending`: **pass**
- `deferred-approval/access-deferred-proof-2` — `deferred.proof`: **pass**
- `deferred-approval/access-deferred-forwarded-3` — `deferred.forwarding`: **pass**
- `deferred-approval/pending-status-4` — `deferred.pending`: **pass**
- `deferred-approval/pending-deferred-pending-5` — `deferred.pending`: **pass**
- `deferred-approval/pending-ps-no-token-6` — `deferred.delivery`: **pass**
- `deferred-approval/waiting-status-7` — `deferred.pending`: **pass**
- `deferred-approval/waiting-deferred-stable-8` — `deferred.pending`: **pass**
- `deferred-approval/result-status-9` — `deferred.delivery`: **pass**
- `deferred-approval/result-deferred-proof-10` — `deferred.proof`: **pass**
- `deferred-approval/token-status-11` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-12` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-signature-13` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-identity-14` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-key-15` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-lifetime-16` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-scope-17` — `deferred.delivery`: **pass**
- `deferred-approval/token-ps-jwt-subject-18` — `deferred.delivery`: **pass**
- `deferred-approval/protected-status-19` — `deferred.host`: **pass**
- `deferred-approval/protected-json-member-20` — `deferred.host`: **pass**
- `deferred-approval/gone-status-21` — `deferred.gone`: **pass**
- `deferred-approval/as-gone-status` — `deferred.gone`: **pass**
- `deferred-denied/access-status-0` — `deferred.payment`: **pass**
- `deferred-denied/access-deferred-pending-1` — `deferred.payment`: **pass**
- `deferred-denied/access-deferred-proof-2` — `deferred.proof`: **pass**
- `deferred-denied/access-deferred-forwarded-3` — `deferred.forwarding`: **pass**
- `deferred-denied/pending-status-4` — `deferred.pending`: **pass**
- `deferred-denied/pending-deferred-pending-5` — `deferred.pending`: **pass**
- `deferred-denied/pending-ps-no-token-6` — `deferred.delivery`: **pass**
- `deferred-denied/waiting-status-7` — `deferred.pending`: **pass**
- `deferred-denied/waiting-deferred-stable-8` — `deferred.pending`: **pass**
- `deferred-denied/result-status-9` — `deferred.delivery`: **pass**
- `deferred-denied/result-deferred-proof-10` — `deferred.proof`: **pass**
- `deferred-denied/token-status-11` — `deferred.delivery`: **pass**
- `deferred-denied/token-json-member-12` — `deferred.delivery`: **pass**
- `deferred-denied/token-ps-no-token-13` — `deferred.delivery`: **pass**
- `deferred-denied/gone-status-14` — `deferred.gone`: **pass**
- `deferred-denied/as-gone-status` — `deferred.gone`: **pass**
- `deferred-invalid-grant/access-status-0` — `deferred.payment`: **pass**
- `deferred-invalid-grant/access-deferred-pending-1` — `deferred.payment`: **pass**
- `deferred-invalid-grant/access-deferred-proof-2` — `deferred.proof`: **pass**
- `deferred-invalid-grant/access-deferred-forwarded-3` — `deferred.forwarding`: **pass**
- `deferred-invalid-grant/pending-status-4` — `deferred.pending`: **pass**
- `deferred-invalid-grant/pending-deferred-pending-5` — `deferred.pending`: **pass**
- `deferred-invalid-grant/pending-ps-no-token-6` — `deferred.delivery`: **pass**
- `deferred-invalid-grant/waiting-status-7` — `deferred.pending`: **pass**
- `deferred-invalid-grant/waiting-deferred-stable-8` — `deferred.pending`: **pass**
- `deferred-invalid-grant/result-status-9` — `deferred.delivery`: **pass**
- `deferred-invalid-grant/result-deferred-proof-10` — `deferred.proof`: **pass**
- `deferred-invalid-grant/token-status-11` — `deferred.delivery`: **pass**
- `deferred-invalid-grant/token-json-member-12` — `deferred.delivery`: **pass**
- `deferred-invalid-grant/token-ps-no-token-13` — `deferred.delivery`: **pass**
- `deferred-invalid-grant/gone-status-14` — `deferred.gone`: **pass**
- `deferred-invalid-grant/as-gone-status` — `deferred.gone`: **pass**
- `deferred-foreign-location/access-status-0` — `deferred.payment`: **pass**
- `deferred-foreign-location/access-deferred-pending-1` — `deferred.payment`: **pass**
- `deferred-foreign-location/access-deferred-proof-2` — `deferred.proof`: **pass**
- `deferred-foreign-location/access-deferred-forwarded-3` — `deferred.forwarding`: **pass**
- `deferred-foreign-location/pending-status-4` — `deferred.delivery`: **pass**
- `deferred-foreign-location/pending-json-member-5` — `deferred.delivery`: **pass**
