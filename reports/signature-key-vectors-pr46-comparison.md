# Signature-Key test vectors: the set in PR 46 compared

Two sets of test vectors for HTTP Signature Keys
(`draft-hardt-httpbis-signature-key`) are proposed upstream, both answering
[dickhardt/signature-key#25](https://github.com/dickhardt/signature-key/issues/25):

- [PR 46](https://github.com/dickhardt/signature-key/pull/46), 31 vectors,
  generated from the draft text.
- [PR 48](https://github.com/dickhardt/signature-key/pull/48), the set in
  [vectors/signature-key](../vectors/signature-key/README.md) of this
  repository.

This page records what happened when the PR 46 vectors were run through two
verifiers, and the points where a vector, as published, leaves its result
open. It is written for an implementer deciding how to read either set.

| What | Revision |
| --- | --- |
| PR 46 | head `92637edac57df6d39ef80145aef498834e8e81af`, CC0 |
| Draft | signature-key `69f5ba2`, the PR's base; AAuth protocol `70d6737` |
| aauth-rust | `v0.1.0-alpha.24` (`9b13c8b`) |
| aauth-go | `e76d864` |

Line numbers below are in the signature-key draft unless they say
"protocol".

## How the vectors were run

Each vector's request went to each library's verifier, configured as an
AAuth Resource with the other Signature-Key schemes enabled. Separately, a
harness that uses neither library rebuilt every published signature base
from the published request and verified the signatures.

## The bytes

All 29 published signature bases rebuild byte for byte from the published
requests, including both labels of the multi-signature vector. Every
Ed25519 and ES256 signature verifies under the `signing_key` or `key` the
vector names. The three ML-DSA-44 signatures were not checked: the harness
had no ML-DSA verifier at the time.

## Results

| Result | Vectors |
| --- | ---: |
| Both verifiers give what the vector expects | 19 |
| A verifier differs from the vector | 12 |

Of the 12:

- **8 are open in the draft or the vector.** Six jwt-family vectors depend
  on a `typ` policy the file does not state. The multi-signature vector
  does not say which labels to verify. One vector expects a code the draft
  does not name.
- **3 vectors should change.** Two carry no signature, so the rule they
  test is never reached. One ML-DSA-44 positive vector has no condition for
  a verifier without ML-DSA.
- **1 found a verifier bug.** aauth-rust refused a jwks_uri signer whose
  `dwk` is not an AAuth document name. aauth-rust fixed it in
  `v0.1.0-alpha.26`.

The 19 that agree are the hwk, jkt-jwt, jwks and self-jwt positives, the
five Algorithm Determination negatives, `self-jwt-with-cnf-forbidden`, both
issuer checks, `jwks-kid-not-in-jwks`, `signature-key-not-covered` with
`required_input`, the hwk and jwks MUST ACCEPT controls,
`akp-only-jwks-must-decline-not-throw`, and the optional deterministic
ML-DSA-44 vector, which both verifiers decline.

## Where a result is open

1. **`hwk-symmetric-forbidden` and `unknown-scheme-selected` carry no
   `Signature-Input` or `Signature`.** A verifier takes the labels it
   verifies from `Signature-Input` (line 173), so it selects no member, and
   the scheme rule (line 155) and the symmetric-key rule (line 217) are
   never reached. Line 1018 makes missing headers `invalid_signature`, and
   both verifiers answer that. Signing each request with any key would let
   a verifier reach the rule: it rejects at scheme selection or Algorithm
   Determination before it uses the signing key.

2. **The jwt-family vectors depend on a `typ` policy the file does not
   state.** These are `jwt-cnf-ed25519`, `jwt-cnf-ed25519-cache-requested`,
   `jwt-without-exp`, `jwt-expired-one-second-before-now`,
   `jwt-exp-300s-after-now-MUST-ACCEPT` and
   `jwt-iat-one-hour-after-now-is-clock-skew`. Their assertions use `typ`
   `aa-token+jwt`. Lines 556 and 564 leave the `typ` check to deployment
   policy, and it is step 2, before the `exp` check in step 3 (line 566). A
   verifier with any other policy rejects all six at step 2, so the `exp`
   and `iat` rules are not reached. An AAuth verifier expects `aa-agent+jwt`
   (protocol line 539). Stating the expected `typ`, issuer and `dwk` as
   verifier configuration would make the six decidable.

3. **`multi-signature-hwk-and-jwks` does not say which labels to verify.**
   Line 173 leaves that to application context, and line 181 allows
   verifying a subset. A verifier configured for label `sig` rejects the
   request. Naming the labels, `sig1` and `sig2`, fixes the expectation.

4. **`mldsa-44-verify-only` is a positive vector with no condition.** A
   verifier without ML-DSA must answer `unsupported_algorithm` (line 233),
   which is what `akp-only-jwks-must-decline-not-throw` expects. The two
   vectors also carry the same `Signature-Key` and the same ML-DSA-44
   signing key, so a verifier that implements ML-DSA-44 would accept a
   request the file marks must-reject. A condition on each, like the one on
   the `iat` vector, makes the pair consistent.

5. **`label-missing-from-signature-key` expects `invalid_key`, a code the
   draft does not name here.** Line 179 requires the verification to fail.
   Line 1018 gives `invalid_signature` for missing Signature-Key material,
   and line 1046 gives `invalid_key` for a key that cannot be parsed. Both
   verifiers answer `invalid_signature`. Until the draft names a code, any
   refusal should pass.

6. **`hwk-alg-kty-inconsistent` has two possible faults.** Its RSA `n` is a
   17-byte fragment, so a verifier may reject it as unparseable before it
   compares `kty` with `alg`. Both give `invalid_key`, so the vector cannot
   tell them apart. A full-length modulus leaves the disagreement as the
   only fault.

7. **In `self-jwt-es256`, `aud` names a different party from the request
   target.** The `aud` is `https://client.example` and the request goes to
   `resource.example`. Neither verifier checks `aud`, which lines 633 and
   657 leave to policy, but a verifier that does would reject the vector.

8. **`jwks_uri-discovery-ed25519` uses `dwk="example-configuration"`, the
   draft's own example (line 479).** It is right as published, and it is
   the vector that found the aauth-rust bug: line 454 makes `dwk` any
   metadata document name.

## What each set has that the other does not

| | PR 46 | PR 48 |
| --- | --- | --- |
| Schemes | hwk, jkt-jwt, jwks_uri, jwks, jwt, self-jwt | the same, plus x509 and cached |
| Algorithms | Ed25519, ES256, ML-DSA-44 | Ed25519, ES256, ES384, PS256, RS256, ML-DSA-44 |
| Expectation | on negatives, `must_reject`, `expected_signature_error`, `rule` and `draft_section`; a condition (`applies_to`, `conformance`) on two vectors | on every vector, `expect.outcome`, `error` and the draft lines in `basis`; `verify-or-reject` as an outcome |
| Verifier configuration | not stated | a `verifier` member: label, window, schemes, algorithms, self-jwt `typ` |
| Must-accept controls | 3 | 1 before this comparison; 8 boundary vectors added since |
| Deterministic ML-DSA-44 | yes, optional | added since |
| Codes no vector reaches | listed with reasons | added since |
| Appendix in RFC 9421 Appendix B style | deferred | yes, folded per RFC 8792 |
| Derivation | bases rebuilt from the draft text | bytes from aauth-rust and aauth-go, rechecked by a harness that uses neither |

PR 46 also showed that PR 48 lacked a request with two signatures, which it
now has.

Both libraries behind PR 48 come from one project. Their agreement shows
that two codebases read the draft the same way, not that the reading is
right. Each vector's `basis` cites the draft lines it rests on, so a reader
can check the reading against the text. PR 46, built from the text without
a signer, is a cross-check on those readings.
