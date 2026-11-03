# Signature-Key test vectors

Test vectors for HTTP Signature Keys (`draft-hardt-httpbis-signature-key`),
in the shape asked for in
[dickhardt/signature-key#25](https://github.com/dickhardt/signature-key/issues/25).
They cover every scheme and algorithm that both aauth-rust and aauth-go
implement, the draft's MUST-reject rules with the `Signature-Error` code
each one fixes, must-accept boundary cases one step from those rules, and
ML-DSA-44.

- [`signature-key-vectors.json`](signature-key-vectors.json) is the
  machine-readable set. It is authoritative and needs no network access.
- [`APPENDIX.md`](APPENDIX.md) is the same set for reading, in the style of
  RFC 9421 Appendix B, with long lines folded per RFC 8792.

The expectations come from the pinned drafts, not from either library:
signature-key at `69f5ba2` and the AAuth protocol at `70d6737`, with their
SHA-256 in the file's `drafts` member. Where the signature-key draft leaves
an error code open, the AAuth protocol's Verification (Server) steps fix it,
and each vector's `expect.basis` cites the lines. The vectors are MIT
licensed, as the rest of this repository.

## How a vector is evaluated

1. Build the received request: `request` with the `signed` header fields
   added.
2. Evaluate it as if the current time were `now`, with the `verifier`
   configuration: the Resource at `verifier.resource`, label `sig`, a
   60-second window, the listed schemes and algorithms. A vector with
   `signatures` replaces label `sig` with every label it lists: each is
   verified over its own base.
3. Resolve keys only from the documents: the file's `documents`, with the
   vector's own `documents` replacing any at the same URL. x509 chains are
   documents too; the trust anchors and CRLs are in `x509`.
4. Compare with `expect`.

| `expect.outcome` | Passes when |
| --- | --- |
| `verify` | the request verifies; for a vector with `signatures`, every listed label verifies |
| `reject` | the request is refused, with `Signature-Error` `error` equal to `expect.error`; an absent `error` means the drafts fix no code, so any `Signature-Error` passes |
| `verify-or-reject` | the request verifies, or is refused with `expect.error`. Used for the two ML-DSA-44 requests: a verifier that does not implement ML-DSA-44 must decline with `unsupported_algorithm`, never fail in an undefined way |

`expect.required_input_includes` names components a refusal's
`required_input` should list (RECOMMENDED, so not required to pass).

A vector with an `optional` member may be skipped for its category check;
the member says why and what is still graded. Only
`jwks-ml-dsa-44-deterministic` has one.

## Categories

Every vector carries the category issue 25 defines.

| Category | Meaning | What to check |
| --- | --- | --- |
| 1 | key handling | the key selection or refusal |
| 2 | verify-only | the signature verifies. ECDSA and RSA-PSS signatures are randomized: never recompute and compare them (RFC 9421 Section 3.3.4) |
| 3 | reproduce-the-bytes | Ed25519 and RS256 are deterministic: signing `signature_base` with the private key gives exactly `signed.Signature`. So is ML-DSA-44 in the FIPS 204 deterministic variant, which the ML-DSA-44 vectors use |

The file has 2 vectors in category 1, 19 in category 2 and 46 in category 3.

## Members

Top level:

| Member | Content |
| --- | --- |
| `drafts` | the pinned drafts: name, commit, SHA-256 of the file, URL |
| `generated` | the library revisions that signed and checked this file, and the harness |
| `verifier` | the verifier configuration every expectation assumes |
| `keys` | every key: `id`, `alg`, `public_jwk`, `private_jwk`, the Ed25519 or ML-DSA-44 `seed_hex` or the EC or RSA `pkcs8_base64`, and the `derivation` that reproduces it |
| `documents` | the default documents a verifier can fetch: `url`, `content_type`, `body` |
| `x509` | the x509 trust anchors and CRLs, DER, base64 |
| `vectors` | the vectors, in the order below |

Each vector:

| Member | Content |
| --- | --- |
| `id`, `title` | name; an id ending in `.rust` or `.go` is one library's signature where both signed and the signatures differ (category 2) |
| `category` | 1, 2 or 3, as above |
| `scheme`, `alg` | the selected member's scheme and the request signature algorithm; a vector with `signatures` has no `scheme` |
| `now` | the verification time, Unix seconds |
| `request` | the request before signing: `method`, `url`, `headers`, `body` |
| `signed` | the header fields signing added: `Signature-Input`, `Signature`, `Signature-Key` and, with content, `Content-Digest` |
| `signature_base` | the RFC 9421 signature base for label `sig`, verbatim, with `signature_base_sha256` and `signature_base_length` |
| `signature_verifies` | whether `Signature` verifies over the base under the key the member conveys, when that key is well formed. It separates a canonicalization fault from a crypto fault |
| `signing_key` | the `keys` id that produced the signature; absent with `signatures` |
| `signatures` | only on a request carrying more than one signature: per label, its `scheme`, `alg`, `signing_key`, `signature_base` with its SHA-256 and length, `signature_verifies` and `resolves`. The top-level `signature_base` is then absent. RFC 9421 leaves the label out of the base, so two signatures over the same components and parameters have the same base and differ only in key and signature |
| `assertion` | for jwt, jkt-jwt and self-jwt: the compact JWT, its decoded header and payload, and the key that signed it |
| `documents` | documents that replace the defaults for this vector |
| `resolves` | the document URLs key resolution reads |
| `expect` | `outcome`, `error`, `basis` (the draft lines) |
| `optional` | on a vector whose category check an implementation may skip: why, and what is still graded |
| `provenance` | `signed_by` (`aauth-rust`, `aauth-go` or `harness`), `reproduced_by` (libraries that produced the same bytes), `mutation` and a `note` |

## Fixed values

- `now` is 1800000000 for every vector, and `created` equals it except in
  the four window vectors. jwt and jkt-jwt assertions are issued 300
  seconds before `now` and expire 3000 seconds after; self-jwt assertions
  are issued 30 seconds before and expire 300 seconds after. The vectors
  for an expired assertion, a missing `exp`, an `exp` one second after
  `now` and an `nbf` equal to `now` change them, as their titles say.
- The names are example domains: `resource.example`, `agent-provider.example`,
  `signer.example`, `keys.example` and `certs.example`.
- The jwt vectors carry an AAuth agent token (`typ` `aa-agent+jwt`), so the
  jwt scheme's deployment `typ` policy is AAuth's. The self-jwt `typ` is
  `vector-self+jwt`.
- Ed25519 and ML-DSA-44 seeds are SHA-256 of
  `aauth-conformance signature-key vectors <key id>`; P-256 and P-384
  private scalars are SHA-256 and SHA-384 of that string. The RSA keys are
  this suite's fixture test keys. Every key is a public test key.
- The x509 root and both end-entity certificates are signed with the
  Ed25519 root key, so their DER is reproducible.

## Boundary vectors

A set of refusals alone cannot catch a verifier that over-blocks: one that
rejects everything passes every negative. The eight `accept-*` vectors sit
one step from a MUST-reject rule and must verify. Each title starts
"boundary, must verify", and each `expect.basis` cites the line that puts
the boundary there.

| Vector | One step from |
| --- | --- |
| `accept-created-window-ahead` | `created` 60 seconds ahead; 61 is `clock_skew` (protocol line 2246, signature-key line 1106) |
| `accept-created-window-behind` | `created` 60 seconds old; 61 is `invalid_signature` (protocol line 2246, signature-key line 1114) |
| `accept-jwt-exp-next-second`, `accept-jkt-jwt-exp-next-second`, `accept-self-jwt-exp-next-second` | `exp` one second after `now`; `exp` at `now` has expired (signature-key line 1086, protocol line 2317) |
| `accept-jwt-nbf-now`, `accept-jkt-jwt-nbf-now`, `accept-self-jwt-nbf-now` | `nbf` equal to `now`; one second later is not yet valid (RFC 7519 Section 4.1.5, which the drafts apply to every JWT: protocol line 2313, signature-key lines 1194-1198) |

The `iat` bound has no boundary vector: a verifier is not required to bound
`iat` (signature-key line 1114), so no `iat` must be refused.

## ML-DSA-44

Two vectors carry an ML-DSA-44 request signature, both `verify-or-reject`
with `unsupported_algorithm`: a verifier that implements ML-DSA-44 verifies
them, and one that does not must decline with that code (signature-key line
233).

- `jwks-uri-ml-dsa-only` (category 1) resolves a jwks_uri whose only key is
  ML-DSA-44.
- `jwks-ml-dsa-44-deterministic` (category 3) resolves a jwks key and is
  signed with the FIPS 204 deterministic variant (rnd all zeros, empty
  context), the only form whose bytes reproduce. It is `optional`: most
  libraries do not expose the deterministic variant, so a signer without
  it may skip reproducing the bytes, and verification is graded the same
  either way.

Neither aauth-rust nor aauth-go signs with ML-DSA-44, so the harness signs
both. The key's seed is in `keys`.

## How the set was produced

Each positive case is signed by both libraries through their native signers
(aauth-rust `sign_requests`, aauth-go `SignRequests`), at the fixed
`created`. The harness in `internal/conformance` then checks every output
with its own code, using only the Go standard library: it rebuilds the
signature base from the received request, verifies the signature, and
compares `Signature-Input`, `Signature-Key` and `Content-Digest` with what
the drafts give.

- Deterministic cases are published once when both libraries produce the
  same bytes; `reproduced_by` names the second library.
- Randomized cases are published once per library, so each library's
  signatures are verified by the other.
- A negative vector is one library's signed request with the defect
  applied (a flipped signature bit, a renamed label, an expired or malformed
  assertion, a changed document). Where no conforming signer can produce the
  defect, the harness signs it, and `provenance.note` says why.
- The harness signs 10 vectors: the 8 negatives no conforming signer
  produces and the 2 ML-DSA-44 vectors, which it signs with Go's
  `crypto/mldsa` in the deterministic variant.

The `vectors.signature-key` role then runs every vector against each
library's native verifier (see the repository README). A multi-signature
vector is verified label by label with each library's request verifier:
aauth-go `PrepareRequest` with `SignatureLabel`, aauth-rust
`PreparedRequest::prepare_with_schemes` with the label, then the verifier
the member's scheme calls for. The set is published only when both
libraries agree.

To check this file against the libraries, or to regenerate it:

```sh
go run ./cmd/build-adapters -role vectors.signature-key -go-source /path/to/aauth-go -rust-source /path/to/aauth-rust -claim-recommended -out build/sigvec
go run ./cmd/sigkey-vectors -targets build/sigvec/targets.json -check
go run ./cmd/sigkey-vectors -targets build/sigvec/targets.json -write
```

`-check` re-signs every vector with the published assertions and reports
any byte that differs, apart from randomized signatures. `-write` replaces
the file, its scenarios (`scenarios/5xx-sigvec-*.json`) and `APPENDIX.md`.
`go test ./internal/conformance -run Sigvec` re-derives every key, rebuilds
every signature base and checks every signature without either library.
The ML-DSA-44 key needs Go 1.27 or later (`crypto/mldsa`).

## Codes a static file cannot reach

The draft registers 14 `Signature-Error` codes. The vectors expect 12 of
them. No vector expects these two:

- `invalid_request`: the request lacks something the application requires,
  unrelated to the signature (signature-key line 1038). The draft does not
  say what an application requires, so no file can fix a request that
  lacks it.
- `revoked_jwt`: the verifier holds notice from the issuer that a valid,
  unexpired JWT was withdrawn (line 1094), and how it learns of that is out
  of scope (line 1102). A file can carry the JWT but not the notice.

Three codes are reached only in part:

- `clock_skew` is expected for a `created` ahead of the window, not for an
  `iat`: bounding `iat` is optional for a verifier (line 1114).
- `cache_miss` is expected for an identifier the verifier never issued. A
  cache hit needs an identifier that verifier issued earlier.
- `invalid_key` is expected for a key that disagrees with its `alg`, not
  for one that fails the verifier's trust requirements (line 1046), which
  are its own policy.

## Not covered

- Live endpoints: every document is in the file.
- A `nonce` parameter is signed by aauth-go only; aauth-rust's signer does
  not offer one, and verifies the vector.
- Multiple signatures beyond `multi-hwk-jwks`: which labels a verifier
  checks is application context (signature-key lines 173 and 181), so that
  vector's verifier is configured to verify `sig1` and `sig2`, as its title
  and basis say. The launchers take that label list from the verify job. With label `sig` configured and a
  second label present, the drafts fix no result: aauth-rust verifies `sig`
  and ignores the other, and aauth-go's Resource refuses the request with
  `invalid_signature`. That case is left out until the draft settles it.

## Compared with PR 46

[reports/signature-key-vectors-pr46-comparison.md](../../reports/signature-key-vectors-pr46-comparison.md)
compares this set with the one proposed in
[dickhardt/signature-key#46](https://github.com/dickhardt/signature-key/pull/46).
The boundary vectors, the deterministic ML-DSA-44 vector and the list of
codes above come from that set.
