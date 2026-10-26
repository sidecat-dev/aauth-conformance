# Budget scenario hand-back

Scenarios 73–78 grade draft-hardt-aauth-budgets at 70d67375. Scenarios 01–72 are unchanged. The role is still `authorization.federated`, version 1, with no new role. The federated slice is 34 scenarios and 399 assertions. It was 408.

The harness Person Server signs the Access Server request for scenarios 74–78. Scenario 73 is the one native Person Server grant. `gofmt` was run on the edited Go files. `rustfmt` is not installed here; `adapters/rust/src/federation.rs` was checked against the surrounding indent. `go test`, `go build`, and `cargo` were not run.

## What each scenario asserts

### 73 — native four-party grant (10 assertions, unchanged)

The Resource offers 5000000 credits. The native Person Server narrows that offer to 2000000. The Access Server echoes 2000000. The protected call on `{path}-budget-grant` costs 1000 and leaves remaining 1999000.

This is the narrowing chain: Resource offer, Person Server parameter, Access Server claim, metered protected call. It is the only native Budget grant, so a standing ceiling is not asked to issue 2000000 again while an earlier allocation is still outstanding.

Header `cost` is optional in the draft. This fixture knows the cost before it writes the header, and the scenario grades that header.

### 74 — omission (6 assertions)

`harness_ps` is set. The authorization body still offers 9000000 credits. The harness Access Server request has no `budget` member. The Access Server response is HTTP 200 and its auth token has no `budget` claim. That is the omission rule: a resource token carried `budget`, the parameter was left out, and the issuer must not add a claim. The protected call uses `{path}-budget-omit`, which is not metered, and returns `directed-person-1`.

The Rust adapter serves that path from the plain Resource. It does not meter the call and does not clear outstanding allocations there. Clearing outstanding stays on the scenario's initial GET, which is the scenario boundary. The Go adapter already leaves this path unmetered. Its behavior was not changed.

### 75 — consumption (11 assertions)

`harness_ps` is set. The harness sends one per-token allocation of 2000000 credits, and the Access Server echo is graded on `access` (2000000 credits, decimals 0). The protected call costs 1500000 and leaves remaining 500000.

The same-scale step-up is HTTP 401. Its Resource token offers 5000000 credits and carries `budget_consumed` of 1500000 whose `jti` is the presented auth token and whose claim has those two members. Remaining stays 500000, so the refusal does not draw the grant down.

`step-up-other` sends the same 1000000 cost with unsigned `X-Fixture-Offer: points` and must be HTTP 401. `fed-consumed-if-present` passes when `budget_consumed` is absent. When the claim is present, `consumed` must be 1500000, the claim must have exactly two members, `jti` must match the presented auth token, and that same Resource token's `budget` must be credits at decimals 0. A record in another scale fails.

The Go adapter switches the offer to points and omits the record. The Rust library offers the scale declared at challenge time and omits a record whose unit differs. With the adapter's unit switch still in place, both omit the record and pass. A library that stays on credits and attaches the record also passes.

Attaching `budget_consumed` on a refusal is a SHOULD. The same-scale assertion is where the MUST shape is graded: the record's `jti`, its `consumed` value, and the same unit and decimals as the `budget` claim in that Resource token.

### 76 — reserved header (11 assertions)

`harness_ps` is set. The Access Server echo on `access` is 2000000 credits. The reserved call holds 800000 and settles 400000. The header is remaining 1200000, reserved 800000, and no cost.

The cost-only trailer is graded when a trailer field is present: `cost` 400000, and `remaining` and `reserved` absent. When no trailer field is sent, those checks pass. If a trailer field is sent, the `Trailer` header must list `AAuth-Budget`. Both current adapters send the trailer, so they are still graded on its contents.

The following call holds 100000 and settles 100000. Header remaining is net of the new hold: 2000000 - 400000 - 100000 = 1500000, and reserved is 100000. A recipient that never saw the trailer can recover its cost as 1200000 + 800000 - 1500000 - 100000 = 400000, because the later remaining reflects the commit, the release, and the new hold.

### 77 — usage (15 assertions)

`harness_ps` is set. The protected call on `{path}-budget-usage` costs 1000. Before that charge the runner posts `usage-baseline` for the known subject and Person Server. That stage is recorded and not asserted. After the charge, `usage-delta` requires `all_time` to have risen by 1000. An omitted `usage` object on the baseline counts as 0. A missing `all_time` after the charge fails.

The ledger key is `(ps, sub, aud)`. `all_time` is everything metered under that key, including earlier scenarios in the same process. A split per-path ledger (0 then 1000) and a single ledger (sum then sum + 1000) both pass. The scenario does not require a fresh store.

The usage response is graded for audience `https://access.conformance.test`, unit `credits`, and decimals 0. An unrecognized subject returns 200 and omits `usage`. `json-path` null means the path is absent; a present JSON null fails. The unknown-subject response still reports credits at decimals 0. A scope key without `ps`, and a body with both `sub` and `tenant`, are HTTP 400 `invalid_request`. An unknown thumbprint is `"jkts": {}`.

### 78 — per-token cap (10 assertions)

`harness_ps` is set. Each auth token is its own cap. The first protected call costs 1500000 and leaves remaining 500000. The second auth token is another harness Access Server POST with the same 2000000 allocation, not a native Person Server `/token` exchange and not the relay. It also costs 1500000 and leaves remaining 500000. A later 1000000 on the first token is HTTP 401 and leaves that token's remaining at 500000.

## What was dropped

- Scenario 74 dropped `token-status`, `token-jwt`, and `token-budget`. The harness Person Server has no `token` stage. `access-status` 200 was added. `access-budget` null stayed.
- Scenario 75 dropped `token-budget` (replaced by `access-budget`), `other-budget` (a required points offer), and the old `other-consumed` that required the record to be absent.
- Scenario 76 dropped the five `abandoned` assertions: status 200, remaining 1100000, reserved 500000, cost absent, and trailer cost 500000. The required trailer cost became `sfv-trailer-if-present`. `trailer-declared-if-present` was added. Following remaining changed from 1000000 to 1500000 because the abandoned hold is no longer spent. `token-budget` moved to `access-budget`.
- Scenario 77 dropped `usage-cache` (`Cache-Control: no-store`) and `usage-unsigned` (no `Signature` header). `usage-all-time` changed from an absolute `json-path` of 1000 to `usage-delta` of 1000.
- Scenario 78 dropped no assertion. The second token is issued by the harness.

## What the draft leaves open

Signing a usage response is RECOMMENDED. An absent `Signature` passes, and this harness does not check that a present signature covers `@status`, content-type, content-digest, and `@authority` / `@path`. `Cache-Control: no-store` is required on the 202 pending response, not on the usage query.

A streamed response SHOULD send `reserved` in the header and `cost` in the trailer. A resource that cannot send trailers sends `reserved` alone and passes. When a trailer is sent, it must be cost only, and `Trailer` must list `AAuth-Budget`. A recipient must not treat the trailer as necessary.

Whether a call that fails draws down, and whether an unsettled hold is committed in full, is the resource's metering policy. The old abandoned stage committed the whole hold. That is fixture policy, so the stage is gone.

Omission is what a Person Server that does not implement the extension sends. A budget-aware native Person Server is not required to drop the parameter. Scenario 74 makes the harness omit it and grades the Access Server.

Until a figure arrives, an issuer that holds a ceiling accounts the allocation as fully consumed. A long-lived native Person Server will not reissue 2000000 while a prior allocation is outstanding. Scenarios 74–78 therefore send a fresh per-token allocation from the harness. The draft also permits the Access Server to lower that amount. Both current servers echo 2000000, and the scenarios grade that echo.

These rows are still ungraded: the Person Server copying unit and decimals unchanged on the relay body, a negative case that injects `budget` into delivery, `as_of` and the scope-key echo on the usage response, and the header carrying the unit and decimals pair. `budget_units` and `usage_endpoint` metadata are not read; `/authorize` and `/usage` are fixed. The Go adapter's offer-unit switch is process-global, and its Person Server and Access Server declare credits while the Resource declares points. Those fixture details stayed. Cost and remaining assertions remain under the existing clause ids. No clause was added.

A step-up Resource token is stored only when the fixture bindings verify (signature, presented `jti`, subject, agent thumbprint, `iat` equal to the fixture clock, scope `read`, and no mission, tenant, or account claim). `budget` and `budget_consumed` are allowed. A binding failure is an execution error, so an invalid token cannot satisfy the consumption assertions.

## Rust main 704effbf

`704effbf` is not an object in this checkout. `git ls-remote` to the sprint GitLab host did not resolve, and the HTTPS remote asked for a username. `upstream-merge.log` records merge request !19, source `e8d9ba7`, merged as `704effbf`.

That tree's usage response is signed and carries `Cache-Control: no-store`. Scenarios 73–78 do not require a signature and do not require `no-store` on the usage query, so that tree is not failed for either choice.
