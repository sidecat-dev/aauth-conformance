# Budgets implementation report

This report says what two implementations do with `draft-hardt-aauth-budgets`, and where they disagree. The test vectors that both compute are in [`vectors/budgets/`](../vectors/budgets/).

## Draft

The report is against `draft-hardt-aauth-budgets` at commit `70d67375deb0bb002af7da0711fc58f6e8926e7e`, dated 3 October 2026:

<https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-budgets.md>

The SHA-256 of that file is `f00d34c91576476cdb30b7aa1aa13a0bc9fc1d99fc43b4f0389ccb3e8bf2e150`.

Implementation Status says implementation reports and test vectors are expected from the efforts named there and will be recorded in that section. The section records none.

## Implementations

- aauth-go main, revision `567e556af2bd7fc931143e679dd228b709111797`. Budget objects, narrowing, the `AAuth-Budget` field, trailers, and usage queries are in package `budgets`. Metering is `resource.BudgetStore` and `resource.BudgetReserver`. The Person Server is package `personserver`. The Access Server is package `accessserver`. The previous revision `ad34a9ad148cd2dd0f96b77e387c4fd22a3ca535` refused `remaining=999999999999999, cost=0` because `httpsfv` v1.1.1 rejects a 15-digit integer when another character follows it. That field is now accepted.
- aauth-rust `v0.1.0-alpha.29`, revision `b60eac37fe686b7069e0d464254acf7564c071c5`. The profile crate is `aauth-rust-budgets`. The Resource is `aauth-rust-resource`. The Person Server is `aauth-rust-person-server`. The Access Server is `aauth-rust-access-server`. The previous release, `v0.1.0-alpha.28` (`ed4671b6a6b03993480a1b7fa8ca156c6ae607bd`), accepted seven of the cases under Findings that both now refuse, and refused a 16-digit hold before comparing it with the grant. The aauth-rust issues #1 to #6 recorded them.

A vector is published only when both libraries return the same parsed result. Header field text and compact budget JSON are recorded for each library when the bytes differ. Member order is not treated as a disagreement. The two cases where the results differ are listed under Findings and in `disagreements` in `vectors/budgets/budgets-vectors.json`. They are not expected results.

## Budget object

The draft's budget object is `amount`, `unit`, and `decimals`. `amount` is a non-negative integer. Implementations MUST NOT issue an amount above 999999999999999. `decimals` is a non-negative integer. The value is `amount` divided by 10 raised to `decimals`, in `unit`.

aauth-go parses one object with `budgets.ParseValueJSON` and emits one with `Value.MarshalJSON` (`budgets/value.go`). `decodeStrictJSON` rejects a second JSON value, an unknown member, and a duplicate member. `validateAmount` rejects a negative integer and an integer above `MaximumAmount`, which is 999999999999999. `NewUnit` rejects an empty unit and a negative or fractional scale.

aauth-rust parses with `parse_budget_bytes` and builds with `Budget::new` (`aauth-rust-budgets` `value.rs`). `check_amount` applies the same 15-digit limit, `MAX_AMOUNT`. Unknown members, duplicate members, and a JSON number written with a fraction are `Error::Malformed`.

Both accept a zero amount, the object in the draft's example (`5000000`, `USD`, `6`), the object in the auth-token example (`2000000`, `USD`, `6`), the amount 999999999999999, and a scale of zero. Both accept an object whose members arrive in another order, and both accept insignificant whitespace around one object. The parsed `amount`, `unit`, and `decimals` match. The compact JSON does not: aauth-go emits `amount`, `unit`, `decimals`; aauth-rust emits `amount`, `decimals`, `unit`. Both strings are in the vector.

Both refuse a missing member, an empty object, a negative amount, a 16-digit amount, a fractional amount, an amount written as `1.0`, an amount written as a string, an empty unit, a negative scale, a fractional scale, an unknown member, a duplicate `amount`, two JSON values, JSON null, a JSON array, and a bare JSON number.

## Narrowing

The draft says each stage MUST NOT exceed the previous stage. The resource settles `unit` and `decimals`. A later party MUST NOT change them and MUST NOT raise `amount`. An agent request is optional. Omitting it means the resource applies its own default. A request above what the resource will grant is not an error; the resource narrows.

Both compare two objects with the same rule. aauth-go uses `budgets.ValidateNarrowing`. aauth-rust uses `validate_narrowing`. An equal amount, a lower amount, and a zero amount are accepted. A higher amount is refused (`exceeds`). A different unit or a different scale is refused (`denomination`).

aauth-go checks a value against `budget_units` with `budgets.ValidateDeclaredValue` (`budgets/metadata.go`). A unit that is not declared, or a scale that differs from the declaration, is an error. When the declaration has `max` and the amount is above it, the function returns `value exceeds unit metadata maximum`. On the Resource, `BudgetConfig.InitialOffer` and `BudgetConfig.Offer` are host callbacks (`resource/budget.go`). `initialOfferFor` returns no offer when `InitialOffer` is nil. When the callback returns a value, `ValidateDeclaredValue` checks it. The library does not choose a default amount.

aauth-rust sizes a resource offer with `offer_budget` (`value.rs`). An omitted request uses `default_offer` of the first declared unit, capped by that unit's `max` when `max` is present. A request in a declared unit is narrowed to that unit's `max` when `max` is lower. An unknown unit is `Error::UndeclaredUnit`. A scale that differs from the declaration is `Error::DecimalsMismatch`. `check_declared` checks that a signed budget names a declared unit at the declared scale. An empty declaration list accepts the signed scale. `check_declared` does not compare `amount` to `max`. `narrow_to` copies `unit` and `decimals` and lowers `amount` to a cap when the cap is lower.

## Metering

The draft has the resource reserve a maximum before it serves, commit the cost it learns, and return the unspent part of the hold. A refusal MUST NOT draw the budget down and carries no `cost`. `remaining` is already net of reservations.

aauth-rust meters with `Ledger` (`ledger.rs`). `open` records a grant. `reserve` holds a maximum. `commit` posts a cost up to that hold and releases the rest. `release` drops a hold and posts nothing. `outstanding` returns the committed total and the reserved total. `remaining` in the vectors is the grant minus those two. A hold larger than a positive remainder is `Refusal::Insufficient`. A hold against a zero remainder is `Refusal::Exhausted`. A cost above the hold is `ChargeError::Protocol` and the hold stays in place until `release`. A negative hold is `ChargeError::Protocol`. A hold above 15 digits exceeds every grant, so it is `Refusal::Insufficient`, or `Refusal::Exhausted` against a zero remainder, and the refusal header omits `required`. A hold of zero is accepted when the remainder is positive, and the reserved total does not change. `open_directory` keeps a snapshot across process exit. The comment on that function says a torn write is recovered from the previous snapshot, and that this is not power loss. There is no separate fixed-price charge method on `Ledger`. The Resource settles a known cost by reserving and then committing.

aauth-go has no ledger type in package `budgets`. The Resource meter is `resource.BudgetReserver`: `Reserve`, `Commit`, `Release`, and the fixed-price `Charge` on `resource.BudgetStore` (`resource/budget.go`). The vectors call `testutil.NewBudgetStore` (`testutil/budget.go`), which implements that interface. `Reserve` rejects `Hold <= 0` with `ErrBudgetReservation` and does not change the account. A hold above the remainder is `ErrBudgetInsufficient` when the remainder is positive and `ErrBudgetExhausted` when it is zero. That comparison is also what a 16-digit hold hits. `Commit` rejects a cost above the hold, or an unknown hold, with `ErrBudgetReservation`. `Charge` posts a fixed cost with no preceding hold.

The sequences both compute the same way are: reserve then commit part of the hold; refuse a later hold that does not fit; exhaust the grant; release a hold; commit zero; commit more than the hold and then release it; two holds; two tokens; a hold equal to the remainder; a hold against a spent grant; a negative hold; a hold above 15 digits; and a commit of a hold id that was never reserved. After each step the remaining figure is the grant minus what has been committed minus what is still reserved. A refusal leaves that remaining figure unchanged.

## AAuth-Budget header

`AAuth-Budget` is an RFC 9651 Dictionary. `remaining` is required. `cost`, `reserved`, `required`, and the `unit`/`decimals` pair are optional. `reserved` is meaningful where `cost` is not yet known, and it is required where `cost` is omitted. `required` is sent only with `reason=insufficient-budget`, where it is recommended. Recipients MUST ignore members they do not recognize. A sender MUST include both `unit` and `decimals`, or neither. A resource MUST NOT omit both `cost` and `reserved` on a served metered response. A trailer MUST list `AAuth-Budget` in `Trailer`, MUST carry `cost` and nothing else, and MUST NOT restate a header member. A recipient MUST NOT treat the trailer as necessary. Recipients MUST ignore the field on a response served from cache with a positive `current_age`.

Both parse the draft's examples: the success field with `cost` and `remaining`, the streamed field with `remaining` and `reserved`, the exhausted field with `remaining=0`, and the insufficient field with `remaining` and `required`. Both accept those fields with the members in the other order, with no space after a comma, and with the unit pair omitted. Both accept `cost=0` and `reserved=0`. Both ignore an unrecognized member. Both refuse an empty field, a field with no `remaining`, a negative integer, a 16-digit integer, a string, a decimal, a boolean, or a token where an integer is required, a unit without `decimals`, `decimals` without a unit, an empty unit, a parameter on a member, a dictionary written with semicolons, and a duplicate `remaining`. Both refuse `required` together with `cost` or with `reserved`, and `required` equal to or below `remaining`. aauth-go refuses `cost` together with `reserved`; aauth-rust accepts it, with `cost` within `reserved`. That case is under Findings.

Both format the same four examples. aauth-go builds them with `NewSuccessFeedback`, `NewReservedFeedback`, and `NewRefusalFeedback`, then `FormatFeedback` (`budgets/feedback.go`). aauth-rust builds them with `BudgetHeader::final_cost`, `reserved_hold`, and `refusal`, which take the grant, then `sender_field` (`header.rs`). Both refuse to format a success field whose `cost` and `remaining` sum above the grant, and a refusal whose `required` is not above `remaining`. Neither writes `cost` and `reserved` on one field. The parsed members match. The field bytes differ by member order. aauth-go writes `cost` before `remaining`. aauth-rust writes `remaining` before `cost`. The draft's own examples use both orders. Both strings are in the vectors. RFC 9651 does not fix dictionary member order.

aauth-go parses the field with `ParseFeedback`, which calls `httpsfv.UnmarshalDictionary` from `github.com/dunglas/httpsfv` v1.1.1. aauth-rust parses with `parse_header`. Unknown header members are dropped on both sides. `parse_header` takes `current_age`. A missing age, or an age of zero, leaves the field actionable. An age above zero sets `actionable` to false. `act_on_header` then returns no remaining figure. `budgets.ParseFeedback` does not take an age. The aauth-go agent, in `responseCarriesAge` (`agent/budget.go`), drops Budget feedback when the response has an `Age` header. A present `Age` of zero is included. The parser and the agent are different layers: the parser returns the members, and the agent discards them when `Age` is present.

A trailer is `cost` and nothing else. aauth-go emits it with `FormatTrailer` and merges it with `ApplyTrailer`. aauth-rust emits it with `trailer_field`, which also sets the `Trailer` header value to `AAuth-Budget`. Both accept the draft's cost-only example, a zero cost, and a cost inside a preceding `reserved` hold. Both refuse a negative cost, a 16-digit cost, a cost above the header's `reserved`, and a trailer that restates a header that already carried `cost`.

## Usage queries

The draft's usage endpoint is how a Person Server or Access Server reads counters.

aauth-go parses a request with `budgets.ParseUsageRequest` and checks a response with `budgets.CheckUsageResponse` (`budgets/usage.go`). The Resource reads the body in `resource/usage.go` and queries a store that implements `resource.BudgetUsageStore`.

aauth-rust parses a request with `parse_usage_query`, builds the counters with `answer_usage`, and signs the response with `sign_usage_response` (`usage.rs`).

The vector file does not include usage requests. The two libraries were not run against each other on those bodies.

## Person Server

aauth-go checks an authorization decision with `validateBudgetDecision` (`personserver/server.go`). A decision that names a budget when the resource token carried none is rejected: the decision cannot invent a budget. A decision that omits the budget when the resource token carried one is rejected. A decision that raises the amount, or changes `unit` or `decimals`, is rejected through `ValidateNarrowing`. An equal or lower amount is kept. Direct issuance sizes each auth token from that token's own resource-token offer. A federated Person Server that is asked to authorize a delegated budget refuses the request. The error text is `federated Budget does not compose with delegation`.

aauth-rust accounts grants when `Server::with_budgets` is given an `IssuerPolicy` (`aauth-rust-person-server` `server.rs`). `policy.cap` is the per-token maximum. `policy.omit_above` omits the four-party PS-to-AS parameter when the resource offer is above that limit. Three-party issuance still narrows to the cap and counts the grant. `issue_auth_budget` (`issuer.rs`) issues no budget claim when the four-party parameter is omitted. A parameter with no resource offer is `Error::Malformed`. The issued amount is `narrow_to` of the parameter and the policy cap, so it is not above either. `verify_delivered` rejects a sent parameter that comes back missing, and an omitted parameter that comes back as a claim, as `Error::Malformed`. A claim that changes the denomination or raises the amount is `Error::Denomination` or `Error::Exceeds`.

## Access Server

aauth-go selects the ceiling with `selectBudgetCeiling` (`accessserver/budget.go`). No resource offer and no Person Server ceiling issues no claim. A Person Server ceiling with no resource offer is an error: the request cannot invent a budget. A resource offer with no Person Server ceiling issues no budget claim. The comment on that branch says omission means the Person Server is not granting a budget. A ceiling that is present must narrow the offer: `ValidateNarrowing` rejects a higher amount or a different denomination. `validateBudgetDecision` applies the same rule to the authorization decision. A decision cannot invent a budget, and it must preserve a ceiling that was selected.

aauth-rust reads the PS-to-AS parameter in `budget_parameter` and writes the auth-token claim in `issued_extra` (`aauth-rust-access-server` `lib.rs`). Both call `issue_auth_budget`. Omitting the parameter issues no `budget` claim. A parameter that does not narrow the resource offer is `invalid_budget`. A parameter with no resource offer is `invalid_budget`.

## Resource

aauth-go enables the profile with `resource.BudgetConfig`. `Metered`, when nil, selects every protected route. A route the callback rejects is not charged. When the route is metered and the auth token has no budget grant, `resource/protected.go` writes `403` `access_denied` with `metered route requires a signed Budget grant`. It does not substitute an amount. When a grant is present, `budgetResponseWriter` attaches the field. A fixed price uses `Cost`. A variable price uses `Maximum`, which reserves before the handler runs. Settlement after the response header is written sends a cost-only trailer. Settlement before that write sends `cost` on the header. An unsettled request commits the whole hold.

aauth-rust enables the profile with `Server::with_budgets` on the Resource. `admit_auth` (`ps_authorization.rs`), when no budget grant is on the auth token, finishes admission without opening a ledger. The request is not metered, and no amount is invented. `budget_gate.admitted_cost` reads one `AAuth-Max-Cost` structured-field integer when the client sends it. The host `default_bound` is the ceiling. A client value above that ceiling does not raise it. A client value of zero is not treated as a free admission when the host bound is positive: the admission is refused, exhausted when nothing remains and insufficient otherwise. The draft does not define `AAuth-Max-Cost`. aauth-go does not read that header. The aauth-go bound is the host `Cost` or `Maximum` callback.

`metered_access_mode` in aauth-rust accepts only the access mode `auth-token`.

## Suite coverage

The coverage figures come from `conformance-map.edn` in aauth-conformance at `f415f2f8e18bebb2b4b6928d96c80d999244e72a`. The map links keyword sentences of this draft to suite scenarios. It does not record whether a hosted run exercised those scenarios. That result is in the next section.

The map has 151 entries for this draft: 79 MUST, 23 SHOULD, 41 MAY, and 8 clause records that carry no requirement level. Of the 79 MUST sentences, 34 are reached by at least one scenario and 45 are reached by none. A sentence can be reached by more than one scenario. The count each scenario reaches is:

| Scenario | MUST sentences it reaches |
| --- | --- |
| `budget-header` | 17 |
| `budget-usage` | 12 |
| `budget-consumption` | 10 |
| `budget-four-party-grant` | 8 |
| `budget-hard-cap` | 8 |
| `budget-four-party-omission` | 5 |

Two of the 34 reached sentences use MUST or REQUIRED and then lower the requirement. Line 637 says "This is SHOULD rather than MUST" about including the field on every response. Line 1057 says "It is RECOMMENDED rather than REQUIRED" about signing a usage response. The map still lists both sentences at MUST because those words occur in them.

The 45 MUST sentences no scenario reaches, by section and map id:

- `budget-is-scope`: `budgets:259`, `budgets:261`
- `narrowing-chain`: `budgets:267`, `budgets:301.2`, `budgets:305`
- `range-limits`: `budgets:326`
- `budget-object`: `budgets:344`, `budgets:345`, `budgets:346`
- `budget-units`: `budgets:382`, `budgets:383`, `budgets:383.2`, `budgets:385.2`, `budgets:387`, `budgets:389.2`
- `authorization-endpoint`: `budgets:417.2`, `budgets:419`
- `ps-responses`: `budgets:538`
- `auth-token`: `budgets:601`, `budgets:602`, `budgets:603`, `budgets:607`, `budgets:608`
- `cost-omitted`: `budgets:682`, `budgets:692`
- `ambiguous-failure`: `budgets:710`
- `exhaustion`: `budgets:724`
- `required-member`: `budgets:765`
- `exhaustion-deferred`: `budgets:790`, `budgets:793`
- `requires-auth-token`: `budgets:815.2`
- `unreported-allocations`: `budgets:831`
- `aggregation`: `budgets:863`, `budgets:865`, `budgets:867`
- `concurrency`: `budgets:901`, `budgets:902`
- `failed-calls`: `budgets:919`
- `usage-authorization`: `budgets:1063`
- `capability`: `budgets:1085`, `budgets:1087`
- `errors`: `budgets:1105`
- `budget-not-scope`: `budgets:1143`
- `why-not-ratelimit`: `budgets:1302`
- `pa-tpx`: `budgets:1340`

There is no suite role named for Budgets. The six scenarios above are part of `authorization.federated`, which has 34 scenarios and 398 assertions.

## Hosted results

Both hosted reports ran suite `f415f2f8e18bebb2b4b6928d96c80d999244e72a` and exited 0.

- aauth-rust `v0.1.0-alpha.28`, published 2026-11-03T15:52:24Z: <https://aauth.sidecat.dev/reports/rust-v0.1.0-alpha.28/>
- aauth-go `ad34a9a`, published 2026-11-03T15:52:27Z: <https://aauth.sidecat.dev/reports/go-ad34a9a/>

For `authorization.federated`, both reports say execution passed: 62 assertions pass, 336 are `not_exercised`, and none fail. The six Budget scenarios are `not_exercised` on every assertion. The detail on each of those assertions is `uses the launcher's fixed budget paths and X-Fixture cost headers`. The assertion counts are `budget-four-party-grant` 10, `budget-four-party-omission` 6, `budget-consumption` 11, `budget-header` 10, `budget-usage` 15, and `budget-hard-cap` 10. The 62 passing assertions are the other scenarios in the role.

## Findings

Two cases are disagreements. The vector file records both results and does not pick one.

**`cost` and `reserved` on one field.** The field is `remaining=10, cost=4, reserved=8`. aauth-go `ParseFeedback` returns `AAuth-Budget header must not carry both cost and reserved`. aauth-rust `parse_header` accepts it. The draft decides this case for aauth-rust. Line 623 makes `reserved` meaningful only while `cost` is not yet known, so a sender does not write both, and both libraries refuse to format them together. But line 702 says a recipient that merges a `cost` trailer into a header that carried `reserved` "produces a single Dictionary whose keys do not collide", and calls that safe. That Dictionary carries both members. aauth-go's own `ApplyTrailer` builds the same value and accepts it when `cost` is within `reserved`; only `ParseFeedback` refuses it.

**A hold of zero.** aauth-go `testutil` `budgetStore.Reserve` rejects `Hold <= 0` with `ErrBudgetReservation` and leaves the grant unchanged. The vector records that as `rejected`. aauth-rust `Ledger::reserve` accepts a zero maximum when the remainder is positive. The remaining figure stays 500 and the reserved total stays 0. The draft does not decide this case. Lines 911 and 913 refuse a maximum that exceeds the remainder and reserve the maximum, and do not say whether a zero maximum is a reservation.

Eight earlier disagreements are now vectors. aauth-rust `v0.1.0-alpha.29` changed to the reading the draft supports, which aauth-go already took:

| Case | Now | Draft lines |
| --- | --- | --- |
| `header.required-equal`, `header.required-below`, `header.format-required-equal` | both refuse, `malformed` | 621, 624, 743: `required` is the maximum of a request refused because it exceeds the remainder, and `remaining` is a floor |
| `header.cost-and-required`, `header.reserved-and-required` | both refuse, `malformed` | 724, 795: a refusal carries no `cost` and no `reserved` |
| `header.format-over-grant` | both refuse, `malformed` | 621, 909, 913: `remaining` is net of everything committed and held |
| `trailer.cost-above-reserved` | both refuse, `malformed` | 676, 702, 913: `remaining` is a floor only when the cost is within the hold |
| `meter.hold-above-carrier` | both refuse, `insufficient` | 722, 911: a maximum that exceeds a positive remainder is refused as insufficient-budget |

The Go driver now reports aauth-go's three shape refusals (`both`, `required`, `exclusive`) as `malformed`, the README's code for a value that is not the shape the draft requires.

## Editor's notes

Each note is a sentence the draft leaves open, the question both implementations had to answer, and the answer in the code.

**Unknown members of a budget object.** The object section names `amount`, `unit`, and `decimals` and does not say what a recipient does with any other member. The header section says recipients MUST ignore members they do not recognize. The question is whether an additional member of a budget object is ignored or rejected. Both reject it. aauth-go `decodeStrictJSON` uses `DisallowUnknownFields`. aauth-rust `parse_budget_bytes` rejects an unknown member as `Error::Malformed`.

**Duplicate JSON members.** The object section does not say what happens when `amount` appears twice. Both reject the value. aauth-go's strict decoder rejects the duplicate. aauth-rust's strict JSON parse rejects it as `Error::Malformed`.

**An omitted agent request.** "Omitting it means the resource applies its own default." The question is which amount that default is. aauth-rust `offer_budget` uses `default_offer` of the first declared unit, capped by that unit's `max` when `max` is present. aauth-go does not choose a number. `initialOfferFor` returns no offer when `BudgetConfig.InitialOffer` is nil, and otherwise uses the host callback, checked with `ValidateDeclaredValue`.

**An amount above the declared `max`.** `max` is the largest amount the resource will accept on a single auth token, and the resource MUST NOT reject an authorization request because `budget.amount` exceeds what it will grant; it narrows. The question is whether a value above `max` is narrowed or is an error. aauth-rust `offer_budget` narrows a request to `max`. `check_declared` does not compare a signed amount with `max`. aauth-go `ValidateDeclaredValue` returns an error when the declaration has `max` and the amount is above it. The Resource offer path runs that check on the value the host callback returns.

**An auth token that omits `budget` after the resource issued one.** "A resource that issued a `budget` in a resource token and receives an auth token without a `budget` claim MUST treat the request as carrying no budget authorization under this extension and apply its own default." The question is what that default is. Neither implementation invents an amount. aauth-go, on a metered route, responds `403` `access_denied` (`resource/protected.go`). aauth-rust `admit_auth` finishes admission without opening a ledger, so the request is not metered.

**`cost` and `reserved` together.** "`reserved` is meaningful only where `cost` is not yet known." Trailer Rules then describe a merged header and trailer as one Dictionary with both members. The question is whether a field that carries both is rejected. Both libraries refuse to write both on one field. aauth-go also rejects them on parse. aauth-rust accepts them on parse when `cost` is within `reserved`.

**`required` compared with `remaining`.** `required` is "the maximum cost the resource computed for a request it refused", and `insufficient-budget` means that maximum exceeds the remainder. The draft does not state the comparison on the field. The question is whether `required` must be greater than `remaining`. Both now reject `required` less than or equal to `remaining`, on parse and on format, because `remaining` is a floor.

**`cost` or `reserved` together with `required`.** "A refusal therefore carries no `cost`", and the `202` field "carries no `cost` and no `reserved`". The `401` case says only that the resource holds nothing. The question is whether a recipient rejects `cost` or `reserved` together with `required`. Both now reject both combinations.

**Figures that sum above the grant.** The header section does not say a sender must reject `cost` and `remaining` whose sum is above the signed grant. It follows from `remaining` being net of reservations and the hard-cap invariant. Both now refuse to format that field.

**A trailer cost above `reserved`.** The agent computes `remaining + reserved - cost`, and the header's `remaining` is a floor. The question is whether `cost` greater than `reserved` is a malformed trailer. Both now reject it.

**A hold of zero.** The reservation text does not say whether zero is a hold. aauth-go `Reserve` rejects `Hold <= 0` and leaves the grant unchanged. aauth-rust `Ledger::reserve` accepts a zero maximum when the remainder is positive.

**A hold outside the 15-digit carrier that also exceeds the remainder.** Implementations MUST NOT issue an amount above 999999999999999, "so that the amount and every derived figure remain representable in both carriers." The question is which refusal applies when the hold is outside that carrier and larger than the remainder. Both now compare the hold with the remainder and refuse it as insufficient. `required` cannot carry that figure, and aauth-rust omits it.
