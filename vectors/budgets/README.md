# Budgets test vectors

`budgets-vectors.json` is the authoritative set. It holds the Budgets cases that aauth-go (`567e556af2bd7fc931143e679dd228b709111797`) and aauth-rust `v0.1.0-alpha.28` (`ed4671b6a6b03993480a1b7fa8ca156c6ae607bd`) both compute, against [draft-hardt-aauth-budgets](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-budgets.md) at commit `70d67375deb0bb002af7da0711fc58f6e8926e7e` (3 October 2026).

The file contains 82 vectors: 25 budget objects, 7 narrowing cases, 34 header cases, 6 trailer cases, and 10 metering sequences. A case is a vector only when both libraries return the same result. `disagreements` lists the other 10 cases. Those entries are findings. They are not expected results, and an implementation is not graded against either side.

No network is required to evaluate a vector. Read `input`, run that operation, and compare the result with `expect`.

## Operations

`input.op` selects the operation.

| `op` | What to compute |
| --- | --- |
| `object` | Parse `input.json` as one budget object. On success, compare the integer `amount`, the `unit`, and the `decimals`. `expect.serializations` records each library's compact JSON. Member order in that JSON is not significant. |
| `narrow` | Accept when `granted` has the same `unit` and `decimals` as `offered` and `granted.amount` is less than or equal to `offered.amount`. Otherwise refuse. |
| `header-parse` | Parse `input.field` as an RFC 9651 Dictionary. Compare the members in `expect`. Ignore dictionary order. |
| `header-format` | Build the field for `input.kind` (`success`, `reserved`, or `refusal`) from the integer members and the grant's unit and scale. Compare the parsed members. |
| `trailer-format` | Emit a trailer dictionary whose only member is `cost`, and list `AAuth-Budget` as the `Trailer` header value. |
| `trailer-restate` | Parse `input.header`. Refuse when it already carries `cost`. Otherwise accept a trailer of `input.cost`. |
| `meter` | Open one grant per `jti` (the default jti is `token-1`). Apply `steps` in order. `reserve` holds `hold` or refuses. `commit` posts `cost` against that hold, and the unspent part of the hold returns. `release` drops the hold and posts nothing. After each step, `remaining` is grant minus committed minus still reserved. |

A refusal in `expect` is `{"outcome":"refuse","code":"..."}`. The codes are:

| Code | Meaning |
| --- | --- |
| `malformed` | The value is not the shape the draft requires. |
| `range` | An integer is above 999999999999999. |
| `denomination` | `unit` or `decimals` changed. |
| `exceeds` | `amount` is above the previous stage. |
| `exhausted` | Nothing remains, so the request was not reserved. |
| `insufficient` | Something remains, and the request's maximum does not fit. The grant is unchanged. |
| `rejected` | The operation was refused and the grant is unchanged, for a reason other than the two refusals above. |

`exhausted` and `insufficient` also carry `remaining`, `committed`, and `reserved` as they stand after the refusal.

## Serializations

`expect.serializations` gives the text each library emitted. For a header, that text is the RFC 9651 Dictionary. The draft's examples use more than one member order, and RFC 9651 does not fix it. For a budget object, that text is the compact JSON of `amount`, `unit`, and `decimals`. A pass is a value that parses to the members in `expect`. Either published serialization does that. Byte-for-byte equality with one of them is sufficient and not required.

## Reproducing the file

Build the two drivers against the revisions above, then from this repository:

```sh
ln -s /path/to/aauth-go cmd/budget-vectors/driver-go/aauth-go-src
ln -s /path/to/aauth-rust cmd/budget-vectors/driver-rust/aauth-rust-src
mkdir -p build
go build -C cmd/budget-vectors/driver-go -o "$PWD/build/budget-driver-go" .
cargo build --manifest-path cmd/budget-vectors/driver-rust/Cargo.toml --release
go run ./cmd/budget-vectors -go-driver "$PWD/build/budget-driver-go" -rust-driver cmd/budget-vectors/driver-rust/target/release/budget-vector-driver -check
```

`-check` re-runs both libraries and exits 1 when any byte of `budgets-vectors.json` differs. `-write` replaces the file. The Go driver calls `budgets.ParseValueJSON`, `budgets.ValidateNarrowing`, `budgets.ParseFeedback`, `budgets.FormatFeedback`, `budgets.FormatTrailer`, `budgets.ApplyTrailer`, and `testutil.NewBudgetStore`. The Rust driver calls `parse_budget_bytes`, `validate_narrowing`, `parse_header`, `sender_field`, `trailer_field`, and `Ledger`.

The symlinks are gitignored. Point them at the revisions in `generated.libraries` before building.
