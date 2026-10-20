# aauth-conformance

Wire-level conformance scenarios for the AAuth drafts, run against more than one
implementation. The harness plays the other roles; the system under test is one
role of one implementation. Scenario files carry deterministic keys and assert on
status, structured-field headers, problem bodies and JWT claims, each tagged with
the clause it exercises. The output is a clause-by-implementation report.

Implementations exercised today: `sidecat-dev/aauth-go`, `sidecat-dev/aauth-rust`.

MIT licensed. Development happens in sprint forks under `sidecat-dev/sprint-*`;
this repository receives curated merges.
