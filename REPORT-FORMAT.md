# Conformance report, version 1

This is the report a tool writes after it grades an implementation, and the
report a tool reads when someone else graded one. Version 1 uses three
vocabularies that already exist:

* The claim is an [EARL](https://www.w3.org/TR/EARL10-Schema/) assertion: a
  subject, a test, an outcome, and an assertor.
* The result word is the OpenID Foundation conformance export:
  `PASSED`, `FAILED`, `REVIEW`, `WARNING`, `SKIPPED`, `INTERRUPTED`.
  `plan`, `test`, and `condition` are the same export's names for the run,
  one graded unit, and one requirement inside it.
* The prose file is the implementation-status note [RFC 7942](https://www.rfc-editor.org/rfc/rfc7942)
  asks a draft to carry. The feature is the draft section. The status is the
  outcome.

This file does not copy an OpenID Foundation JSON schema. The Foundation
publishes those six result words and the plan, test, and result names. The
`conditions` array is this format's name for the requirements a test checked.

A reader ignores object members it does not know. A producer uses each member
name once. When `version` is present and is not `1`, a reader refuses the file
rather than guessing. A file with no `version` is the legacy envelope below.
Whitespace is not significant. A signature, when a deployment adds one, is over
the exact file bytes of `report.json`.

## Files

| File | What it is |
| --- | --- |
| `report.json` | This format. The interchange. |
| `report.md` | The RFC 7942 prose for the same run. |
| `junit.xml` | The same result as JUnit XML, for a CI dashboard. |
| `index.html` | A page for a person: a summary, then one row per test that opens onto its conditions. Presentation only. |

`report.md`, `junit.xml`, and `index.html` are rendered from `report.json`.
They are not part of the interchange a tool has to emit.

## Report object

A producer writes these members.

| Member | Meaning |
| --- | --- |
| `version` | The integer `1`. |
| `subject` | The implementation under test. `implementation` is its name. `revision` is the revision the producer graded. |
| `assertor` | Who graded it. `name` is the tool. `suite` is an optional build or commit identifier. |
| `plan` | The run. `id` is the producer's plan name. `tests` lists the test ids in that plan. |
| `tests` | One object per graded unit. For this suite, one test is one role. |

These members are optional. The hosted publisher writes them.

| Member | Meaning |
| --- | --- |
| `profile` | The URL of this document. |
| `id` | The producer's id for this report. |
| `published` | UTC timestamp, `YYYY-MM-DDThh:mm:ssZ`. |
| `transport` | How the grade reached the implementation. `remote` means deployed servers over HTTPS. |
| `exit` | Process exit of the grader. An integer. |
| `implementation`, `revision`, `suite` | Copies of `subject.implementation`, `subject.revision`, and `assertor.suite`, for a reader that looks up those older names. |
| `evidence` | Suite role documents. See below. |

The hosted publisher's `plan.id` is `aauth-conformance-remote`. Another producer chooses its own plan id. A reader displays `plan.id` and does not require a particular value.

## Test object

| Member | Meaning |
| --- | --- |
| `id` | Stable id of this test. For this suite, the role id. |
| `role` | Optional. The suite role, when `id` is that role. |
| `result` | One of the six result words below. |
| `outcome` | The EARL outcome. Required when `result` is `SKIPPED`, so a reader can tell the two SKIPPED rows apart. |
| `execution` | Optional suite word: `passed`, `failed_or_incomplete`, or `not_exercised`. |
| `counts` | Optional assertion totals. See Counts. |
| `conditions` | One object per requirement. May be empty. |

## Condition object

A condition is one requirement the test checked. For this suite, that is one clause.

| Member | Meaning |
| --- | --- |
| `id` | The requirement id. For this suite, the clause id. |
| `result` | One of the six result words. |
| `outcome` | The EARL outcome. |
| `section` | The draft heading this requirement cites. This is the line a person reads. |
| `source` | Absolute `http` or `https` URL of that draft. |
| `anchor` | URL fragment of the heading, without `#`. The link is `source` + `#` + `anchor`. |
| `scope` | Optional. This suite uses `protocol`, `adapter-contract`, `recommended`, or `out-of-slice`. |
| `counts` | Optional per-state totals for this requirement. |

`section` is the heading the catalog recorded. It is not a copy of the draft sentence under that heading.

## Result words

| Result | EARL outcome | When this suite emits it |
| --- | --- | --- |
| `PASSED` | `passed` | The assertions passed. |
| `FAILED` | `failed` | An assertion failed. |
| `INTERRUPTED` | `cantTell` | The grader hit a transport or startup error. |
| `SKIPPED` | `inapplicable` | The assertion was `not_exercised`: this transport does not run it, or the check did not apply. |
| `SKIPPED` | `untested` | The assertion was `not_claimed`: the implementation did not claim the clause. |
| `WARNING` | `cantTell` | Accepted from another producer. This suite does not emit it. |
| `REVIEW` | `untested` | Accepted from another producer. This suite does not emit it. |

EARL's outcome URIs are `http://www.w3.org/ns/earl#passed`, `#failed`, `#cantTell`, `#inapplicable`, and `#untested`. This file uses the local names so the JSON stays plain JSON. `cantTell` keeps the capital T from the EARL spec.

A reader uses `outcome` to split the two `SKIPPED` rows. When `outcome` is absent, `SKIPPED` means `inapplicable`.

### Counts

`counts` is an object of integers:

| Member | Assertion state |
| --- | --- |
| `pass` | `pass` |
| `fail` | `fail` |
| `error` | `error` |
| `not_exercised` | `not_exercised` |
| `not_claimed` | `not_claimed` |

On a test, the counts are every assertion in that role. On a condition, the counts are the assertions for that clause. A condition whose clause was not claimed has all-zero counts. The test totals still include an assertion that names an unclaimed clause. A reader that is given no `counts` object shows the result and leaves the count cells empty.

### How this suite fills result

The clause rule is the one in [FORMAT.md](FORMAT.md): failure, then error, then an observed pass, then no exercised assertion. A run error counts as error for every claimed clause. A clause the run did not claim is `not_claimed`.

| Clause state | `result` | `outcome` |
| --- | --- | --- |
| `fail` | `FAILED` | `failed` |
| `error` | `INTERRUPTED` | `cantTell` |
| `pass` | `PASSED` | `passed` |
| `not_exercised` | `SKIPPED` | `inapplicable` |
| `not_claimed` | `SKIPPED` | `untested` |

The test result follows the role's `execution` value:

| `execution` | Extra condition | `result` | `outcome` |
| --- | --- | --- | --- |
| `passed` | | `PASSED` | `passed` |
| `not_exercised` | | `SKIPPED` | `inapplicable` |
| `failed_or_incomplete` | a `fail` assertion | `FAILED` | `failed` |
| `failed_or_incomplete` | an `error` assertion and no `fail` | `INTERRUPTED` | `cantTell` |
| `failed_or_incomplete` | anything else | `FAILED` | `failed` |

## Evidence

`evidence.roles` is optional. When a producer has the suite's own role documents, it puts them here, keyed by role id. Each value is a role report as [FORMAT.md](FORMAT.md) describes it: `version`, `role`, `execution`, `catalog`, and `runs`. Assertion records live on `runs[].cases[].assertions[]` and use `state` values `pass`, `fail`, `error`, `not_exercised`, and `not_claimed`. The Go field name for that slice is `results`; the JSON name is `assertions`.

A reader that finds a non-empty `evidence.roles` grades the page and the counts from those documents. `tests` is the summary and agrees with that evidence. A reader that finds no evidence uses `tests` and `conditions` alone. That is how a report from another tool is read.

## JUnit

`junit.xml` beside `report.json` is a `testsuites` element. One `testsuite` per test. `name` is the test id. One `testcase` per condition. `classname` is the test id and `name` is the condition id. A test with no conditions is one `testcase` named for the test.

| Condition | JUnit child |
| --- | --- |
| `PASSED` | none |
| `FAILED` | `failure` |
| `INTERRUPTED` | `error`, `type` `cantTell` |
| `SKIPPED` with outcome `inapplicable` | `skipped`, message `not_exercised` |
| `SKIPPED` with outcome `untested` | `skipped`, message `not_claimed` |
| `WARNING` | `system-out`. The suite still passes. |
| `REVIEW` | `skipped` |

## Prose

`report.md` is the implementation-status note. It names the implementation, the revision, the assertor, and the suite. Each test then has the four RFC 7942 lines this report can fill:

* Implementation: name and revision.
* Description: the test id.
* Coverage: the condition table. The feature column is the draft section, linked to `source#anchor`.
* Experience: the execution word, the result word, and the assertion counts.

Licensing and contact are omitted because the report does not carry them. The status column uses the suite state word (`pass`, `fail`, `error`, `not_exercised`, `not_claimed`).

## Legacy hosted envelope

Reports published before version 1 have no top-level `version`. They are one JSON object:

```json
{
  "id": "report-id",
  "implementation": "name",
  "revision": "revision",
  "suite": "aauth-conformance <commit>",
  "transport": "remote",
  "exit": 0,
  "published": "2026-11-03T00:00:00Z",
  "roles": {}
}
```

`roles` holds the same role documents as `evidence.roles`. A reader converts that object by the evidence rule above. A signed legacy file stays byte for byte. The page, the prose, and `junit.xml` are rendered from it.

A single role document, with `role` and `runs` and no `tests` array, is one role of that same evidence.

## Reading order

1. Refuse a `version` other than `1`.
2. When `version` is `1` and `tests` is an array, read `evidence.roles` if that object is non-empty. Otherwise read `tests`.
3. When there is no `version` and `roles` is an object, read `roles` as evidence.
4. When the object is one role document, read that role.

## Example

```json
{
  "version": 1,
  "profile": "https://gitlab.com/sidecat-dev/aauth-conformance/-/blob/main/REPORT-FORMAT.md",
  "id": "example-1",
  "published": "2026-11-03T00:00:00Z",
  "transport": "remote",
  "exit": 0,
  "subject": {"implementation": "example", "revision": "1"},
  "assertor": {"name": "aauth-conformance", "suite": "aauth-conformance f415f2f8e18bebb2b4b6928d96c80d999244e72a"},
  "plan": {"id": "aauth-conformance-remote", "tests": ["person-server.direct"]},
  "tests": [{
    "id": "person-server.direct",
    "role": "person-server.direct",
    "result": "PASSED",
    "outcome": "passed",
    "execution": "passed",
    "counts": {"pass": 1, "fail": 0, "error": 0, "not_exercised": 0, "not_claimed": 0},
    "conditions": [{
      "id": "ps.person-endpoint",
      "result": "PASSED",
      "outcome": "passed",
      "section": "Person Token Endpoint: signed POST and successful person-token response",
      "anchor": "person-token-endpoint",
      "source": "https://example.test/draft",
      "scope": "protocol",
      "counts": {"pass": 1, "fail": 0, "error": 0, "not_exercised": 0, "not_claimed": 0}
    }]
  }]
}
```
