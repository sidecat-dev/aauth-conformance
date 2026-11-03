# Conformance report, version 1

This is the report a tool writes after it grades an implementation, and the
report a tool reads when someone else graded one. The plan, the test, and the
condition use the names the OpenID Foundation conformance suite already stores,
so that suite can emit this file and can read one.

The names were read from conformance-suite master
`475e8bf0b18e887767184c21388ffe7d783df2c6` on 2026-11-03, and checked against a
public plan and a public test on `staging.certification.openid.net`.

* A plan is `planName`, `variant`, `certificationProfileName`, and `modules`.
  Each module is `testModule`, `variant`, `instances`, `status`, and `result`.
  That is the object `GET /api/plan/{id}` returns.
  `net.openid.conformance.info.Plan`.
* A test is `testId`, `testName`, `variant`, `status`, `result`, and `planId`.
  That is `PublicTestInfo`. `status` is `TestModule.Status`. `result` is
  `TestModule.Result`. Both enums are in
  `net.openid.conformance.testmodule.TestModule`.
* A condition is `src`, `result`, `msg`, and `requirements`. `src` is the
  condition name. `result` is `Condition.ConditionResult` in
  `net.openid.conformance.condition.Condition`: `SUCCESS`, `FAILURE`,
  `WARNING`, `INFO`, `REVIEW`. `requirements` is the list of specification
  citations the condition logs. A public log entry cites `AUTHZEN-5.1`.
* The claim around that plan is an [EARL](https://www.w3.org/TR/EARL10-Schema/)
  assertion: `subject`, `assertor`, and `outcome`. The suite does not have
  those names. They say who was graded, who graded them, and the EARL outcome.
* The prose file is the implementation-status note
  [RFC 7942](https://www.rfc-editor.org/rfc/rfc7942) asks a draft to carry.

The suite's export zip is a different object, `PlanExportInfo`: `exportedAt`,
`exportedFrom`, `exportedBy`, `exportedVersion`, `planInfo`, and
`testLogExports`. Each test export carries `testInfo` and `results`, and
`results` is the log. This file is not that zip. It does not copy HTTP
exchanges. It is the plan and the tests, with one condition per requirement
instead of every log line.

Two members are named `version`, and they are not the same value.

* Top-level `version` is this format, the integer `1`.
* `plan.version` is the suite release. On an OpenID plan that string is the
  suite version, such as `5.1.43`. Here it is the conformance suite revision.

A reader ignores object members it does not know. A producer uses each member
name once. When `version` is present and is not `1`, a reader refuses the file
rather than guessing. A file with no `version` is the legacy envelope below.
Whitespace is not significant. A signature, when a deployment adds one, is over
the exact file bytes of `report.json`.

No hosted `report.json` used version 1 before this revision. An earlier draft
of this file, committed the same day, put the test result words on a condition
and used `INTERRUPTED` as a result. A reader still accepts that draft. A
producer writes the names in this revision.

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
| `version` | The integer `1`. This is the format, not the suite release. |
| `subject` | The implementation under test. `implementation` is its name. `revision` is the revision the producer graded. |
| `assertor` | Who graded it. `name` is the tool. `suite` is an optional build or commit identifier. |
| `plan` | The OpenID plan object, below. |
| `tests` | One OpenID test object per graded unit. For this suite, one test is one role. |

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

## Plan object

| Member | Meaning |
| --- | --- |
| `planName` | The plan name. The hosted publisher uses `aauth-conformance-remote`. Another producer chooses its own. A reader displays it and does not require a particular value. |
| `variant` | The plan variant. An object whose values are strings, or `null`. The suite's `VariantSelection` is that object. This suite has no variant, so the publisher writes `{}`. |
| `certificationProfileName` | The certification profile names `TestPlan.certificationProfileName` returns. An array of strings. Empty when the run is not a certification profile. This suite does not invent one. |
| `modules` | One module per graded unit, in the same order as `tests`. |

Optional: `description`, `started`, `summary`, `version`. `started` is the UTC time the producer records for the plan. This publisher uses the report's `published` time. `version` is the suite release, as above.

### Module object

| Member | Meaning |
| --- | --- |
| `testModule` | The test module name. In the OpenID suite this is the published module name, such as `authzen-pdp-interop-evaluation-01`. For this suite it is the role id. |
| `variant` | The module variant. An object of strings, or `null`. This publisher writes `{}`. |
| `instances` | The test ids of the module's runs. This publisher writes one id, the same value as `testId`. |
| `status` | The latest run's `TestModule.Status`. |
| `result` | The latest run's `TestModule.Result`. |

## Test object

| Member | Meaning |
| --- | --- |
| `testId` | The test id. For this suite, the role id. |
| `testName` | The test module name. For this suite, the same role id. |
| `status` | `TestModule.Status`: `NOT_YET_CREATED`, `CREATED`, `CONFIGURED`, `RUNNING`, `WAITING`, `INTERRUPTED`, `FINISHED`. This suite emits `FINISHED` or `INTERRUPTED`. |
| `result` | `TestModule.Result`: `PASSED`, `FAILED`, `WARNING`, `REVIEW`, `SKIPPED`, `UNKNOWN`. |
| `outcome` | The EARL outcome. Required when `result` is `SKIPPED` or `UNKNOWN`, so a reader can tell those rows apart. |
| `conditions` | One object per requirement. May be empty. |

Optional: `planId`, `variant`, `description`, `alias`, `summary`, `started`. This suite also writes `execution` (`passed`, `failed_or_incomplete`, or `not_exercised`) and `counts`. Those are not OpenID members. A reader that does not know them ignores them.

## Condition object

A condition is one requirement the test checked. For this suite, that is one clause. The members `src`, `result`, `msg`, and `requirements` are the log fields a condition writes.

| Member | Meaning |
| --- | --- |
| `src` | The condition name. For this suite, the clause id. |
| `result` | A `ConditionResult`: `SUCCESS`, `FAILURE`, `WARNING`, `INFO`, `REVIEW`. Omitted when the suite has no condition verdict. |
| `outcome` | The EARL outcome. This is how a reader tells apart the rows that omit `result`. |
| `msg` | The short text a person reads. For this suite, the draft heading. It is not a copy of the draft sentence under that heading. |
| `requirements` | Specification citations. The OpenID suite logs identifiers such as `AUTHZEN-5.1`. This suite logs one absolute `http` or `https` URL with the heading fragment, `source` + `#` + `anchor`. |
| `section` | Optional copy of the draft heading, the same text as `msg`. |
| `source` | Optional. Absolute `http` or `https` URL of that draft, without the fragment. |
| `anchor` | Optional. URL fragment of the heading, without `#`. |
| `scope` | Optional. This suite uses `protocol`, `adapter-contract`, `recommended`, or `out-of-slice`. |
| `counts` | Optional per-state totals for this requirement. |

## Result words

`INTERRUPTED` is a status. It is not a result. The suite's `AbstractTestModule` keeps a `FAILED` result when a test is stopped, and it clears a `WARNING` or a `REVIEW` to `UNKNOWN` because those are not a verdict until the test finishes.

| Test result | EARL outcome | When this suite emits it |
| --- | --- | --- |
| `PASSED` | `passed` | The role's execution is `passed`. Status is `FINISHED`. |
| `FAILED` | `failed` | An assertion failed, or the run is `failed_or_incomplete` without an error-only stop. Status is `FINISHED`. |
| `UNKNOWN` | `cantTell` | The grader hit a transport or startup error and recorded no failing assertion. Status is `INTERRUPTED`. |
| `SKIPPED` | `inapplicable` | The role was `not_exercised`. Status is `FINISHED`. |
| `SKIPPED` | `untested` | The role claimed nothing and passed nothing. Status is `FINISHED`. |
| `WARNING` | `cantTell` | Accepted from another producer. This suite does not emit it. A warning does not by itself fail the test. |
| `REVIEW` | `untested` | Accepted from another producer. This suite does not emit it. |

| Condition result | EARL outcome | When this suite emits it |
| --- | --- | --- |
| `SUCCESS` | `passed` | The clause's assertions passed. |
| `FAILURE` | `failed` | An assertion for that clause failed. |
| omitted | `cantTell` | The clause has an error and no failure. There is no `ConditionResult` for that. |
| omitted | `inapplicable` | The clause was `not_exercised`. |
| omitted | `untested` | The clause was `not_claimed`. |
| `WARNING` | `cantTell` | Accepted from another producer. This suite does not emit it. |
| `INFO` | `passed` | Accepted from another producer. This suite does not emit it. `INFO` does not fail the test. |
| `REVIEW` | `untested` | Accepted from another producer. This suite does not emit it. |

EARL's outcome URIs are `http://www.w3.org/ns/earl#passed`, `#failed`, `#cantTell`, `#inapplicable`, and `#untested`. This file uses the local names so the JSON stays plain JSON. `cantTell` keeps the capital T from the EARL spec.

A reader uses `outcome` when `result` is `SKIPPED`, `UNKNOWN`, or omitted. When `outcome` is absent, `SKIPPED` means `inapplicable`.

### Counts

`counts` is an object of integers. These are this suite's assertion states. The OpenID log counter is `SUCCESS`, `FAILURE`, and `WARNING`, which correspond to `pass`, `fail`, and the `WARNING` result. `error`, `not_exercised`, and `not_claimed` have no condition result, so they stay under these names.

| Member | Assertion state |
| --- | --- |
| `pass` | `pass` |
| `fail` | `fail` |
| `error` | `error` |
| `not_exercised` | `not_exercised` |
| `not_claimed` | `not_claimed` |

On a test, the counts are every assertion in that role. On a condition, the counts are the assertions for that clause. A condition whose clause was not claimed has all-zero counts. The test totals still include an assertion that names an unclaimed clause. A reader that is given no `counts` object shows the result and leaves the count cells empty.

### How this suite fills status and result

The clause rule is the one in [FORMAT.md](FORMAT.md): failure, then error, then an observed pass, then no exercised assertion. A run error counts as error for every claimed clause. A clause the run did not claim is `not_claimed`.

| Clause state | Condition `result` | `outcome` |
| --- | --- | --- |
| `fail` | `FAILURE` | `failed` |
| `error` | omitted | `cantTell` |
| `pass` | `SUCCESS` | `passed` |
| `not_exercised` | omitted | `inapplicable` |
| `not_claimed` | omitted | `untested` |

The test status and result follow the role's `execution` value:

| `execution` | Extra condition | `status` | `result` | `outcome` |
| --- | --- | --- | --- | --- |
| `passed` | | `FINISHED` | `PASSED` | `passed` |
| `not_exercised` | | `FINISHED` | `SKIPPED` | `inapplicable` |
| `failed_or_incomplete` | a `fail` assertion | `FINISHED` | `FAILED` | `failed` |
| `failed_or_incomplete` | an `error` assertion and no `fail` | `INTERRUPTED` | `UNKNOWN` | `cantTell` |
| `failed_or_incomplete` | anything else | `FINISHED` | `FAILED` | `failed` |

## Evidence

`evidence.roles` is optional. When a producer has the suite's own role documents, it puts them here, keyed by role id. Each value is a role report as [FORMAT.md](FORMAT.md) describes it: `version`, `role`, `execution`, `catalog`, and `runs`. Assertion records live on `runs[].cases[].assertions[]` and use `state` values `pass`, `fail`, `error`, `not_exercised`, and `not_claimed`. The Go field name for that slice is `results`; the JSON name is `assertions`.

A reader that finds a non-empty `evidence.roles` grades the page and the counts from those documents. `tests` is the summary and agrees with that evidence. A reader that finds no evidence uses `tests` and `conditions` alone. That is how a report from another tool is read.

## JUnit

`junit.xml` beside `report.json` is a `testsuites` element. One `testsuite` per test. `name` is the test id. One `testcase` per condition. `classname` is the test id and `name` is the condition `src`. A test with no conditions is one `testcase` named for the test.

| Condition | JUnit child |
| --- | --- |
| `SUCCESS` or `INFO` | none |
| `FAILURE` | `failure` |
| result omitted, outcome `cantTell` | `error`, `type` `cantTell` |
| result omitted, outcome `inapplicable` | `skipped`, message `not_exercised` |
| result omitted, outcome `untested` | `skipped`, message `not_claimed` |
| `WARNING` | `system-out`. The suite still passes. |
| `REVIEW` | `skipped` |

## Prose

`report.md` is the implementation-status note. It names the implementation, the revision, the assertor, and the suite. Each test then has the four RFC 7942 lines this report can fill:

* Implementation: name and revision.
* Description: the test id.
* Coverage: the condition table. The feature column is the draft section, linked to `source#anchor`.
* Experience: the test status, the test result, and the assertion counts.

Licensing and contact are omitted because the report does not carry them. The clause status column uses the suite state word (`pass`, `fail`, `error`, `not_exercised`, `not_claimed`), because those are the counts. The summary status column uses the OpenID status (`FINISHED`, `INTERRUPTED`).

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

## Earlier draft of version 1

A reader accepts these names from the first draft of this file:

| Draft name | Read it as |
| --- | --- |
| `plan.id` | `planName` |
| `plan.tests` | the list of test ids, when `modules` is absent |
| `test.id` | `testId` |
| `condition.id` | `src` |
| condition `result` `PASSED` | `SUCCESS` |
| condition `result` `FAILED` | `FAILURE` |
| condition `result` `INTERRUPTED` | result omitted, outcome `cantTell` |
| condition `result` `SKIPPED` | result omitted, outcome from `outcome` |
| test `result` `INTERRUPTED` | `status` `INTERRUPTED`, `result` `UNKNOWN` |

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
  "plan": {
    "planName": "aauth-conformance-remote",
    "variant": {},
    "certificationProfileName": [],
    "started": "2026-11-03T00:00:00Z",
    "version": "aauth-conformance f415f2f8e18bebb2b4b6928d96c80d999244e72a",
    "modules": [{
      "testModule": "person-server.direct",
      "variant": {},
      "instances": ["person-server.direct"],
      "status": "FINISHED",
      "result": "PASSED"
    }]
  },
  "tests": [{
    "testId": "person-server.direct",
    "testName": "person-server.direct",
    "planId": "aauth-conformance-remote",
    "variant": {},
    "status": "FINISHED",
    "result": "PASSED",
    "outcome": "passed",
    "execution": "passed",
    "counts": {"pass": 1, "fail": 0, "error": 0, "not_exercised": 0, "not_claimed": 0},
    "conditions": [{
      "src": "ps.person-endpoint",
      "result": "SUCCESS",
      "outcome": "passed",
      "msg": "Person Token Endpoint: signed POST and successful person-token response",
      "requirements": ["https://example.test/draft#person-token-endpoint"],
      "section": "Person Token Endpoint: signed POST and successful person-token response",
      "source": "https://example.test/draft",
      "anchor": "person-token-endpoint",
      "scope": "protocol",
      "counts": {"pass": 1, "fail": 0, "error": 0, "not_exercised": 0, "not_claimed": 0}
    }]
  }]
}
```
