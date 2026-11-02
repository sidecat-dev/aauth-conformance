# Conformance map

[conformance-map.edn](conformance-map.edn) lists every sentence or table row
containing a BCP 14 keyword in each draft that [clauses.json](clauses.json)
pins. Each entry names the suite clauses and scenarios that reach it and each
library's state in the reports the map was built from. `cmd/confmap`
generates it from `clauses.json`, `scenarios/`, the pinned draft files and a
directory of reports. The same inputs give the same bytes.

## Reading it

The file is one EDN map. Each element of a top-level vector is on its own line.

| Key | Holds |
| --- | --- |
| `:suite-sha256` | Suite digest of the checkout that generated the map |
| `:reports-source` | Label of the reports the statuses come from |
| `:drafts` | Per pinned source: `:id`, `:file`, `:commit`, `:sha256`, `:lines` |
| `:reports` | Per report run: `:role`, `:library`, `:revision`, `:execution`, `:suite-sha256` |
| `:scenarios` | Per scenario: `:id`, `:role`, `:file` |
| `:suite-clauses` | Per `clauses.json` clause, in catalog order (below) |
| `:clauses` | Per draft keyword sentence, by draft then line (below) |

A `:clauses` entry:

| Key | Holds |
| --- | --- |
| `:id` | `DRAFT:LINE`, with `.2`, `.3` for later sentences starting on the same line |
| `:draft` | Source id from `clauses.json` |
| `:line` | Line of the pinned file where the sentence starts |
| `:level` | `:must` (MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT), `:should` (SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED) or `:may` (MAY, OPTIONAL); the strongest keyword in the sentence |
| `:section` | Anchor of the innermost enclosing heading |
| `:text` | The sentence or table row on one line |
| `:suite-clauses` | Suite clauses anchored at the entry's section or any enclosing section |
| `:scenarios` | Scenarios with an assertion naming one of those suite clauses, in file order |
| `:status` | Per library, the first of `:fail`, `:error`, `:pass`, `:not-exercised`, `:not-claimed`, `:not-applicable` held by one of those suite clauses |
| `:reason` | Per library, for `:not-exercised` and `:not-applicable`: the assertion detail or the report's `unavailable` text |

An entry with no suite clauses has empty `:suite-clauses` and `:scenarios` and
no `:status`. A link means a scenario grades a requirement of that section,
not that it grades that sentence.

A `:suite-clauses` entry has `:id`, `:draft`, `:anchor`, `:role`, `:scope`,
`:scenarios`, `:status` and `:reason` with the same values as above, plus:

- `:anchor-line` is the line declaring the anchor. It is `nil` when the
  pinned draft declares no such anchor.
- `:linked` is the number of `:clauses` entries in the anchored section.
  A figure anchor stands for the section containing the figure.

Library states come from each report's clause matrix (see
[FORMAT.md](FORMAT.md)). A run whose implementation is `unavailable` gives
`:not-applicable` for every clause of its role.

## Extraction rules

- Keywords are the upper-case BCP 14 words.
- Skipped: front matter, fenced code, HTML comments, lines starting with `{`,
  and the `Document History` section.
- A paragraph or list item is joined and split into sentences after `.`, `!`
  or `?` followed by a space and a capital letter, quote, bracket, backtick
  or emphasis mark. A sentence of at most two words joins the sentence
  before it. Each table row is one unit and is not split.
- A heading's anchor is its `{#anchor}`. Without one, it is the lower-cased
  title with characters other than letters, digits, spaces, `-` and `_`
  removed and spaces made `-`. The first declaration of a repeated anchor is
  used. `Figure: ... {#anchor}` lines declare figure anchors.

## Regenerating

From the project root, with the pinned drafts in `DRAFTS` (directly or one
level down) and a full run's reports in `REPORTS` (`*.json` or
`*/report.json`, one per role and library):

```sh
go run ./cmd/confmap -drafts DRAFTS -reports REPORTS -source "LABEL"
go run ./cmd/confmap -drafts DRAFTS -check
CONFMAP_DRAFTS=DRAFTS go test ./cmd/confmap
```

The generator refuses a draft whose SHA-256 differs from its pin.

`-check` fails when the map names a scenario, scenario file, suite clause,
draft or draft line that does not exist. It also fails when the map differs
from one regenerated from the current suite and drafts with the map's own
statuses. `go test ./...` runs the same check on the committed map; without
`CONFMAP_DRAFTS` it skips the draft lines and the regeneration.

## Adding a clause

1. Add the clause to `clauses.json` with `anchor` set to a heading or figure
   anchor of the pinned draft.
2. Name it in scenario assertions.
3. Run the role for each library and regenerate the map.
4. Check that its `:anchor-line` is not `nil` and its `:linked` is above 0.

A new pinned draft is a new `sources` entry in `clauses.json`.

## Updating

| Updating | Check |
| --- | --- |
| clauses | `scenarios`, `cmd/build-adapters`, `conformance-map.edn` |
| scenarios | `clauses.json`, `README.md`, `reports`, `conformance-map.edn` |
| adapters | `ADAPTERS.md`, `cmd/build-adapters`, `reports` |
| deployments | `REMOTE.md`, `deployments/README.md`, `run-remote.sh` |
| vectors | `cmd/sigkey-vectors`, `scenarios`, `APPENDIX.md`, `PROVENANCE.md` |
| reports | `conformance-map.edn`, `README.md` |
| docs | `README.md`, `FORMAT.md`, `ADAPTERS.md`, `REMOTE.md` |
| drafts (re-pin) | `clauses.json`, `scenarios`, `conformance-map.edn` |
