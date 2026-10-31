# Community test vectors

These nine files are byte-for-byte copies of `testdata/vectors/*.json` from the
community Go implementation of AAuth:

- Repository: https://github.com/aauth-dev/aauth-go
- Tag: `v0.3.0`, commit `5aff16d165c07efd978762e750390ced6b4a9eb7` (2026-10-26)
- Path: `testdata/vectors/`
- License: MIT, "Copyright (c) 2026 AAuth"; the notice is in
  [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md).

| File | Cases | SHA-256 |
| --- | ---: | --- |
| `agent-identifier.json` | 20 | `2f095ee94de677b9198466b7ce158840b38a36ef86de15172f99217bd9b77ead` |
| `http-signature.json` | 13 | `d37870542ce41136e80e2e170483ebfa31e6ab6f1a5ae56f7aa960b43173b691` |
| `jwk-thumbprint.json` | 3 | `1c76db6d2e39c811d4c291f455f676723a38c87c33b08ebf444b135c5a270ed5` |
| `jwt.json` | 14 | `5778abc224a1774f45d228d37039c293db51989a7ab7981cf755be47a446cfe0` |
| `metadata.json` | 4 | `edae9c211152116749351724efd54a83f4e21b82108b2781f8940366414f6c83` |
| `requirement.json` | 8 | `3409442f2f0c66bdc75a5433ff331b1d0cc7bd31d62c96c52b4df9563a25671b` |
| `server-identifier.json` | 13 | `0979d8f808c09b0fbbca978151b71601f0d7a78dd8304f65d4a35947bfa5ea69` |
| `signature-error.json` | 10 | `0811df1a5db06152411071a7f26ebff5286bec336339d033183f4ce9c6681334` |
| `signature-key.json` | 9 | `ab8aea985d7d3a10595aa774192f76db6998f26abc2a1acc4cb2de0cbd3375e8` |

The files are not edited. Each case is also embedded in one scenario under
`scenarios/4NN-vector-*.json`, with its file, index and the file's SHA-256; a
unit test checks that every embedded case equals the case in these files.

The files record what that implementation emits or decides. The scenarios
grade only what the pinned drafts fix, so a scenario may assert less than the
vector says; the differences are listed in the scenario titles and in FORMAT.md.
