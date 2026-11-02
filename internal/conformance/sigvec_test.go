package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func readSigvecForTest(t *testing.T) (SigvecFile, []byte) {
	t.Helper()
	file, data, err := ReadSigvec("../..")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no published vector file yet")
	}
	if err != nil {
		t.Fatal(err)
	}
	return file, data
}

// Catches a scenario whose embedded vector or environment drifted from the
// published file, a vector without a scenario, or one graded twice.
func TestSigvecScenariosEmbedThePublishedVectors(t *testing.T) {
	file, data := readSigvecForTest(t)
	sum := sha256.Sum256(data)
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, scenario := range suite.Scenarios {
		if scenario.Role != SigvecRole {
			continue
		}
		var in SigvecInput
		if err := Decode(scenario.Input, &in); err != nil {
			t.Fatal(err)
		}
		if in.Source.SHA256 != hex.EncodeToString(sum[:]) || in.Source.Index >= len(file.Vectors) || seen[in.Source.Index] {
			t.Fatalf("%s: source does not name one vector of the current file", scenario.ID)
		}
		seen[in.Source.Index] = true
		want := file.Vectors[in.Source.Index]
		if !jsonEqual(want, in.Vector) || !jsonEqual(SigvecEnvironmentFor(file, want), in.Environment) {
			t.Fatalf("%s: embedded vector or environment differs from %s[%d]", scenario.ID, SigvecFilePath, in.Source.Index)
		}
		if scenario.ID != "sigvec."+want.ID || len(scenario.Assertions) == 0 || scenario.Assertions[0].Clause != sigvecClause(want.ID) {
			t.Fatalf("%s: id or clause does not match vector %s", scenario.ID, want.ID)
		}
	}
	if len(seen) != len(file.Vectors) {
		t.Fatalf("%d scenarios for %d vectors", len(seen), len(file.Vectors))
	}
}

// Rebuilds every signature base and checks every signature with the
// harness's own code, so a published vector cannot rest on a library alone.
func TestSigvecVectorsRecheckIndependently(t *testing.T) {
	file, _ := readSigvecForTest(t)
	ids := map[string]bool{}
	for _, v := range file.Vectors {
		if ids[v.ID] {
			t.Fatalf("vector %s is repeated", v.ID)
		}
		ids[v.ID] = true
		received := SigvecReceived(v)
		base, err := SigvecBase(received, file.Verifier.Label)
		if err != nil {
			if v.SignatureBase != "" {
				t.Fatalf("%s: %v", v.ID, err)
			}
			continue
		}
		sum := sha256.Sum256([]byte(base))
		if base != v.SignatureBase || hex.EncodeToString(sum[:]) != v.SignatureBaseSHA256 || len(base) != v.SignatureBaseLength {
			t.Fatalf("%s: published signature base, digest or length is not the harness's", v.ID)
		}
		key, _, keyErr := SigvecConveyedKey(SigvecEnvironmentFor(file, v), received, file.Verifier.Label)
		signature, sigErr := sigvecSignatureBytes(received, file.Verifier.Label)
		verifies := keyErr == nil && sigErr == nil && SigvecVerifyJWK(key, []byte(base), signature)
		if v.Expect.Outcome == "verify" && !verifies {
			t.Fatalf("%s: positive vector does not verify under the harness", v.ID)
		}
		if v.SignatureVerifies != nil && *v.SignatureVerifies != verifies {
			t.Fatalf("%s: signature_verifies is %v, the harness finds %v", v.ID, *v.SignatureVerifies, verifies)
		}
		if v.Expect.Outcome == "reject" && v.Expect.Error == "" && !strings.Contains(v.Expect.Basis, "no code is fixed") {
			t.Fatalf("%s: a refusal without a code must say why no code is fixed", v.ID)
		}
	}
}

// Every published private key must reproduce from its stated derivation.
func TestSigvecKeysReproduceFromTheirDerivation(t *testing.T) {
	file, _ := readSigvecForTest(t)
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSigvecBuild(suite.Fixture)
	if err != nil {
		if strings.Contains(err.Error(), "toolchain") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if !jsonEqual(b.published, file.Keys) {
		got, _ := json.Marshal(b.published)
		t.Fatalf("published keys differ from their derivations: %s", got)
	}
	if !jsonEqual(b.defaults, file.Documents) {
		t.Fatal("published default documents differ from the derived ones")
	}
}

func TestSigvecFoldingUnfoldsToTheOriginal(t *testing.T) {
	original := strings.Repeat("abcdefghij ", 20) + "\n" + `"@signature-params": ("@method" "@authority" "@path" "signature-key");created=1800000000`
	folded := sigvecFold(original)
	body := strings.TrimPrefix(folded, "NOTE: '\\' line wrapping per RFC 8792\n\n")
	for _, line := range strings.Split(body, "\n") {
		if len(line) > 69 {
			t.Fatalf("folded line is %d columns", len(line))
		}
	}
	if strings.TrimSuffix(strings.ReplaceAll(body, "\\\n", ""), "\n") != original {
		t.Fatal("unfolding does not give the original")
	}
}
