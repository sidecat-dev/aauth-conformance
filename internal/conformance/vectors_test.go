package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Catches an embedded vector case drifting from the copied community file,
// a vector left without a scenario, or one imported twice.
func TestVectorScenariosEmbedTheCopiedCasesExactly(t *testing.T) {
	suite, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("../../vectors/community/*.json")
	expected := map[string]int{}
	for _, file := range files {
		var doc struct {
			Cases []json.RawMessage `json:"cases"`
		}
		data, _ := os.ReadFile(file)
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		expected["vectors/community/"+filepath.Base(file)] = len(doc.Cases)
	}
	seen := map[string]bool{}
	total := 0
	for _, scenario := range suite.Scenarios {
		if scenario.Role != VectorsRole {
			continue
		}
		var in VectorInput
		if err := Decode(scenario.Input, &in); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join("../..", in.Source.File))
		if err != nil {
			t.Fatalf("%s: %v", scenario.ID, err)
		}
		original, digest, err := vectorCaseFromFile(data, in.Source.Index)
		if err != nil || digest != in.Source.SHA256 {
			t.Fatalf("%s: source %s digest %s: %v", scenario.ID, in.Source.File, digest, err)
		}
		want, _ := vectorCanonical(original)
		got, _ := vectorCanonical(in.Case)
		if want != got {
			t.Fatalf("%s: embedded case differs from %s[%d]", scenario.ID, in.Source.File, in.Source.Index)
		}
		key := fmt.Sprintf("%s#%d", in.Source.File, in.Source.Index)
		if seen[key] {
			t.Fatalf("%s: case imported twice", key)
		}
		seen[key] = true
		total++
	}
	sum := 0
	for _, n := range expected {
		sum += n
	}
	if len(expected) != 9 || total != sum || sum != 94 {
		t.Fatalf("imported %d of %d cases from %d files", total, sum, len(expected))
	}
}

// Catches the tamper or clock of an HTTP signature vector being dropped, and a
// not-offered kind or member being graded as a pass.
func TestVectorRequestAndGrading(t *testing.T) {
	in := VectorInput{Kind: "http-signature", Case: json.RawMessage(`{"name":"t","signing_key":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","alg":"Ed25519","d":"secret"},
	"request":{"method":"GET","url":"https://resource.example/a","headers":{"Signature-Key":"sig=jwt;jwt=\"x\""}},
	"signed":{"Signature":"sig=:AA==:","Signature-Input":"sig=(\"@method\");created=1000"},
	"tamper":{"method":"","url":"https://resource.example/b"},"verify":{"at_offset":61},"expect":"invalid_signature"}`)}
	request, err := vectorRequest(fixture(), in)
	if err != nil {
		t.Fatal(err)
	}
	built := request["request"].(vectorHTTPRequest)
	key := request["key"].(map[string]any)
	if built.URL != "https://resource.example/b" || built.Headers["Signature-Input"] == "" || request["now"].(int64) != 1061 || request["window"].(int64) != 60 || key["d"] != nil {
		t.Fatalf("%+v", request)
	}
	a := Assertion{ID: "a", Clause: "c", Kind: "vector-result", Member: "code", Equals: json.RawMessage(`"invalid_signature"`)}
	for _, outcome := range []VectorOutcome{
		{NotOffered: "no public verifier"},
		{Values: map[string]any{"accepted": false}, Unoffered: []string{"code"}},
	} {
		if got := vectorGrade(a, outcome); got.State != "not_exercised" {
			t.Fatalf("not offered graded %s", got.State)
		}
	}
	if got := vectorGrade(a, VectorOutcome{Values: map[string]any{"accepted": false}}); got.State != "fail" {
		t.Fatalf("missing member graded %s", got.State)
	}
	if got := vectorGrade(a, VectorOutcome{Values: map[string]any{"accepted": false, "code": "invalid_key"}}); got.State != "fail" {
		t.Fatalf("wrong code graded %s", got.State)
	}
	if got := vectorGrade(a, VectorOutcome{Values: map[string]any{"accepted": false, "code": "invalid_signature"}}); got.State != "pass" {
		t.Fatalf("matching code graded %s", got.State)
	}
	not := Assertion{ID: "n", Clause: "c", Kind: "vector-result-not", Member: "code", Equals: json.RawMessage(`"unsupported_scheme"`)}
	for values, want := range map[string]string{`{"accepted":false,"code":"unsupported_scheme"}`: "fail", `{"accepted":false,"code":"invalid_jwt"}`: "pass", `{"accepted":true}`: "pass"} {
		var parsed map[string]any
		json.Unmarshal([]byte(values), &parsed)
		if got := vectorGrade(not, VectorOutcome{Values: parsed}); got.State != want {
			t.Fatalf("%s graded %s, want %s", values, got.State, want)
		}
	}
	if _, err := vectorDecodeOutcome(Response{Status: 501, Body: []byte(`{}`)}); err == nil {
		t.Fatal("501 without a reason accepted")
	}
	if _, err := vectorDecodeOutcome(Response{Status: 200, Body: []byte(`{"code":"x"}`)}); err == nil {
		t.Fatal("result without accepted accepted")
	}
}
