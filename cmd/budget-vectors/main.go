// budget-vectors asks aauth-go and aauth-rust for the same Budgets cases and
// writes the results they share.
//
//	go run ./cmd/budget-vectors -go-driver ./driver-go -rust-driver ./driver-rust -write
//	go run ./cmd/budget-vectors -go-driver ./driver-go -rust-driver ./driver-rust -check
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
)

const (
	draftName    = "draft-hardt-aauth-budgets"
	draftCommit  = "70d67375deb0bb002af7da0711fc58f6e8926e7e"
	draftSHA     = "f00d34c91576476cdb30b7aa1aa13a0bc9fc1d99fc43b4f0389ccb3e8bf2e150"
	draftURL     = "https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-budgets.md"
	goRevision   = "ad34a9ad148cd2dd0f96b77e387c4fd22a3ca535"
	rustRevision = "ed4671b6a6b03993480a1b7fa8ca156c6ae607bd"
	rustVersion  = "0.1.0-alpha.28"
)

func main() {
	os.Exit(run())
}

func run() int {
	write := flag.Bool("write", false, "write vectors/budgets/budgets-vectors.json")
	check := flag.Bool("check", false, "re-run both libraries and report every difference from the published file")
	goDriver := flag.String("go-driver", "", "path to the aauth-go driver binary")
	rustDriver := flag.String("rust-driver", "", "path to the aauth-rust driver binary")
	outPath := flag.String("out", "vectors/budgets/budgets-vectors.json", "vector file")
	findingsPath := flag.String("findings", "", "also write the agreement and disagreements as JSON")
	flag.Parse()
	if *write == *check || *goDriver == "" || *rustDriver == "" {
		fmt.Fprintln(os.Stderr, "give exactly one of -write and -check, and both -go-driver and -rust-driver")
		return 2
	}
	cases := catalog()
	goResults, err := drive(*goDriver, cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aauth-go:", err)
		return 2
	}
	rustResults, err := drive(*rustDriver, cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aauth-rust:", err)
		return 2
	}
	file := baseFile()
	for _, item := range cases {
		goValue, ok := goResults[item.ID]
		if !ok {
			fmt.Fprintf(os.Stderr, "aauth-go returned no result for %s\n", item.ID)
			return 2
		}
		rustValue, ok := rustResults[item.ID]
		if !ok {
			fmt.Fprintf(os.Stderr, "aauth-rust returned no result for %s\n", item.ID)
			return 2
		}
		same, expect := agreement(goValue, rustValue)
		input := item.request()
		input["op"] = item.Op
		if same {
			file.Vectors = append(file.Vectors, vector{
				ID: item.ID, Title: item.Title, Kind: item.Kind, Input: input,
				Expect: expect, Provenance: provenance(item.Basis),
			})
			fmt.Printf("%-40s agree\n", item.ID)
			continue
		}
		file.Disagreements = append(file.Disagreements, disagreement{
			ID: item.ID, Title: item.Title, Kind: item.Kind, Input: input, Basis: item.Basis,
			Go: goValue, Rust: rustValue,
		})
		fmt.Printf("%-40s DISAGREE\n", item.ID)
	}
	fmt.Printf("%d vectors, %d disagreements\n", len(file.Vectors), len(file.Disagreements))
	if *findingsPath != "" {
		if err = writeJSON(*findingsPath, file); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if *write {
		if err = writeJSON(*outPath, file); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}
	published, err := os.ReadFile(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fresh, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fresh = append(fresh, '\n')
	if !bytes.Equal(published, fresh) {
		fmt.Fprintln(os.Stderr, "published file differs from a fresh run")
		return 1
	}
	fmt.Println("published file matches")
	return 0
}

func drive(binary string, cases []caseDef) (map[string]any, error) {
	payload := map[string]any{"cases": make([]any, 0, len(cases))}
	for _, item := range cases {
		body := item.request()
		body["id"] = item.ID
		body["op"] = item.Op
		payload["cases"] = append(payload["cases"].([]any), body)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w\n%s", binary, err, stderr.String())
	}
	var response struct {
		Results []struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Value any    `json:"value"`
			Error string `json:"error"`
		} `json:"results"`
	}
	if err = json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("%s: %w\n%s", binary, err, stdout.String())
	}
	out := map[string]any{}
	for _, result := range response.Results {
		if !result.OK {
			return nil, fmt.Errorf("%s case %s: %s", binary, result.ID, result.Error)
		}
		out[result.ID] = result.Value
	}
	return out, nil
}

// agreement reports whether the two library values are the same result.
// Header field bytes and compact budget JSON are not part of that comparison.
// When either library produced that text, both strings are kept on the
// expected value.
func agreement(goValue, rustValue any) (bool, any) {
	goMap, goObject := copiedMap(goValue)
	rustMap, rustObject := copiedMap(rustValue)
	if !goObject || !rustObject {
		return canonical(goValue) == canonical(rustValue), goValue
	}
	serializations := map[string]any{}
	recordText(serializations, "aauth-go", goMap)
	recordText(serializations, "aauth-rust", rustMap)
	if canonical(goMap) != canonical(rustMap) {
		return false, nil
	}
	expect := cloneMap(goMap)
	if len(serializations) > 0 {
		expect["serializations"] = serializations
	}
	return true, expect
}

// recordText lifts header field text or compact budget JSON out of the
// compared value. Parsed members stay behind for the comparison.
func recordText(serializations map[string]any, library string, value map[string]any) {
	for _, key := range []string{"field", "json"} {
		text, ok := takeString(value, key)
		if ok {
			serializations[library] = text
			return
		}
	}
}

func takeString(value map[string]any, key string) (string, bool) {
	raw, ok := value[key]
	if !ok || raw == nil {
		delete(value, key)
		return "", false
	}
	text, ok := raw.(string)
	delete(value, key)
	return text, ok
}

func copiedMap(value any) (map[string]any, bool) {
	original, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	return cloneMap(original), true
}

func cloneMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value)+1)
	for key, item := range value {
		out[key] = item
	}
	return out
}

func canonical(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(raw)
}

func (item caseDef) request() map[string]any {
	out := make(map[string]any, len(item.Input))
	for key, value := range item.Input {
		out[key] = value
	}
	return out
}

func baseFile() vectorFile {
	return vectorFile{
		Version: 1,
		Title:   "AAuth Budgets test vectors",
		Description: []string{
			"Deterministic Budgets cases that aauth-go and aauth-rust both compute, checked against draft-hardt-aauth-budgets at commit 70d67375deb0bb002af7da0711fc58f6e8926e7e (3 October 2026).",
			"A vector is published only when both libraries agree. disagreements lists the cases they do not agree on. Those entries are findings, not expected results.",
			"Serializations record each library's header field or compact budget JSON. The expected value is the parsed members. Member order is not significant.",
			"Evaluate a vector with no network: run the operation in input and compare it with expect. vectors/budgets/README.md describes every member.",
		},
		Drafts: []draft{{
			Name: draftName, Commit: draftCommit, SHA256: draftSHA, Date: "2026-10-03", URL: draftURL,
		}},
		Generated: generated{
			Libraries: []library{
				{ID: "aauth-go", Revision: goRevision},
				{ID: "aauth-rust", Revision: rustRevision, Version: rustVersion},
			},
			Harness: "cmd/budget-vectors, driver-go against budgets and testutil.NewBudgetStore, driver-rust against aauth-rust-budgets",
		},
		Vectors:       []vector{},
		Disagreements: []disagreement{},
	}
}

func provenance(basis string) provenanceDoc {
	return provenanceDoc{
		ProducedBy: []library{
			{ID: "aauth-go", Revision: goRevision},
			{ID: "aauth-rust", Revision: rustRevision, Version: rustVersion},
		},
		Agreement: "both libraries returned this result",
		Basis:     basis,
	}
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

type vectorFile struct {
	Version       int            `json:"version"`
	Title         string         `json:"title"`
	Description   []string       `json:"description"`
	Drafts        []draft        `json:"drafts"`
	Generated     generated      `json:"generated"`
	Vectors       []vector       `json:"vectors"`
	Disagreements []disagreement `json:"disagreements"`
}

type draft struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	SHA256 string `json:"sha256"`
	Date   string `json:"date"`
	URL    string `json:"url"`
}

type generated struct {
	Libraries []library `json:"libraries"`
	Harness   string    `json:"harness"`
}

type library struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Version  string `json:"version,omitempty"`
}

type vector struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Kind       string         `json:"kind"`
	Input      map[string]any `json:"input"`
	Expect     any            `json:"expect"`
	Provenance provenanceDoc  `json:"provenance"`
}

type provenanceDoc struct {
	ProducedBy []library `json:"produced_by"`
	Agreement  string    `json:"agreement"`
	Basis      string    `json:"basis"`
}

type disagreement struct {
	ID    string         `json:"id"`
	Title string         `json:"title"`
	Kind  string         `json:"kind"`
	Input map[string]any `json:"input"`
	Basis string         `json:"basis"`
	Go    any            `json:"aauth-go"`
	Rust  any            `json:"aauth-rust"`
}
