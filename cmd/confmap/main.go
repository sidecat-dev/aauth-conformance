// confmap generates conformance-map.edn, one entry per BCP 14 keyword
// sentence of every draft the catalog pins, from clauses.json, the scenarios,
// the pinned drafts and per-library reports; -check verifies a map.
//
//	go run ./cmd/confmap -drafts DIR -reports DIR
//	go run ./cmd/confmap -drafts DIR -check
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

func main() { os.Exit(run()) }

func run() int {
	suiteDir := flag.String("suite", ".", "suite directory")
	draftsDir := flag.String("drafts", "", "directory holding the pinned draft files, directly or one level down")
	reportsDir := flag.String("reports", "reports", "directory of report JSON: *.json and */report.json")
	source := flag.String("source", "", "label recorded as :reports-source (default: the -reports value)")
	out := flag.String("out", "", "map file (default: SUITE/conformance-map.edn)")
	check := flag.Bool("check", false, "verify the map instead of writing it")
	flag.Parse()
	if *out == "" {
		*out = filepath.Join(*suiteDir, "conformance-map.edn")
	}
	if *draftsDir == "" {
		fmt.Fprintln(os.Stderr, "confmap: -drafts is required")
		return 2
	}
	if *check {
		problems, err := Check(*suiteDir, *draftsDir, *out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "confmap:", err)
			return 1
		}
		for _, p := range problems {
			fmt.Println(p)
		}
		if len(problems) > 0 {
			fmt.Printf("%s: %d problems\n", *out, len(problems))
			return 1
		}
		fmt.Printf("%s: ok\n", *out)
		return 0
	}
	in, err := LoadInputs(*suiteDir, *draftsDir)
	if err == nil {
		var reports []conformance.Report
		if reports, err = LoadReports(*reportsDir); err == nil {
			in.Statuses, err = FromReports(reports)
		}
	}
	if *source == "" {
		*source = *reportsDir
	}
	in.ReportsSource = *source
	var m Map
	if err == nil {
		m, err = Build(in)
	}
	if err == nil {
		err = os.WriteFile(*out, Render(m), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "confmap:", err)
		return 1
	}
	fmt.Printf("%s: %d clauses, %d suite clauses, %d reports\n", *out, len(m.Clauses), len(m.SuiteClauses), len(m.Reports))
	return 0
}

// LoadInputs loads the suite and the drafts its catalog pins, refusing a
// draft whose bytes do not match the pinned SHA-256.
func LoadInputs(suiteDir, draftsDir string) (Inputs, error) {
	in := Inputs{Drafts: map[string]Draft{}, DraftFiles: map[string]string{}}
	suite, err := conformance.Load(suiteDir)
	if err != nil {
		return in, err
	}
	in.Suite = suite
	files, err := filepath.Glob(filepath.Join(suiteDir, "scenarios", "*.json"))
	if err != nil {
		return in, err
	}
	for _, f := range files {
		in.ScenarioFiles = append(in.ScenarioFiles, "scenarios/"+filepath.Base(f))
	}
	for _, s := range suite.Catalog.Sources {
		name := path.Base(s.URL)
		b, err := readDraft(draftsDir, name, s.SHA256)
		if err != nil {
			return in, fmt.Errorf("source %s: %w", s.ID, err)
		}
		in.Drafts[s.ID] = ParseDraft(string(b))
		in.DraftFiles[s.ID] = name
	}
	return in, nil
}

func findDraft(dir, name string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	deeper, err := filepath.Glob(filepath.Join(dir, "*", name))
	if err != nil {
		return "", err
	}
	matches = append(matches, deeper...)
	if len(matches) != 1 {
		return "", fmt.Errorf("%d files named %s under %s", len(matches), name, dir)
	}
	return matches[0], nil
}

func readDraft(dir, name, pin string) ([]byte, error) {
	p, err := findDraft(dir, name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != pin {
		return nil, fmt.Errorf("%s has SHA-256 %s, pinned %s", p, got, pin)
	}
	return b, nil
}

// LoadReports reads DIR/*.json and DIR/*/report.json in name order.
func LoadReports(dir string) ([]conformance.Report, error) {
	flat, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	nested, err := filepath.Glob(filepath.Join(dir, "*", "report.json"))
	if err != nil {
		return nil, err
	}
	paths := append(flat, nested...)
	slices.Sort(paths)
	reports := make([]conformance.Report, len(paths))
	for i, p := range paths {
		if err := conformance.ReadJSON(p, &reports[i]); err != nil {
			return nil, err
		}
	}
	return reports, nil
}
