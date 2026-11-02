// sigkey-vectors generates the Signature-Key test vectors with the libraries
// in a vectors.signature-key target file, or checks the published vectors
// against them.
//
//	go run ./cmd/build-adapters -role vectors.signature-key -go-source ... -rust-source ... -out build/sigvec
//	go run ./cmd/sigkey-vectors -targets build/sigvec/targets.json -check
//	go run ./cmd/sigkey-vectors -targets build/sigvec/targets.json -write
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

func main() { os.Exit(run()) }

func run() int {
	suitePath := flag.String("suite", ".", "suite directory")
	targetsPath := flag.String("targets", "build/sigvec/targets.json", "vectors.signature-key launcher manifest")
	write := flag.Bool("write", false, "regenerate and write the vector file, scenarios and appendix")
	check := flag.Bool("check", false, "re-sign the published vectors and report every difference")
	reportPath := flag.String("report", "", "write the generation findings and agreement as JSON")
	flag.Parse()
	if *write == *check {
		fmt.Fprintln(os.Stderr, "give exactly one of -write and -check")
		return 2
	}
	suite, err := conformance.Load(*suitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var targets conformance.Targets
	if err = conformance.ReadJSON(*targetsPath, &targets); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if targets.Role != conformance.SigvecRole {
		fmt.Fprintf(os.Stderr, "targets are built for %q, not %s\n", targets.Role, conformance.SigvecRole)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	options := conformance.Options{Timeout: 10 * time.Second, StartupTimeout: 30 * time.Second, Stderr: os.Stderr}
	var generation conformance.SigvecGeneration
	differences := []string{}
	if *write {
		generation, err = conformance.GenerateSigvecVectors(ctx, suite.Fixture, targets, options)
		if err == nil {
			err = conformance.WriteSigvec(*suitePath, generation.File)
		}
	} else {
		var published conformance.SigvecFile
		published, _, err = conformance.ReadSigvec(*suitePath)
		if err == nil {
			generation, differences, err = conformance.CheckSigvecVectors(ctx, suite.Fixture, targets, options, published)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	for _, a := range generation.Agreement {
		state := "single signer"
		switch {
		case a.Identical:
			state = "identical bytes"
		case a.SameBase:
			state = "same base, different signature"
		case len(a.Signed) > 1:
			state = "DIFFERENT: " + a.Difference
		}
		fmt.Printf("%-34s category %d signed by %v: %s; published %v\n", a.Case, a.Category, a.Signed, state, a.Published)
		for _, refused := range a.Refused {
			fmt.Printf("%-34s   not signed: %s\n", "", refused)
		}
	}
	for _, f := range generation.Findings {
		fmt.Printf("finding %s %s %s: %s\n", f.Vector, f.Library, f.Kind, f.Detail)
	}
	for _, d := range differences {
		fmt.Println("difference from the published file:", d)
	}
	fmt.Printf("%d vectors, %d findings, %d differences\n", len(generation.File.Vectors), len(generation.Findings), len(differences))
	if *reportPath != "" {
		b, _ := json.MarshalIndent(map[string]any{"agreement": generation.Agreement, "findings": generation.Findings, "differences": differences, "libraries": generation.File.Generated.Libraries}, "", "  ")
		if err = os.WriteFile(*reportPath, append(b, '\n'), 0644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if len(differences) > 0 {
		return 1
	}
	return 0
}
