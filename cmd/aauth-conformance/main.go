// aauth-conformance runs the same wire scenarios against configured Resources.
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
	suitePath := flag.String("suite", ".", "directory with fixture.json, clauses.json and scenarios/")
	targetsPath := flag.String("targets", "build/targets.json", "implementation launcher manifest")
	reportPath := flag.String("report", "build/report.json", "JSON evidence output")
	markdownPath := flag.String("markdown", "build/report.md", "clause matrix and assertion output")
	timeout := flag.Duration("timeout", 5*time.Second, "timeout for each HTTP exchange")
	flag.Parse()
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := conformance.RunSuite(ctx, suite, targets, conformance.Options{Timeout: *timeout, Stderr: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		err = os.WriteFile(*reportPath, append(b, '\n'), 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	out, err := os.Create(*markdownPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	err = report.Markdown(out)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, err, closeErr)
		return 2
	}
	counts := map[string]int{}
	for _, r := range report.Runs {
		for _, c := range r.Cases {
			for _, a := range c.Results {
				counts[a.State]++
			}
		}
	}
	fmt.Printf("%d scenarios × %d implementations; assertions %v\nReports: %s %s\n", len(report.Runs[0].Cases), len(report.Runs), counts, *reportPath, *markdownPath)
	if !report.Success() {
		return 1
	}
	return 0
}
