package main

import (
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

func TestSummaryUsesExecutionForAnUnexercisedRole(t *testing.T) {
	unexercised := summary(conformance.Report{Role: "events.agent", Execution: "not_exercised"})
	if !strings.Contains(unexercised, "events.agent: not exercised;") {
		t.Fatal(unexercised)
	}
	passed := summary(conformance.Report{Role: "r3.issuer", Execution: "passed"})
	if !strings.Contains(passed, "r3.issuer: passed;") {
		t.Fatal(passed)
	}
	failed := summary(conformance.Report{Role: "r3.issuer", Execution: "failed_or_incomplete"})
	if !strings.Contains(failed, "r3.issuer: failed or incomplete;") {
		t.Fatal(failed)
	}
}
