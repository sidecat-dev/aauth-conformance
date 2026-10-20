package conformance

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

type Case struct {
	DeferredHandoffs []FederatedHandoff  `json:"deferred_handoffs,omitempty"`
	Handoff          *FederatedHandoff   `json:"federation_handoff,omitempty"`
	Exchanges        []PersonExchange    `json:"exchanges,omitempty"`
	SigningInput     *AgentJob           `json:"signing_input,omitempty"`
	ControlResponse  *Response           `json:"control_response,omitempty"`
	RequestBody      []byte              `json:"request_body_base64,omitempty"`
	ID               string              `json:"id"`
	Error            string              `json:"error,omitempty"`
	Method           string              `json:"method,omitempty"`
	URL              string              `json:"url,omitempty"`
	Headers          map[string][]string `json:"request_headers,omitempty"`
	SignatureBase    string              `json:"signature_base,omitempty"`
	Response         *Response           `json:"response,omitempty"`
	Results          []Result            `json:"assertions"`
}
type Run struct {
	Target Target `json:"implementation"`
	Error  string `json:"error,omitempty"`
	Cases  []Case `json:"cases"`
}
type Report struct {
	Role        string  `json:"role"`
	Version     int     `json:"version"`
	Execution   string  `json:"execution"`
	SuiteSHA256 string  `json:"suite_sha256"`
	Clock       int64   `json:"verifier_unix_seconds"`
	Catalog     Catalog `json:"catalog"`
	Runs        []Run   `json:"runs"`
}
type Cell struct {
	State                               string
	Passed, Failed, Errors, Unexercised int
}

func (r Report) Matrix() map[string]map[string]Cell {
	matrix := map[string]map[string]Cell{}
	for _, clause := range r.Catalog.Clauses {
		matrix[clause.ID] = map[string]Cell{}
		for _, run := range r.Runs {
			cell := Cell{State: "not_claimed"}
			if slices.Contains(run.Target.Claims, clause.ID) {
				for _, c := range run.Cases {
					for _, result := range c.Results {
						if result.Clause == clause.ID {
							switch result.State {
							case "pass":
								cell.Passed++
							case "fail":
								cell.Failed++
							case "error":
								cell.Errors++
							case "not_exercised":
								cell.Unexercised++
							}
						}
					}
				}
				switch {
				case cell.Failed > 0:
					cell.State = "fail"
				case cell.Errors > 0 || run.Error != "":
					cell.State = "error"
				case cell.Passed > 0:
					cell.State = "pass"
				default:
					cell.State = "not_exercised"
				}
			}
			matrix[clause.ID][run.Target.ID] = cell
		}
	}
	return matrix
}
func (r Report) Success() bool {
	passed := false
	for _, run := range r.Runs {
		if run.Error != "" {
			return false
		}
		for _, c := range run.Cases {
			if c.Error != "" {
				return false
			}
			for _, v := range c.Results {
				if v.State == "fail" || v.State == "error" {
					return false
				}
				passed = passed || v.State == "pass"
			}
		}
	}
	return passed
}
func (r Report) Markdown(out io.Writer) error {
	var b strings.Builder
	title := "Resource agent-identity"
	if r.Role == DeferredRole {
		title = "Deferred four-party authorization"
	}
	if r.Role == FederatedRole {
		title = "Four-party authorization"
	}
	if r.Role == PersonServerRole {
		title = "Person Server direct authorization"
	}
	if r.Role == AgentRole {
		title = "Agent signing"
	}
	fmt.Fprintf(&b, "# %s report\n\nSuite SHA-256: `%s`\n\nVerifier clock: `%d` Unix seconds\n\n", title, r.SuiteSHA256, r.Clock)
	state := "failed or incomplete"
	if r.Success() {
		state = "passed"
	}
	fmt.Fprintf(&b, "Execution: **%s**.\n\n", state)
	b.WriteString("Pass means only the listed assertions passed, not the entire section. `adapter-contract` rows specify the test application's response. Loopback HTTP transport does not measure TLS, enrollment or discovery security.\n\n| Clause | Scope")
	for _, run := range r.Runs {
		fmt.Fprintf(&b, " | %s (`%s`)", clean(run.Target.ID), clean(run.Target.Revision))
	}
	b.WriteString(" |\n| --- | ---")
	for range r.Runs {
		b.WriteString(" | ---")
	}
	b.WriteString(" |\n")
	matrix := r.Matrix()
	sources := map[string]Source{}
	for _, s := range r.Catalog.Sources {
		sources[s.ID] = s
	}
	for _, clause := range r.Catalog.Clauses {
		fmt.Fprintf(&b, "| [%s](%s#%s) | %s", clean(clause.ID), sources[clause.Source].URL, clause.Anchor, clause.Scope)
		for _, run := range r.Runs {
			cell := matrix[clause.ID][run.Target.ID]
			fmt.Fprintf(&b, " | %s (%d pass, %d fail, %d error, %d unexercised)", cell.State, cell.Passed, cell.Failed, cell.Errors, cell.Unexercised)
		}
		b.WriteString(" |\n")
	}
	b.WriteString("\n## Assertion evidence\n\n")
	for _, run := range r.Runs {
		fmt.Fprintf(&b, "### %s\n\n", clean(run.Target.ID))
		if run.Error != "" {
			fmt.Fprintf(&b, "Adapter error: %s\n\n", clean(run.Error))
		}
		for _, c := range run.Cases {
			if c.Error != "" {
				fmt.Fprintf(&b, "Exchange `%s` error: %s\n\n", clean(c.ID), clean(c.Error))
			}
			for _, a := range c.Results {
				fmt.Fprintf(&b, "- `%s/%s` — `%s`: **%s**", clean(c.ID), clean(a.Assertion), clean(a.Clause), a.State)
				if a.State == "fail" || a.State == "error" {
					fmt.Fprintf(&b, "; expected `%s`, actual `%v` %s", clean(string(a.Expected)), a.Actual, clean(a.Detail))
				}
				b.WriteByte('\n')
			}
		}
		b.WriteByte('\n')
	}
	_, err := io.WriteString(out, b.String())
	return err
}
func clean(s string) string { return strings.NewReplacer("|", "\\|", "\n", " ", "`", "'").Replace(s) }
