// Command driver-go runs Budgets cases against aauth-go. One JSON object on
// stdin, one on stdout.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	var request struct {
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		fatal(err)
	}
	results := make([]any, 0, len(request.Cases))
	for _, rawCase := range request.Cases {
		var header struct {
			ID string `json:"id"`
			Op string `json:"op"`
		}
		if err := json.Unmarshal(rawCase, &header); err != nil {
			fatal(err)
		}
		value, err := dispatch(header.Op, rawCase)
		if err != nil {
			results = append(results, map[string]any{"id": header.ID, "ok": false, "error": err.Error()})
			continue
		}
		results = append(results, map[string]any{"id": header.ID, "ok": true, "value": value})
	}
	emit(map[string]any{"results": results})
}

func dispatch(op string, raw json.RawMessage) (any, error) {
	switch op {
	case "object":
		return objectCase(raw)
	case "narrow":
		return narrowCase(raw)
	case "header-parse":
		return headerParseCase(raw)
	case "header-format":
		return headerFormatCase(raw)
	case "trailer-format":
		return trailerFormatCase(raw)
	case "trailer-restate":
		return trailerRestateCase(raw)
	case "meter":
		return meterCase(raw)
	default:
		return nil, fmt.Errorf("unknown op %s", op)
	}
}

func objectCase(raw json.RawMessage) (any, error) {
	var body struct {
		JSON string `json:"json"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	value, err := budgets.ParseValueJSON([]byte(body.JSON))
	if err != nil {
		return refused(code(err)), nil
	}
	encoded, err := value.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"outcome":  "accept",
		"amount":   value.Amount(),
		"unit":     value.Unit().Name(),
		"decimals": value.Unit().Decimals(),
		"json":     string(encoded),
	}, nil
}

func narrowCase(raw json.RawMessage) (any, error) {
	var body struct {
		Offered budgetJSON `json:"offered"`
		Granted budgetJSON `json:"granted"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	offered, err := body.Offered.value()
	if err != nil {
		return refused(code(err)), nil
	}
	granted, err := body.Granted.value()
	if err != nil {
		return refused(code(err)), nil
	}
	if err := budgets.ValidateNarrowing(offered, granted); err != nil {
		return refused(code(err)), nil
	}
	return map[string]any{"outcome": "accept"}, nil
}

func headerParseCase(raw json.RawMessage) (any, error) {
	var body struct {
		Field string `json:"field"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	feedback, err := budgets.ParseFeedback([]string{body.Field})
	if err != nil {
		return refused(code(err)), nil
	}
	field, err := budgets.FormatFeedback(feedback)
	if err != nil {
		return nil, err
	}
	value := feedbackValue(feedback)
	value["outcome"] = "accept"
	value["field"] = field
	return value, nil
}

func headerFormatCase(raw json.RawMessage) (any, error) {
	var body struct {
		Kind      string     `json:"kind"`
		Grant     budgetJSON `json:"grant"`
		Remaining int64      `json:"remaining"`
		Cost      *int64     `json:"cost"`
		Reserved  *int64     `json:"reserved"`
		Required  *int64     `json:"required"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	grant, err := body.Grant.value()
	if err != nil {
		return nil, err
	}
	var feedback budgets.Feedback
	switch body.Kind {
	case "success":
		if body.Cost == nil {
			return nil, errors.New("success format requires cost")
		}
		feedback, err = budgets.NewSuccessFeedback(grant, *body.Cost, body.Remaining)
	case "reserved":
		if body.Reserved == nil {
			return nil, errors.New("reserved format requires reserved")
		}
		feedback, err = budgets.NewReservedFeedback(grant, body.Remaining, *body.Reserved)
	case "refusal":
		feedback, err = budgets.NewRefusalFeedback(grant, body.Remaining, body.Required)
	default:
		return nil, fmt.Errorf("unknown format kind %s", body.Kind)
	}
	if err != nil {
		return refused(code(err)), nil
	}
	field, err := budgets.FormatFeedback(feedback)
	if err != nil {
		return refused(code(err)), nil
	}
	value := feedbackValue(feedback)
	value["outcome"] = "accept"
	value["field"] = field
	return value, nil
}

func trailerFormatCase(raw json.RawMessage) (any, error) {
	var body struct {
		Cost int64 `json:"cost"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	field, err := budgets.FormatTrailer(body.Cost)
	if err != nil {
		return refused(code(err)), nil
	}
	return map[string]any{"outcome": "accept", "field": field, "listed": "AAuth-Budget"}, nil
}

func trailerRestateCase(raw json.RawMessage) (any, error) {
	var body struct {
		Header string `json:"header"`
		Cost   int64  `json:"cost"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	feedback, err := budgets.ParseFeedback([]string{body.Header})
	if err != nil {
		return refused(code(err)), nil
	}
	trailer, err := budgets.FormatTrailer(body.Cost)
	if err != nil {
		return refused(code(err)), nil
	}
	if _, err := budgets.ApplyTrailer(feedback, []string{trailer}); err != nil {
		return refused(code(err)), nil
	}
	return map[string]any{"outcome": "accept", "field": trailer}, nil
}

type meterBody struct {
	Grant budgetJSON  `json:"grant"`
	Steps []meterStep `json:"steps"`
}

type meterStep struct {
	Op   string `json:"op"`
	ID   string `json:"id"`
	JTI  string `json:"jti"`
	Hold int64  `json:"hold"`
	Cost int64  `json:"cost"`
}

type account struct {
	grant    int64
	consumed int64
	reserved int64
	holds    map[string]int64
}

func (account account) remaining() int64 {
	return account.grant - account.consumed - account.reserved
}

func meterCase(raw json.RawMessage) (any, error) {
	var body meterBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	grant, err := body.Grant.value()
	if err != nil {
		return nil, err
	}
	store := testutil.NewBudgetStore()
	reserver, ok := store.(resource.BudgetReserver)
	if !ok {
		return nil, errors.New("budget store does not reserve")
	}
	accounts := map[string]*account{}
	when := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	steps := make([]any, 0, len(body.Steps))
	for _, step := range body.Steps {
		jti := step.JTI
		if jti == "" {
			jti = "token-1"
		}
		acct := accounts[jti]
		if acct == nil {
			acct = &account{grant: grant.Amount(), holds: map[string]int64{}}
			accounts[jti] = acct
		}
		var value map[string]any
		switch step.Op {
		case "reserve":
			value, err = meterReserve(reserver, acct, grant, jti, step, when)
		case "commit":
			value, err = meterCommit(reserver, acct, jti, step, when)
		case "release":
			value, err = meterRelease(reserver, acct, jti, step)
		default:
			return nil, fmt.Errorf("unknown meter op %s", step.Op)
		}
		if err != nil {
			return nil, err
		}
		value["op"] = step.Op
		value["id"] = step.ID
		value["jti"] = jti
		steps = append(steps, value)
	}
	return map[string]any{"outcome": "accept", "steps": steps}, nil
}

func meterReserve(reserver resource.BudgetReserver, acct *account, grant budgets.Value, jti string, step meterStep, when time.Time) (map[string]any, error) {
	result, err := reserver.Reserve(context.Background(), resource.BudgetReserve{
		ID: step.ID, Token: aauth.TokenReference{Issuer: "https://as.example", JTI: jti},
		PersonServer: "https://ps.example", Subject: "person-1", Audience: "https://resource.example",
		Grant: grant, Hold: step.Hold, AgentJKT: "thumbprint", ReservedAt: when,
	})
	if err == nil {
		if result.Remaining != acct.remaining()-step.Hold || result.Reserved != step.Hold {
			return nil, fmt.Errorf("reserve result remaining %d reserved %d", result.Remaining, result.Reserved)
		}
		acct.reserved += step.Hold
		acct.holds[step.ID] = step.Hold
		return meterState(acct, "accept", ""), nil
	}
	return meterError(acct, err, result.Remaining, true)
}

func meterCommit(reserver resource.BudgetReserver, acct *account, jti string, step meterStep, when time.Time) (map[string]any, error) {
	if _, ok := acct.holds[step.ID]; !ok {
		return meterState(acct, "refuse", "rejected"), nil
	}
	result, err := reserver.Commit(context.Background(), resource.BudgetCommit{
		Token: aauth.TokenReference{Issuer: "https://as.example", JTI: jti},
		ID:    step.ID, Cost: step.Cost, ChargedAt: when,
	})
	if err == nil {
		hold := acct.holds[step.ID]
		delete(acct.holds, step.ID)
		acct.reserved -= hold
		acct.consumed += step.Cost
		if result.Remaining != acct.remaining() || result.Cost != step.Cost {
			return nil, fmt.Errorf("commit result remaining %d cost %d", result.Remaining, result.Cost)
		}
		return meterState(acct, "accept", ""), nil
	}
	return meterError(acct, err, result.Remaining, false)
}

func meterRelease(reserver resource.BudgetReserver, acct *account, jti string, step meterStep) (map[string]any, error) {
	if _, ok := acct.holds[step.ID]; !ok {
		return meterState(acct, "refuse", "rejected"), nil
	}
	err := reserver.Release(context.Background(), resource.BudgetRelease{
		Token: aauth.TokenReference{Issuer: "https://as.example", JTI: jti}, ID: step.ID,
	})
	if err == nil {
		acct.reserved -= acct.holds[step.ID]
		delete(acct.holds, step.ID)
		return meterState(acct, "accept", ""), nil
	}
	return meterError(acct, err, 0, false)
}

func meterError(acct *account, err error, remaining int64, checkRemaining bool) (map[string]any, error) {
	switch {
	case errors.Is(err, resource.ErrBudgetExhausted):
		if checkRemaining && remaining != acct.remaining() {
			return nil, fmt.Errorf("exhausted remaining %d, ledger %d", remaining, acct.remaining())
		}
		return meterState(acct, "refuse", "exhausted"), nil
	case errors.Is(err, resource.ErrBudgetInsufficient):
		if checkRemaining && remaining != acct.remaining() {
			return nil, fmt.Errorf("insufficient remaining %d, ledger %d", remaining, acct.remaining())
		}
		return meterState(acct, "refuse", "insufficient"), nil
	case errors.Is(err, resource.ErrBudgetReservation), errors.Is(err, resource.ErrBudgetConflict):
		return meterState(acct, "refuse", "rejected"), nil
	default:
		return nil, err
	}
}

func meterState(acct *account, outcome, code string) map[string]any {
	value := map[string]any{
		"outcome":   outcome,
		"remaining": acct.remaining(),
		"committed": acct.consumed,
		"reserved":  acct.reserved,
	}
	if code != "" {
		value["code"] = code
	}
	return value
}

func feedbackValue(feedback budgets.Feedback) map[string]any {
	value := map[string]any{
		"remaining": feedback.Remaining(),
		"cost":      nil,
		"reserved":  nil,
		"required":  nil,
		"unit":      nil,
		"decimals":  nil,
	}
	if cost, ok := feedback.Cost(); ok {
		value["cost"] = cost
	}
	if reserved, ok := feedback.Reserved(); ok {
		value["reserved"] = reserved
	}
	if required, ok := feedback.Required(); ok {
		value["required"] = required
	}
	if unit, ok := feedback.Unit(); ok {
		value["unit"] = unit.Name()
		value["decimals"] = unit.Decimals()
	}
	return value
}

type budgetJSON struct {
	Amount   int64  `json:"amount"`
	Unit     string `json:"unit"`
	Decimals int64  `json:"decimals"`
}

func (body budgetJSON) value() (budgets.Value, error) {
	unit, err := budgets.NewUnit(body.Unit, body.Decimals)
	if err != nil {
		return budgets.Value{}, err
	}
	return budgets.NewValue(body.Amount, unit)
}

func refused(code string) map[string]any {
	return map[string]any{"outcome": "refuse", "code": code}
}

func code(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "15-digit"):
		return "range"
	case strings.Contains(message, "preserve unit"), strings.Contains(message, "denomination conflicts"):
		return "denomination"
	case strings.Contains(message, "exceeds the offer"):
		return "exceeds"
	default:
		return "malformed"
	}
}

func emit(value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s\n", encoded)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "driver-go: %v\n", err)
	os.Exit(1)
}
