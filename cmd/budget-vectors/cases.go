package main

// catalog is the Budgets case list. A case is published only when both
// libraries return the same result. A split is recorded as a disagreement.
func catalog() []caseDef {
	var cases []caseDef
	add := func(id, title, kind, basis, op string, input map[string]any) {
		cases = append(cases, caseDef{ID: id, Title: title, Kind: kind, Basis: basis, Op: op, Input: input})
	}
	object := func(id, title, basis, body string) {
		add(id, title, "object", basis, "object", map[string]any{"json": body})
	}
	object("object.zero", "Zero amount is a budget", "Budgets lines 344 and 326: amount is a non-negative integer.", `{"amount":0,"unit":"USD","decimals":0}`)
	object("object.draft-example", "Budget object from the draft example", "Budgets lines 334-346.", `{"amount":5000000,"unit":"USD","decimals":6}`)
	object("object.auth-example", "Budget object from the auth token example", "Budgets lines 593 and 344-346.", `{"amount":2000000,"unit":"USD","decimals":6}`)
	object("object.max-amount", "Largest amount the draft allows", "Budgets line 326: implementations MUST NOT issue an amount above 999999999999999.", `{"amount":999999999999999,"unit":"tokens","decimals":0}`)
	object("object.decimals-zero", "Scale zero", "Budgets line 346: decimals is a non-negative integer.", `{"amount":15,"unit":"tokens","decimals":0}`)
	object("object.key-order", "Members in a different order", "Budgets lines 344-346. JSON object order is not significant.", `{"unit":"USD","decimals":2,"amount":500}`)
	object("object.whitespace", "Whitespace around one object", "Budgets lines 344-346.", " \n{\"amount\":1,\"unit\":\"USD\",\"decimals\":2}\n")
	object("object.missing-amount", "Amount omitted", "Budgets line 344: amount is required.", `{"unit":"USD","decimals":2}`)
	object("object.missing-unit", "Unit omitted", "Budgets line 345: unit is required.", `{"amount":1,"decimals":2}`)
	object("object.missing-decimals", "Decimals omitted", "Budgets line 346: decimals is required.", `{"amount":1,"unit":"USD"}`)
	object("object.empty", "Empty object", "Budgets lines 344-346.", `{}`)
	object("object.negative-amount", "Negative amount", "Budgets line 344: amount is a non-negative integer.", `{"amount":-1,"unit":"USD","decimals":2}`)
	object("object.amount-above-carrier", "Amount above 15 digits", "Budgets line 326.", `{"amount":1000000000000000,"unit":"USD","decimals":0}`)
	object("object.amount-fraction", "Fractional amount", "Budgets line 344: amount is an integer.", `{"amount":1.5,"unit":"USD","decimals":2}`)
	object("object.amount-one-point-zero", "Amount written as 1.0", "Budgets line 344: amount is an integer. A JSON number with a fraction is not an integer.", `{"amount":1.0,"unit":"USD","decimals":2}`)
	object("object.amount-string", "Amount as a string", "Budgets line 344.", `{"amount":"1","unit":"USD","decimals":2}`)
	object("object.empty-unit", "Empty unit", "Budgets line 345: unit is a string identifying what is metered.", `{"amount":1,"unit":"","decimals":2}`)
	object("object.negative-decimals", "Negative decimals", "Budgets line 346: decimals is a non-negative integer.", `{"amount":1,"unit":"USD","decimals":-1}`)
	object("object.decimals-fraction", "Fractional decimals", "Budgets line 346.", `{"amount":1,"unit":"USD","decimals":1.5}`)
	object("object.unknown-member", "Unknown member", "Budgets lines 344-346 name amount, unit, and decimals. The draft does not say to ignore other members.", `{"amount":1,"unit":"USD","decimals":6,"future":true}`)
	object("object.duplicate-amount", "Duplicate amount member", "Budgets lines 344-346.", `{"amount":1,"unit":"USD","decimals":2,"amount":2}`)
	object("object.two-values", "Two JSON values", "Budgets lines 334-346: the budget is one object.", `{"amount":1,"unit":"USD","decimals":2}{"amount":1,"unit":"USD","decimals":2}`)
	object("object.null", "JSON null", "Budgets lines 334-346.", `null`)
	object("object.array", "JSON array", "Budgets lines 334-346.", `[{"amount":1,"unit":"USD","decimals":2}]`)
	object("object.number", "JSON number", "Budgets lines 334-346.", `1`)

	usd := map[string]any{"amount": int64(500), "unit": "USD", "decimals": int64(2)}
	narrow := func(id, title, basis string, granted map[string]any) {
		add(id, title, "narrowing", basis, "narrow", map[string]any{"offered": usd, "granted": granted})
	}
	narrow("narrow.equal", "Granted amount equals the offer", "Budgets line 267: each stage MUST NOT exceed the previous stage. An equal amount does not exceed it.", map[string]any{"amount": int64(500), "unit": "USD", "decimals": int64(2)})
	narrow("narrow.lower", "Granted amount is lower", "Budgets lines 299 and 301: a later party MAY lower the amount.", map[string]any{"amount": int64(200), "unit": "USD", "decimals": int64(2)})
	narrow("narrow.zero", "Granted amount is zero", "Budgets line 344: zero is a non-negative amount, and it does not exceed the offer.", map[string]any{"amount": int64(0), "unit": "USD", "decimals": int64(2)})
	narrow("narrow.higher", "Granted amount exceeds the offer", "Budgets line 267.", map[string]any{"amount": int64(501), "unit": "USD", "decimals": int64(2)})
	narrow("narrow.unit", "Granted unit differs", "Budgets line 301: the PS MUST NOT change unit or decimals. The same rule binds the access server at line 602.", map[string]any{"amount": int64(200), "unit": "EUR", "decimals": int64(2)})
	narrow("narrow.decimals", "Granted decimals differ", "Budgets line 301.", map[string]any{"amount": int64(200), "unit": "USD", "decimals": int64(6)})
	narrow("narrow.unit-and-higher", "Unit differs and the amount is higher", "Budgets lines 267 and 301. The denomination check is the one both libraries report.", map[string]any{"amount": int64(900), "unit": "EUR", "decimals": int64(2)})

	header := func(id, title, basis, field string) {
		add(id, title, "header", basis, "header-parse", map[string]any{"field": field})
	}
	header("header.success-example", "Draft success header", "Budgets lines 615 and 621-625.", `cost=221200, remaining=1568800, unit="USD", decimals=6`)
	header("header.success-remaining-first", "Success header with remaining before cost", "Budgets lines 621-625. RFC 9651 does not fix dictionary order.", `remaining=375, cost=125, unit="USD", decimals=2`)
	header("header.success-no-space", "Success header without spaces", "Budgets lines 621-625.", `remaining=375,cost=125,unit="USD",decimals=2`)
	header("header.success-no-unit", "Success header without the unit pair", "Budgets line 625: unit and decimals are optional, and a sender includes both or neither.", `remaining=375, cost=125`)
	header("header.stream-example", "Draft stream header", "Budgets lines 668 and 623.", `remaining=1568800, reserved=431200, unit="USD", decimals=6`)
	header("header.stream-no-unit", "Stream header without the unit pair", "Budgets lines 623 and 625.", `remaining=300, reserved=200`)
	header("header.exhausted-example", "Draft exhausted header", "Budgets lines 643 and 737. A refusal carries no cost.", `remaining=0, unit="USD", decimals=6`)
	header("header.exhausted-no-unit", "Exhausted header without the unit pair", "Budgets lines 621 and 724.", `remaining=0`)
	header("header.insufficient-example", "Draft insufficient-budget header", "Budgets lines 755 and 624.", `remaining=150000, required=400000, unit="USD", decimals=6`)
	header("header.insufficient-no-unit", "Insufficient header without the unit pair", "Budgets line 624.", `remaining=150, required=400`)
	header("header.remaining-only", "Remaining alone", "Budgets line 621: remaining is the required member. A served metered response must not omit both cost and reserved (line 692); a recipient can still parse remaining on its own.", `remaining=375`)
	header("header.zero-cost", "Cost zero", "Budgets line 622: cost is a non-negative integer.", `remaining=500, cost=0, unit="USD", decimals=2`)
	header("header.zero-reserved", "Reserved zero", "Budgets line 623: reserved is a non-negative integer.", `remaining=500, reserved=0, unit="USD", decimals=2`)
	header("header.unknown-member", "Unknown member is ignored", "Budgets line 627: recipients MUST ignore members they do not recognize.", `remaining=10, cost=1, future=1, unit="USD", decimals=2`)
	header("header.unknown-boolean", "Unknown boolean member is ignored", "Budgets line 627.", `remaining=10, future=?1`)
	header("header.max-remaining", "Remaining at the 15-digit limit", "Budgets lines 323 and 621.", `remaining=999999999999999, cost=0`)
	header("header.empty", "Empty field", "Budgets line 621: remaining is required.", ``)
	header("header.cost-only", "Cost without remaining", "Budgets line 621. A trailer may be cost alone (line 699); a header may not.", `cost=221200`)
	header("header.negative-remaining", "Negative remaining", "Budgets line 621: remaining is a non-negative integer.", `remaining=-1`)
	header("header.remaining-above-carrier", "Remaining above 15 digits", "Budgets lines 323 and 621.", `remaining=1000000000000000`)
	header("header.remaining-string", "Remaining as a string", "Budgets line 621: remaining is an Integer.", `remaining="10"`)
	header("header.remaining-decimal", "Remaining as a decimal", "Budgets line 621.", `remaining=1.5`)
	header("header.remaining-boolean", "Remaining as a boolean", "Budgets line 621.", `remaining=?1`)
	header("header.remaining-token", "Remaining as a token", "Budgets line 621.", `remaining=USD`)
	header("header.unit-only", "Unit without decimals", "Budgets line 625: the pair is both or neither.", `remaining=10, unit="USD"`)
	header("header.decimals-only", "Decimals without unit", "Budgets line 625.", `remaining=10, decimals=2`)
	header("header.empty-unit", "Empty unit", "Budgets line 625.", `remaining=10, unit="", decimals=2`)
	header("header.parameter", "Parameter on remaining", "Budgets line 612: AAuth-Budget is a Dictionary of members, not a parameterized item.", `remaining=10;k=1`)
	header("header.semicolons", "Members separated by semicolons", "Budgets line 615 separates members with commas. A semicolon starts structured-field parameters.", `remaining=10; cost=2`)
	header("header.duplicate-remaining", "Duplicate remaining key", "Budgets line 621 and RFC 9651 dictionary keys.", `remaining=1, remaining=2`)
	header("header.cost-and-reserved", "Cost and reserved together", "Budgets line 623: reserved is meaningful where cost is not yet known. The draft does not forbid both on one field.", `remaining=10, cost=4, reserved=8, unit="USD", decimals=2`)
	header("header.required-equal", "Required equal to remaining", "Budgets line 624: required is the maximum cost of a request that did not fit. The draft does not say the member must be greater than remaining.", `remaining=10, required=10, unit="USD", decimals=2`)
	header("header.required-below", "Required below remaining", "Budgets line 624.", `remaining=11, required=10, unit="USD", decimals=2`)
	header("header.cost-and-required", "Cost and required together", "Budgets lines 622 and 624. A refusal carries no cost (line 724).", `remaining=10, cost=1, required=20`)
	header("header.reserved-and-required", "Reserved and required together", "Budgets lines 623 and 624.", `remaining=10, reserved=5, required=20`)

	format := func(id, title, basis, kind string, grant map[string]any, extra map[string]any) {
		input := map[string]any{"kind": kind, "grant": grant}
		for key, value := range extra {
			input[key] = value
		}
		add(id, title, "header", basis, "header-format", input)
	}
	grant500 := map[string]any{"amount": int64(500), "unit": "USD", "decimals": int64(2)}
	grantBig := map[string]any{"amount": int64(5000000), "unit": "USD", "decimals": int64(6)}
	format("header.format-success", "Format a completed request", "Budgets lines 621-625.", "success", grant500, map[string]any{"remaining": int64(375), "cost": int64(125)})
	format("header.format-stream", "Format a hold whose cost is not known yet", "Budgets lines 660-668.", "reserved", grant500, map[string]any{"remaining": int64(300), "reserved": int64(200)})
	format("header.format-exhausted", "Format an exhausted refusal", "Budgets lines 724 and 737.", "refusal", grantBig, map[string]any{"remaining": int64(0)})
	format("header.format-insufficient", "Format an insufficient-budget refusal", "Budgets lines 724 and 755.", "refusal", grantBig, map[string]any{"remaining": int64(150000), "required": int64(400000)})
	format("header.format-required-equal", "Format required equal to remaining", "Budgets line 624.", "refusal", grant500, map[string]any{"remaining": int64(10), "required": int64(10)})
	format("header.format-over-grant", "Format cost and remaining above the grant", "Budgets lines 621-622. The draft does not say a sender must reject a field whose figures sum above the grant.", "success", grant500, map[string]any{"remaining": int64(400), "cost": int64(200)})

	add("trailer.cost-example", "Cost-only trailer from the draft", "trailer", "Budgets lines 673 and 699: a trailer carries cost and nothing else.", "trailer-format", map[string]any{"cost": int64(221200)})
	add("trailer.zero", "Trailer cost zero", "trailer", "Budgets line 622: cost is a non-negative integer.", "trailer-format", map[string]any{"cost": int64(0)})
	add("trailer.negative", "Negative trailer cost", "trailer", "Budgets line 622.", "trailer-format", map[string]any{"cost": int64(-1)})
	add("trailer.above-carrier", "Trailer cost above 15 digits", "trailer", "Budgets line 323.", "trailer-format", map[string]any{"cost": int64(1000000000000000)})
	add("trailer.restate-cost", "Trailer restates a header that already carried cost", "trailer", "Budgets line 699: a trailer MUST NOT restate a member the header carried.", "trailer-restate", map[string]any{"header": `remaining=375, cost=125, unit="USD", decimals=2`, "cost": int64(50)})
	add("trailer.after-reserved", "Trailer cost within the hold", "trailer", "Budgets lines 668-676 and 699.", "trailer-restate", map[string]any{"header": `remaining=300, reserved=200, unit="USD", decimals=2`, "cost": int64(125)})
	add("trailer.cost-above-reserved", "Trailer cost above the reserved hold", "trailer", "Budgets lines 676 and 909. The balance formula subtracts cost from remaining plus reserved. The draft does not say a trailer parser must reject cost above reserved.", "trailer-restate", map[string]any{"header": `remaining=300, reserved=200, unit="USD", decimals=2`, "cost": int64(250)})

	meter := func(id, title, basis string, grant map[string]any, steps []map[string]any) {
		add(id, title, "meter", basis, "meter", map[string]any{"grant": grant, "steps": steps})
	}
	step := func(op, id string, extra map[string]any) map[string]any {
		value := map[string]any{"op": op, "id": id}
		for key, item := range extra {
			value[key] = item
		}
		return value
	}
	meter("meter.reserve-commit-refuse", "Reserve, commit part, refuse what does not fit, then exhaust", "Budgets lines 909 and 724. Committed consumption plus outstanding reservations stay within the grant. A refusal does not draw the grant down.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(200)}),
		step("commit", "h1", map[string]any{"cost": int64(125)}),
		step("reserve", "h2", map[string]any{"hold": int64(400)}),
		step("reserve", "h3", map[string]any{"hold": int64(375)}),
		step("commit", "h3", map[string]any{"cost": int64(375)}),
		step("reserve", "h4", map[string]any{"hold": int64(1)}),
	})
	meter("meter.release", "Release a hold without posting it", "Budgets line 724: a refusal does not draw down the budget. Releasing a hold returns it.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(200)}),
		step("release", "h1", nil),
		step("reserve", "h2", map[string]any{"hold": int64(500)}),
	})
	meter("meter.commit-zero", "Commit none of a hold", "Budgets lines 623 and 676: the unspent hold returns to the grant.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(200)}),
		step("commit", "h1", map[string]any{"cost": int64(0)}),
	})
	meter("meter.commit-above-hold", "Commit more than the hold", "Budgets line 909: consumption must not exceed the grant, and a hold is the bound for that request.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(200)}),
		step("commit", "h1", map[string]any{"cost": int64(201)}),
		step("release", "h1", nil),
	})
	meter("meter.two-holds", "Two holds on one token", "Budgets line 913: committed consumption plus outstanding reservations MUST NOT exceed the grant.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(100)}),
		step("reserve", "h2", map[string]any{"hold": int64(100)}),
		step("commit", "h1", map[string]any{"cost": int64(40)}),
		step("release", "h2", nil),
	})
	meter("meter.two-tokens", "Two tokens do not share a grant", "Budgets line 631: the reported figures are this auth token's budget.", grant500, []map[string]any{
		step("reserve", "a", map[string]any{"jti": "token-1", "hold": int64(200)}),
		step("reserve", "b", map[string]any{"jti": "token-2", "hold": int64(200)}),
		step("commit", "a", map[string]any{"jti": "token-1", "cost": int64(200)}),
		step("reserve", "c", map[string]any{"jti": "token-2", "hold": int64(300)}),
	})
	meter("meter.exact-remaining", "Reserve exactly what remains", "Budgets line 909.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(500)}),
		step("reserve", "h2", map[string]any{"hold": int64(1)}),
	})
	meter("meter.spent-grant", "A grant of zero is already exhausted", "Budgets lines 724 and 742.", map[string]any{"amount": int64(0), "unit": "USD", "decimals": int64(2)}, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(1)}),
	})
	meter("meter.negative-hold", "Negative hold", "Budgets line 623: a reservation is a non-negative integer.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(-1)}),
	})
	meter("meter.unknown-hold", "Commit a hold that was not reserved", "Budgets line 909.", grant500, []map[string]any{
		step("commit", "missing", map[string]any{"cost": int64(1)}),
	})
	meter("meter.zero-hold", "Reserve a hold of zero", "Budgets line 623. The draft does not say whether a zero hold is a reservation.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(0)}),
	})
	meter("meter.hold-above-carrier", "Hold above 15 digits", "Budgets line 323: derived figures stay inside the 15-digit carrier.", grant500, []map[string]any{
		step("reserve", "h1", map[string]any{"hold": int64(1000000000000000)}),
	})
	return cases
}

type caseDef struct {
	ID, Title, Kind, Basis, Op string
	Input                      map[string]any
}
