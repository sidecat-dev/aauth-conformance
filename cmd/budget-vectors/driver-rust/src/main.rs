//! Runs Budgets cases from aauth-rust-budgets. One JSON object on stdin, one on stdout.
use std::collections::BTreeMap;
use std::io::{self, Read};

use aauth_rust_budgets::{
    Budget, BudgetHeader, ChargeError, Error, Ledger, Refusal, Reservation, TokenAccount,
    parse_budget_bytes, parse_header, sender_field, trailer_field, validate_narrowing,
};
use serde_json::{Value, json};

fn main() {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).expect("stdin");
    let request: Value = serde_json::from_str(&raw).expect("request json");
    let cases = request["cases"].as_array().expect("cases");
    let mut results = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap_or("").to_owned();
        let value = match case["op"].as_str().unwrap_or("") {
            "object" => object(case),
            "narrow" => narrow(case),
            "header-parse" => header_parse(case),
            "header-format" => header_format(case),
            "trailer-format" => trailer_format(case),
            "trailer-restate" => trailer_restate(case),
            "meter" => meter(case),
            other => Err(format!("unknown op {other}")),
        };
        results.push(match value {
            Ok(value) => json!({"id": id, "ok": true, "value": value}),
            Err(error) => json!({"id": id, "ok": false, "error": error}),
        });
    }
    println!("{}", json!({"results": results}));
}

fn object(case: &Value) -> Result<Value, String> {
    let text = case["json"].as_str().ok_or("json")?.as_bytes();
    match parse_budget_bytes(text) {
        Ok(budget) => Ok(accepted_budget(&budget)),
        Err(error) => Ok(refused(code_error(&error))),
    }
}

fn narrow(case: &Value) -> Result<Value, String> {
    let offered = budget_from_value(&case["offered"])?;
    let granted = budget_from_value(&case["granted"])?;
    match (offered, granted) {
        (Ok(offered), Ok(granted)) => match validate_narrowing(&offered, &granted) {
            Ok(()) => Ok(json!({"outcome": "accept"})),
            Err(error) => Ok(refused(code_error(&error))),
        },
        (Err(error), _) | (_, Err(error)) => Ok(refused(error)),
    }
}

fn header_parse(case: &Value) -> Result<Value, String> {
    let field = case["field"].as_str().ok_or("field")?;
    match parse_header(field, None, None) {
        Ok(parsed) => {
            let served = parsed.header.cost.is_some() || parsed.header.reserved.is_some();
            let formatted = sender_field(&parsed.header, served).map_err(|error| error.to_string())?;
            let mut value = header_value(&parsed.header);
            value["outcome"] = json!("accept");
            value["field"] = json!(formatted);
            Ok(value)
        }
        Err(error) => Ok(refused(code_error(&error))),
    }
}

fn header_format(case: &Value) -> Result<Value, String> {
    let remaining = i64_field(case, "remaining")?;
    let grant = must_budget(&case["grant"])?;
    let built = match case["kind"].as_str().unwrap_or("") {
        "success" => BudgetHeader::final_cost(remaining, i64_field(case, "cost")?, grant.unit(), grant.decimals()),
        "reserved" => BudgetHeader::reserved_hold(
            remaining,
            i64_field(case, "reserved")?,
            grant.unit(),
            grant.decimals(),
        ),
        "refusal" => {
            let required = case.get("required").filter(|value| !value.is_null());
            let required = match required {
                Some(_) => Some(i64_field(case, "required")?),
                None => None,
            };
            BudgetHeader::refusal(remaining, required, grant.unit(), grant.decimals())
        }
        other => return Err(format!("unknown format kind {other}")),
    };
    match built {
        Ok(header) => {
            let served = header.cost.is_some() || header.reserved.is_some();
            match sender_field(&header, served) {
                Ok(field) => {
                    let mut value = header_value(&header);
                    value["outcome"] = json!("accept");
                    value["field"] = json!(field);
                    Ok(value)
                }
                Err(error) => Ok(refused(code_error(&error))),
            }
        }
        Err(error) => Ok(refused(code_error(&error))),
    }
}

fn trailer_format(case: &Value) -> Result<Value, String> {
    let cost = i64_field(case, "cost")?;
    let prior = BudgetHeader::reserved_hold(0, 0, "USD", 0).map_err(|error| error.to_string())?;
    match trailer_field(&prior, cost) {
        Ok(trailer) => Ok(json!({"outcome": "accept", "field": trailer.field, "listed": trailer.listed})),
        Err(error) => Ok(refused(code_error(&error))),
    }
}

fn trailer_restate(case: &Value) -> Result<Value, String> {
    let field = case["header"].as_str().ok_or("header")?;
    let cost = i64_field(case, "cost")?;
    let parsed = match parse_header(field, None, None) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(refused(code_error(&error))),
    };
    match trailer_field(&parsed.header, cost) {
        Ok(trailer) => Ok(json!({"outcome": "accept", "field": trailer.field})),
        Err(error) => Ok(refused(code_error(&error))),
    }
}

fn meter(case: &Value) -> Result<Value, String> {
    let grant = must_budget(&case["grant"])?;
    let steps = case["steps"].as_array().ok_or("steps")?;
    let mut ledger = Ledger::new();
    let mut seen = BTreeMap::<String, ()>::new();
    let mut names = Vec::new();
    for step in steps {
        let jti = step["jti"].as_str().unwrap_or("token-1").to_owned();
        if seen.insert(jti.clone(), ()).is_none() {
            names.push(jti);
        }
    }
    if names.is_empty() {
        names.push("token-1".into());
    }
    for jti in &names {
        ledger.open(account(&grant, jti)).map_err(|error| error.to_string())?;
    }
    let mut holds: BTreeMap<String, Reservation> = BTreeMap::new();
    let mut out = Vec::new();
    for step in steps {
        let op = step["op"].as_str().unwrap_or("");
        let id = step["id"].as_str().unwrap_or("").to_owned();
        let jti = step["jti"].as_str().unwrap_or("token-1").to_owned();
        let step_value = match op {
            "reserve" => {
                let hold = i64_field(step, "hold")?;
                match ledger.reserve("https://as.example", &jti, hold) {
                    Ok(reservation) => {
                        holds.insert(id.clone(), reservation);
                        Ok(meter_state(&ledger, &grant, &jti, "accept", None))
                    }
                    Err(error) => Ok(meter_refusal(&ledger, &grant, &jti, &error)),
                }
            }
            "commit" => {
                let cost = i64_field(step, "cost")?;
                match holds.get(&id).cloned() {
                    None => Ok(meter_state(&ledger, &grant, &jti, "refuse", Some("rejected"))),
                    Some(reservation) => match ledger.commit(&reservation, cost, 1_760_000_000) {
                        Ok(_) => {
                            holds.remove(&id);
                            Ok(meter_state(&ledger, &grant, &jti, "accept", None))
                        }
                        Err(error) => Ok(meter_refusal(&ledger, &grant, &jti, &error)),
                    },
                }
            }
            "release" => match holds.get(&id).cloned() {
                None => Ok(meter_state(&ledger, &grant, &jti, "refuse", Some("rejected"))),
                Some(reservation) => match ledger.release(&reservation) {
                    Ok(()) => {
                        holds.remove(&id);
                        Ok(meter_state(&ledger, &grant, &jti, "accept", None))
                    }
                    Err(error) => Ok(meter_refusal(&ledger, &grant, &jti, &error)),
                },
            },
            other => Err(format!("unknown meter op {other}")),
        }?;
        let mut step_value = step_value;
        step_value["op"] = json!(op);
        step_value["id"] = json!(id);
        step_value["jti"] = json!(jti);
        out.push(step_value);
    }
    Ok(json!({"outcome": "accept", "steps": out}))
}

fn meter_refusal(ledger: &Ledger, grant: &Budget, jti: &str, error: &ChargeError) -> Value {
    let code = match error {
        ChargeError::Refused(Refusal::Exhausted { .. }) => "exhausted",
        ChargeError::Refused(Refusal::Insufficient { .. }) => "insufficient",
        ChargeError::Protocol(_) => "rejected",
    };
    meter_state(ledger, grant, jti, "refuse", Some(code))
}

fn meter_state(ledger: &Ledger, grant: &Budget, jti: &str, outcome: &str, code: Option<&str>) -> Value {
    let (committed, reserved) = ledger
        .outstanding("https://as.example", jti)
        .unwrap_or((0, 0));
    let mut value = json!({
        "outcome": outcome,
        "remaining": grant.amount() - committed - reserved,
        "committed": committed,
        "reserved": reserved,
    });
    if let Some(code) = code {
        value["code"] = json!(code);
    }
    value
}

fn account(grant: &Budget, jti: &str) -> TokenAccount {
    TokenAccount {
        jti: jti.to_owned(),
        grant: grant.clone(),
        ps: "https://ps.example".into(),
        sub: "person-1".into(),
        aud: "https://resource.example".into(),
        iss: "https://as.example".into(),
        jkt: "thumbprint".into(),
        tenant: None,
        mission: None,
    }
}

fn accepted_budget(budget: &Budget) -> Value {
    json!({
        "outcome": "accept",
        "amount": budget.amount(),
        "unit": budget.unit(),
        "decimals": budget.decimals(),
        "json": budget.to_value().to_string(),
    })
}

fn header_value(header: &BudgetHeader) -> Value {
    json!({
        "remaining": header.remaining,
        "cost": header.cost,
        "reserved": header.reserved,
        "required": header.required,
        "unit": header.unit,
        "decimals": header.decimals,
    })
}

fn refused(code: &str) -> Value {
    json!({"outcome": "refuse", "code": code})
}

fn code_error(error: &Error) -> &'static str {
    match error {
        Error::Malformed => "malformed",
        Error::Range => "range",
        Error::Denomination => "denomination",
        Error::Exceeds => "exceeds",
        Error::DecimalsMismatch => "decimals",
        Error::UndeclaredUnit => "undeclared",
        Error::Endpoint => "endpoint",
        Error::AccessMode => "access-mode",
        Error::Unavailable => "unavailable",
        Error::Signing => "signing",
    }
}

fn budget_from_value(value: &Value) -> Result<Result<Budget, &'static str>, String> {
    let amount = json_i64(&value["amount"])?;
    let unit = value["unit"].as_str().ok_or("unit")?.to_owned();
    let decimals = json_i64(&value["decimals"])?;
    Ok(Budget::new(amount, unit, decimals).map_err(|error| code_error(&error)))
}

fn must_budget(value: &Value) -> Result<Budget, String> {
    match budget_from_value(value)? {
        Ok(budget) => Ok(budget),
        Err(code) => Err(format!("grant {code}")),
    }
}

fn i64_field(value: &Value, name: &str) -> Result<i64, String> {
    json_i64(&value[name]).map_err(|_| format!("missing {name}"))
}

fn json_i64(value: &Value) -> Result<i64, String> {
    value.as_i64().ok_or_else(|| "not an i64".into())
}
