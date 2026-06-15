//! Expression evaluator + action runner + RETE firing loop.

use waf_types::decision::{ChallengeKind, Decision};

use super::Network;
use super::working_memory::{ChallengeReq, Outcome, WorkingMemory};
use crate::context::RequestContext;
use crate::rules::grl::ast::*;
use crate::plugin::Plugin;
use crate::rules::grl::registry::{register_context_defaults, FunctionRegistry};

/// Maximum number of fire-cycles per request (re-triggering cap).
const MAX_CYCLES: u32 = 16;

pub struct Engine {
    pub network:  Network,
    /// Context-aware function registry. Populated by [`Engine::install`] and
    /// the built-in defaults. You can also call `registry.register(…)` directly
    /// for one-off functions that don't need a full plugin.
    pub registry: FunctionRegistry,
    plugins:      Vec<Box<dyn Plugin>>,
}

impl Engine {
    pub fn new(network: Network) -> Self {
        let mut registry = FunctionRegistry::new();
        register_context_defaults(&mut registry);
        Self { network, registry, plugins: Vec::new() }
    }

    /// Install a plugin: registers its GRL functions and stores it for
    /// per-request [`enrich`](Engine::enrich) calls.
    pub fn install(&mut self, plugin: impl Plugin) {
        plugin.register(&mut self.registry);
        self.plugins.push(Box::new(plugin));
    }

    /// Run every installed plugin's [`enrich`](Plugin::enrich) method against
    /// `ctx`. Call this once per request **before** [`Engine::fire`].
    pub fn enrich(&self, ctx: &mut RequestContext) {
        for p in &self.plugins {
            p.enrich(ctx);
        }
    }

    /// Run all matching rules against `fact` until quiescent (or cap hit).
    /// Returns the final outcome.
    pub fn fire(&self, fact: &RequestContext) -> Outcome {
        // tracing::debug!(
        //     request_id = %fact.request_id,
        //     method = %fact.method,
        //     path = %fact.path,
        //     rules = self.network.terminals.len(),
        //     "engine::fire called"
        // );
        let mut wm = WorkingMemory::new(fact, &self.registry);
        let mut fired_at_least_once: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for _cycle in 0..MAX_CYCLES {
            // Recompute alpha truth values against current scratch overlay.
            let alphas: Vec<bool> = self.network.alphas.iter()
                .map(|a| eval_alpha(a, &wm))
                .collect();

            // Conflict set in salience order (already sorted at compile time).
            let mut any_new = false;
            for term in &self.network.terminals {
                if !term.guard.eval(&alphas) {
                    tracing::debug!(rule = %term.rule_name, "rule condition not met (skipped)");
                    continue;
                }
                if fired_at_least_once.contains(&term.rule_name) { continue; }
                fired_at_least_once.insert(term.rule_name.clone());
                wm.outcome.matched_rules.push(term.rule_name.clone());

                for stmt in &term.actions {
                    run_stmt(stmt, &mut wm, &mut fired_at_least_once);
                }
                any_new = true;
                // After firing one rule, re-evaluate alphas so subsequent
                // rules see the latest scratch state. Break out of inner
                // loop to restart conflict-set scan.
                break;
            }
            if !any_new { break; }
            if wm.outcome.block_reason.is_some() { break; }
            if wm.outcome.allow { break; }
        }

        wm.outcome
    }
}

/// Convert an `Outcome` into a final `Decision`. Block wins; then challenge;
/// then rate-limit; otherwise allow.
pub fn outcome_to_decision(o: &Outcome) -> Decision {
    if let Some(reason) = &o.block_reason {
        return Decision::Block { reason: reason.clone() };
    }
    if let Some(c) = o.challenge {
        return Decision::Challenge(match c {
            ChallengeReq::Js  => ChallengeKind::JsChallenge,
            ChallengeReq::Pow => ChallengeKind::ProofOfWork,
        });
    }
    if let Some(secs) = o.rate_limit_secs {
        return Decision::RateLimit { retry_after_secs: secs };
    }
    Decision::Allow
}

// ─── Alpha evaluator ─────────────────────────────────────────────────────────

/// Evaluate an alpha node, using the pre-compiled fast-path when available.
///
/// Falls back to `eval_expr` for any node without a pre-compiled form.
pub fn eval_alpha(node: &crate::rules::rete::alpha::AlphaNode, wm: &WorkingMemory) -> bool {
    use crate::rules::grl::ast::Value;
    use crate::rules::rete::alpha::CompiledAlpha;
    if let Some(compiled) = &node.compiled {
        match compiled {
            CompiledAlpha::MatchesRegex { haystack, re } => {
                return match eval_expr(haystack, wm) {
                    Value::Str(s) => re.is_match(&s),
                    v             => re.is_match(&v.as_str()),
                };
            }
        }
    }
    eval_expr(&node.expr, wm).as_bool()
}

// ─── Statement runner ────────────────────────────────────────────────────────

fn run_stmt(stmt: &Stmt, wm: &mut WorkingMemory, fired: &mut std::collections::HashSet<String>) {
    match stmt {
        Stmt::Assign { target, value } => {
            let v = eval_expr(value, wm);
            wm.write_path(target, v);
        }
        Stmt::Call(c) => { run_action(c, wm, fired); }
    }
}

fn run_action(call: &CallExpr, wm: &mut WorkingMemory, fired: &mut std::collections::HashSet<String>) {
    let args: Vec<Value> = call.args.iter().map(|a| eval_expr(a, wm)).collect();
    match call.name.as_str() {
        "block"      => { wm.outcome.block_reason = Some(args.get(0).map(|v| v.as_str()).unwrap_or_default()); }
        "allow"      => { wm.outcome.allow = true; }
        "challenge"  => {
            let kind = args.get(0).map(|v| v.as_str()).unwrap_or_default();
            wm.outcome.challenge = Some(if kind == "pow" { ChallengeReq::Pow } else { ChallengeReq::Js });
        }
        "rate_limit" => { wm.outcome.rate_limit_secs = Some(args.get(0).map(|v| v.as_int() as u64).unwrap_or(60)); }
        "log"        => { wm.outcome.log_messages.push(args.get(0).map(|v| v.as_str()).unwrap_or_default()); }
        "retract"    => { fired.insert(args.get(0).map(|v| v.as_str()).unwrap_or_default()); }
        other => {
            // Unknown action — log and ignore.
            wm.outcome.log_messages.push(format!("unknown action: {}", other));
        }
    }
}

// ─── Expression evaluator ────────────────────────────────────────────────────

pub fn eval_expr(e: &Expr, wm: &WorkingMemory) -> Value {
    match e {
        Expr::Literal(v) => v.clone(),
        Expr::Path(p)    => wm.read_path(p),
        Expr::Call(c)    => eval_fn(c, wm),
        Expr::Unary { op: UnaryOp::Not, expr } => Value::Bool(!eval_expr(expr, wm).as_bool()),
        Expr::Binary { op, left, right } => eval_binary(*op, left, right, wm),
    }
}

fn eval_binary(op: BinOp, l: &Expr, r: &Expr, wm: &WorkingMemory) -> Value {
    match op {
        BinOp::And => Value::Bool(eval_expr(l, wm).as_bool() && eval_expr(r, wm).as_bool()),
        BinOp::Or  => Value::Bool(eval_expr(l, wm).as_bool() || eval_expr(r, wm).as_bool()),
        _ => {
            let lv = eval_expr(l, wm);
            let rv = eval_expr(r, wm);
            match op {
                BinOp::Eq  => Value::Bool(value_eq(&lv, &rv)),
                BinOp::Neq => Value::Bool(!value_eq(&lv, &rv)),
                BinOp::Lt  => Value::Bool(lv.as_int() <  rv.as_int()),
                BinOp::Lte => Value::Bool(lv.as_int() <= rv.as_int()),
                BinOp::Gt  => Value::Bool(lv.as_int() >  rv.as_int()),
                BinOp::Gte => Value::Bool(lv.as_int() >= rv.as_int()),
                BinOp::Add => match (&lv, &rv) {
                    (Value::Str(a), b) => Value::Str(format!("{}{}", a, b.as_str())),
                    (a, Value::Str(b)) => Value::Str(format!("{}{}", a.as_str(), b)),
                    _ => Value::Int(lv.as_int() + rv.as_int()),
                },
                BinOp::Sub => Value::Int(lv.as_int() - rv.as_int()),
                BinOp::Mul => Value::Int(lv.as_int() * rv.as_int()),
                BinOp::Div => Value::Int(lv.as_int() / rv.as_int().max(1)),
                _ => Value::Null,
            }
        }
    }
}

fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y))   => x == y,
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Str(x), Value::Str(y))   => x == y,
        // Cross-type: compare via string form for robustness.
        _ => a.as_str() == b.as_str(),
    }
}

// ─── Built-in functions (Phase 6 will replace SQLi/XSS with real detectors) ──

fn eval_fn(call: &CallExpr, wm: &WorkingMemory) -> Value {
    let args: Vec<Value> = call.args.iter().map(|a| eval_expr(a, wm)).collect();
    wm.registry.call(&call.name, wm.fact, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::grl::parser::parse;
    use std::collections::HashMap;
    use waf_types::{risk::RiskScore, tier::Tier};

    fn ctx(method: &str, path: &str, body: &str) -> RequestContext {
        RequestContext {
            request_id:    "test".into(),
            arrived_at_ms: 0,
            method:        method.into(),
            path:          path.into(),
            query:         None,
            tier:          Tier::CatchAll,
            client_ip:     "127.0.0.1".into(),
            xff_header:    None,
            headers:       HashMap::new(),
            body:          Some(body.as_bytes().to_vec()),
            session_id:    None,
            device_fp:     None,
            risk_score:    RiskScore::ZERO,
            matched_rule_id: None,
            extensions:    HashMap::new(),
        }
    }

    #[test]
    fn literal_block_rule_fires() {
        let src = r#"
            rule "BlockPostX" salience 10 {
                when Request.Method == "POST" && Request.Path == "/x"
                then block("matched");
            }
        "#;
        let net = Network::compile(parse(src).unwrap());
        let eng = Engine::new(net);
        let outcome = eng.fire(&ctx("POST", "/x", ""));
        assert_eq!(outcome.block_reason.as_deref(), Some("matched"));
    }

    #[test]
    fn salience_orders_rules() {
        let src = r#"
            rule "Allow"  salience 1  { when true then allow(); }
            rule "BlockA" salience 50 { when true then block("a"); }
            rule "BlockB" salience 99 { when true then block("b"); }
        "#;
        let net = Network::compile(parse(src).unwrap());
        let eng = Engine::new(net);
        let outcome = eng.fire(&ctx("GET", "/", ""));
        assert_eq!(outcome.block_reason.as_deref(), Some("b"));
    }

    #[test]
    fn assignment_and_dependency_chain() {
        let src = r#"
            rule "Score" salience 50 {
                when Request.Method == "POST"
                then Request.RiskScore = 90;
            }
            rule "BlockHighRisk" salience 10 {
                when Request.RiskScore >= 80
                then block("high risk");
            }
        "#;
        let net = Network::compile(parse(src).unwrap());
        let eng = Engine::new(net);
        let outcome = eng.fire(&ctx("POST", "/", ""));
        assert_eq!(outcome.block_reason.as_deref(), Some("high risk"));
    }

    #[test]
    fn retract_prevents_rule_from_firing() {
        // "Blocker" retracts "Target" before it can fire.
        let src = r#"
            rule "Blocker" salience 99 {
                when true
                then retract("Target");
            }
            rule "Target" salience 1 {
                when true
                then block("should not reach");
            }
        "#;
        let net = Network::compile(parse(src).unwrap());
        let eng = Engine::new(net);
        let outcome = eng.fire(&ctx("GET", "/", ""));
        assert!(outcome.block_reason.is_none(), "retracted rule must not fire");
    }
}
