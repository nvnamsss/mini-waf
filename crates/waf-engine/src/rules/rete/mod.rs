//! RETE network — single-fact specialization for `RequestContext`.
//!
//! Compilation phase (`Network::compile`) extracts every condition leaf from
//! each rule's `when` clause into a unique **AlphaNode** (hash-consed via
//! canonical pretty-print). The remaining boolean structure (`&&`, `||`, `!`)
//! becomes a **Guard** DAG over alpha indices. A **Terminal** binds a guard +
//! salience + actions + rule name.

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;

use crate::rules::grl::ast::*;
use crate::rules::grl::printer::print_expr;
use crate::rules::rete::alpha::CompiledAlpha;

pub mod alpha;
pub mod terminal;
pub mod working_memory;
pub mod engine;

pub use alpha::{AlphaNode, AlphaId};
pub use terminal::{Terminal, Guard};

/// Compiled RETE network.
#[derive(Debug, Default, Clone)]
pub struct Network {
    pub alphas:    Vec<AlphaNode>,
    pub terminals: Vec<Terminal>,
    /// Hash-cons table: canonical expr-string → alpha index.
    alpha_index:   HashMap<String, AlphaId>,
}

impl Network {
    pub fn new() -> Self { Self::default() }

    /// Compile a batch of parsed rules into a single shared network.
    pub fn compile(rules: Vec<RuleAst>) -> Self {
        let mut net = Network::new();
        for r in rules {
            let guard = net.compile_guard(&r.when);
            net.terminals.push(Terminal {
                rule_name: r.name,
                salience:  r.salience,
                guard,
                actions:   r.then,
            });
        }
        // Sort terminals by salience desc — engine iterates in this order.
        net.terminals.sort_by(|a, b| b.salience.cmp(&a.salience));
        net
    }

    /// Recursive descent: `&&`/`||`/`!` become Guard combinators; everything
    /// else becomes a leaf alpha node.
    fn compile_guard(&mut self, e: &Expr) -> Guard {
        match e {
            Expr::Binary { op: BinOp::And, left, right } => {
                let l = self.compile_guard(left);
                let r = self.compile_guard(right);
                merge_and(l, r)
            }
            Expr::Binary { op: BinOp::Or,  left, right } => {
                let l = self.compile_guard(left);
                let r = self.compile_guard(right);
                merge_or(l, r)
            }
            Expr::Unary { op: UnaryOp::Not, expr } => {
                Guard::Not(Box::new(self.compile_guard(expr)))
            }
            Expr::Literal(Value::Bool(true))  => Guard::True,
            Expr::Literal(Value::Bool(false)) => Guard::False,
            other => {
                let id = self.intern_alpha(other.clone());
                Guard::Alpha(id)
            }
        }
    }

    fn intern_alpha(&mut self, expr: Expr) -> AlphaId {
        let key = print_expr(&expr);
        if let Some(id) = self.alpha_index.get(&key) { return *id; }
        let id = self.alphas.len();
        let compiled = compile_alpha(&expr);
        self.alphas.push(AlphaNode { id, expr, key: key.clone(), compiled });
        self.alpha_index.insert(key, id);
        id
    }

    pub fn alpha_count(&self)    -> usize { self.alphas.len() }
    pub fn rule_count(&self)     -> usize { self.terminals.len() }
}

/// Pre-compile an alpha node expression where possible.
///
/// Currently handles `matches(haystack_expr, "literal_string")` — the regex is
/// compiled once here and stored in the node, eliminating `Regex::new` on every
/// fire cycle (saves ~37–129 µs per call depending on pattern complexity).
fn compile_alpha(expr: &Expr) -> Option<CompiledAlpha> {
    if let Expr::Call(c) = expr {
        if c.name == "matches" && c.args.len() == 2 {
            if let Expr::Literal(Value::Str(pat)) = &c.args[1] {
                if let Ok(re) = Regex::new(pat) {
                    return Some(CompiledAlpha::MatchesRegex {
                        haystack: c.args[0].clone(),
                        re:       Arc::new(re),
                    });
                }
            }
        }
    }
    None
}

fn merge_and(l: Guard, r: Guard) -> Guard {
    match (l, r) {
        (Guard::And(mut a), Guard::And(b)) => { a.extend(b); Guard::And(a) }
        (Guard::And(mut a), b)             => { a.push(b);   Guard::And(a) }
        (a, Guard::And(mut b))             => { b.insert(0, a); Guard::And(b) }
        (a, b)                             => Guard::And(vec![a, b]),
    }
}
fn merge_or(l: Guard, r: Guard) -> Guard {
    match (l, r) {
        (Guard::Or(mut a), Guard::Or(b)) => { a.extend(b); Guard::Or(a) }
        (Guard::Or(mut a), b)            => { a.push(b);   Guard::Or(a) }
        (a, Guard::Or(mut b))            => { b.insert(0, a); Guard::Or(b) }
        (a, b)                           => Guard::Or(vec![a, b]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::grl::parser::parse;

    #[test]
    fn shares_identical_alpha_nodes() {
        let src = r#"
            rule "A" salience 10 {
                when contains_sqli(Request.Body) && Request.Method == "POST"
                then block("a");
            }
            rule "B" salience 5 {
                when contains_sqli(Request.Body) || Request.Path == "/x"
                then block("b");
            }
        "#;
        let rules = parse(src).unwrap();
        let net   = Network::compile(rules);
        // Three distinct leaves: contains_sqli(Body), Method=="POST", Path=="/x".
        assert_eq!(net.alpha_count(), 3);
        assert_eq!(net.rule_count(),  2);
        // Sorted by salience desc: A(10) before B(5).
        assert_eq!(net.terminals[0].rule_name, "A");
    }

    #[test]
    fn flattens_nested_and_or() {
        let src = r#"
            rule "X" {
                when (a() && b()) && (c() && d())
                then allow();
            }
        "#;
        let rules = parse(src).unwrap();
        let net   = Network::compile(rules);
        match &net.terminals[0].guard {
            Guard::And(parts) => assert_eq!(parts.len(), 4),
            other => panic!("expected flat AND, got {:?}", other),
        }
    }
}
