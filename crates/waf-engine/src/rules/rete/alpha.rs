//! Alpha layer — single-fact pattern tests.

use std::sync::Arc;

use regex::Regex;

use crate::rules::grl::ast::Expr;

pub type AlphaId = usize;

/// Pre-compiled fast-path for alpha nodes whose evaluation pattern is known at
/// compile time. Currently handles `matches(haystack_expr, "literal_pattern")`
/// by compiling the regex once at `Network::compile` time instead of every
/// fire cycle.
#[derive(Clone)]
pub enum CompiledAlpha {
    /// `matches(haystack, pattern)` where `pattern` is a literal string.
    MatchesRegex {
        haystack: Expr,
        re:       Arc<Regex>,
    },
}

impl std::fmt::Debug for CompiledAlpha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompiledAlpha::MatchesRegex { haystack, re } =>
                write!(f, "MatchesRegex({:?}, {:?})", haystack, re.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlphaNode {
    pub id:       AlphaId,
    pub expr:     Expr,
    /// Canonical pretty-print; used for hash-cons sharing during compile.
    pub key:      String,
    /// Pre-compiled fast-path — `Some` when the expression can be evaluated
    /// without going through `eval_expr` / `dispatch` / `Regex::new`.
    pub compiled: Option<CompiledAlpha>,
}
