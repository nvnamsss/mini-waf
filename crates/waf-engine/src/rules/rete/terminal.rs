//! Terminal nodes — one per rule. A `Guard` is the boolean DAG over alpha
//! results computed by the engine for the current fact.

use super::alpha::AlphaId;
use crate::rules::grl::ast::Stmt;

#[derive(Debug, Clone)]
pub enum Guard {
    True,
    False,
    Alpha(AlphaId),
    And(Vec<Guard>),
    Or(Vec<Guard>),
    Not(Box<Guard>),
}

#[derive(Debug, Clone)]
pub struct Terminal {
    pub rule_name: String,
    pub salience:  i32,
    pub guard:     Guard,
    pub actions:   Vec<Stmt>,
}

impl Guard {
    /// Evaluate against a slice of pre-computed alpha truth values.
    pub fn eval(&self, alphas: &[bool]) -> bool {
        match self {
            Guard::True       => true,
            Guard::False      => false,
            Guard::Alpha(id)  => alphas.get(*id).copied().unwrap_or(false),
            Guard::And(gs)    => gs.iter().all(|g| g.eval(alphas)),
            Guard::Or(gs)     => gs.iter().any(|g| g.eval(alphas)),
            Guard::Not(g)     => !g.eval(alphas),
        }
    }
}
