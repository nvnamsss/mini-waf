//! Canonical pretty-printer for AST nodes.
//!
//! Used as a deterministic key for hash-consing identical sub-expressions
//! across rules in the RETE alpha layer.

use super::ast::*;
use std::fmt::Write;

pub fn print_expr(e: &Expr) -> String {
    let mut out = String::new();
    fmt_expr(e, &mut out);
    out
}

fn fmt_expr(e: &Expr, out: &mut String) {
    match e {
        Expr::Literal(v)  => fmt_value(v, out),
        Expr::Path(p)     => { let _ = write!(out, "{}", p); }
        Expr::Call(c)     => fmt_call(c, out),
        Expr::Unary { op, expr } => {
            let sym = match op { UnaryOp::Not => "!" };
            out.push('('); out.push_str(sym); fmt_expr(expr, out); out.push(')');
        }
        Expr::Binary { op, left, right } => {
            out.push('(');
            fmt_expr(left, out);
            out.push(' '); out.push_str(bin_sym(*op)); out.push(' ');
            fmt_expr(right, out);
            out.push(')');
        }
    }
}

fn fmt_call(c: &CallExpr, out: &mut String) {
    let _ = write!(out, "{}(", c.name);
    for (i, a) in c.args.iter().enumerate() {
        if i > 0 { out.push(','); }
        fmt_expr(a, out);
    }
    out.push(')');
}

fn fmt_value(v: &Value, out: &mut String) {
    match v {
        Value::Null     => out.push_str("null"),
        Value::Bool(b)  => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i)   => { let _ = write!(out, "{}", i); }
        Value::Float(f) => { let _ = write!(out, "{}", f); }
        Value::Str(s)   => { let _ = write!(out, "{:?}", s); }
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::And => "&&", BinOp::Or  => "||",
        BinOp::Eq  => "==", BinOp::Neq => "!=",
        BinOp::Lt  => "<",  BinOp::Lte => "<=",
        BinOp::Gt  => ">",  BinOp::Gte => ">=",
        BinOp::Add => "+",  BinOp::Sub => "-",
        BinOp::Mul => "*",  BinOp::Div => "/",
    }
}
