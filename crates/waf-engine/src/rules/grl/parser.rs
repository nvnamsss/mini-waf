//! GRL → AST parser using `pest`.

use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;

use super::ast::*;

#[derive(Parser)]
#[grammar = "rules/grl/grl.pest"]
struct GrlParser;

/// Parse a `.grl` source file containing zero or more rule definitions.
pub fn parse(src: &str) -> anyhow::Result<Vec<RuleAst>> {
    let mut pairs = GrlParser::parse(Rule::file, src)
        .map_err(|e| anyhow::anyhow!("grl parse error: {}", e))?;
    let file = pairs.next().ok_or_else(|| anyhow::anyhow!("empty grl file"))?;

    let mut rules = Vec::new();
    for pair in file.into_inner() {
        if matches!(pair.as_rule(), Rule::rule_def) {
            rules.push(parse_rule(pair)?);
        }
    }
    Ok(rules)
}

fn parse_rule(pair: Pair<Rule>) -> anyhow::Result<RuleAst> {
    let mut name = String::new();
    let mut salience: i32 = 0;
    let mut when: Option<Expr> = None;
    let mut then: Vec<Stmt> = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::string    => name = unquote(inner.as_str()),
            Rule::integer   => salience = inner.as_str().parse().unwrap_or(0),
            Rule::expression => when = Some(parse_expr(inner)?),
            Rule::statement => then.push(parse_stmt(inner)?),
            _ => {}
        }
    }

    Ok(RuleAst {
        name,
        salience,
        when: when.ok_or_else(|| anyhow::anyhow!("rule missing 'when' clause"))?,
        then,
    })
}

fn parse_stmt(pair: Pair<Rule>) -> anyhow::Result<Stmt> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::assignment => {
            let mut it = inner.into_inner();
            let target = parse_path(it.next().unwrap())?;
            let value = parse_expr(it.next().unwrap())?;
            Ok(Stmt::Assign { target, value })
        }
        Rule::call_stmt => {
            let call = inner.into_inner().next().unwrap();
            Ok(Stmt::Call(parse_call(call)?))
        }
        other => Err(anyhow::anyhow!("unexpected statement: {:?}", other)),
    }
}

fn parse_expr(pair: Pair<Rule>) -> anyhow::Result<Expr> {
    match pair.as_rule() {
        Rule::expression | Rule::or_expr => parse_binary(pair, BinOp::Or),
        Rule::and_expr => parse_binary(pair, BinOp::And),
        Rule::not_expr => {
            let mut inner = pair.into_inner().peekable();
            let mut negated = false;
            if let Some(p) = inner.peek() {
                if matches!(p.as_rule(), Rule::not_op) {
                    negated = true;
                    inner.next();
                }
            }
            let expr = parse_expr(inner.next().unwrap())?;
            if negated {
                Ok(Expr::Unary { op: UnaryOp::Not, expr: Box::new(expr) })
            } else {
                Ok(expr)
            }
        }
        Rule::cmp_expr => {
            let mut it = pair.into_inner();
            let left = parse_expr(it.next().unwrap())?;
            if let Some(op_pair) = it.next() {
                let op = match op_pair.as_str() {
                    "==" => BinOp::Eq,
                    "!=" => BinOp::Neq,
                    "<"  => BinOp::Lt,
                    "<=" => BinOp::Lte,
                    ">"  => BinOp::Gt,
                    ">=" => BinOp::Gte,
                    o    => return Err(anyhow::anyhow!("bad cmp op: {}", o)),
                };
                let right = parse_expr(it.next().unwrap())?;
                Ok(Expr::Binary { op, left: Box::new(left), right: Box::new(right) })
            } else {
                Ok(left)
            }
        }
        Rule::add_expr => parse_left_assoc(pair, &[("+", BinOp::Add), ("-", BinOp::Sub)]),
        Rule::mul_expr => parse_left_assoc(pair, &[("*", BinOp::Mul), ("/", BinOp::Div)]),
        Rule::primary => {
            let inner = pair.into_inner().next().unwrap();
            parse_expr(inner)
        }
        Rule::call_expr => Ok(Expr::Call(parse_call(pair)?)),
        Rule::path      => Ok(Expr::Path(parse_path(pair)?)),
        Rule::literal   => Ok(Expr::Literal(parse_literal(pair)?)),
        other => Err(anyhow::anyhow!("unexpected expr rule: {:?}", other)),
    }
}

/// Generic helper for left-associative N-ary chains: `a OP b OP c …`.
fn parse_binary(pair: Pair<Rule>, op: BinOp) -> anyhow::Result<Expr> {
    let mut it = pair.into_inner();
    let mut acc = parse_expr(it.next().unwrap())?;
    for next in it {
        let right = parse_expr(next)?;
        acc = Expr::Binary { op, left: Box::new(acc), right: Box::new(right) };
    }
    Ok(acc)
}

/// Left-assoc with operator-token-driven dispatch.
fn parse_left_assoc(pair: Pair<Rule>, ops: &[(&str, BinOp)]) -> anyhow::Result<Expr> {
    let mut it = pair.into_inner();
    let mut acc = parse_expr(it.next().unwrap())?;
    while let Some(op_pair) = it.next() {
        let op_text = op_pair.as_str();
        let op = ops.iter().find(|(t, _)| *t == op_text).map(|(_, op)| *op)
            .ok_or_else(|| anyhow::anyhow!("unknown op: {}", op_text))?;
        let right = parse_expr(it.next().unwrap())?;
        acc = Expr::Binary { op, left: Box::new(acc), right: Box::new(right) };
    }
    Ok(acc)
}

fn parse_call(pair: Pair<Rule>) -> anyhow::Result<CallExpr> {
    let mut it = pair.into_inner();
    let name = it.next().unwrap().as_str().to_string();
    let mut args = Vec::new();
    if let Some(arg_list) = it.next() {
        for arg in arg_list.into_inner() {
            args.push(parse_expr(arg)?);
        }
    }
    Ok(CallExpr { name, args })
}

fn parse_path(pair: Pair<Rule>) -> anyhow::Result<Path> {
    let mut segments = Vec::new();
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::ident  => segments.push(PathSeg::Field(p.as_str().to_string())),
            Rule::string => segments.push(PathSeg::Index(unquote(p.as_str()))),
            _ => {}
        }
    }
    Ok(Path { segments })
}

fn parse_literal(pair: Pair<Rule>) -> anyhow::Result<Value> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::string   => Ok(Value::Str(unquote(inner.as_str()))),
        Rule::float    => Ok(Value::Float(inner.as_str().parse().unwrap_or(0.0))),
        Rule::integer  => Ok(Value::Int(inner.as_str().parse().unwrap_or(0))),
        Rule::bool_lit => Ok(Value::Bool(inner.as_str() == "true")),
        Rule::null_lit => Ok(Value::Null),
        other => Err(anyhow::anyhow!("bad literal: {:?}", other)),
    }
}

fn unquote(s: &str) -> String {
    let trimmed = s.trim_matches('"');
    trimmed.replace("\\\"", "\"").replace("\\n", "\n").replace("\\t", "\t")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rule() {
        let src = r#"
            rule "Allow" salience 1 {
                when true
                then allow();
            }
        "#;
        let rules = parse(src).expect("parse");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Allow");
        assert_eq!(rules[0].salience, 1);
        assert_eq!(rules[0].then.len(), 1);
    }

    #[test]
    fn parses_complex_rule() {
        let src = r#"
            rule "BlockSqli" salience 90 {
                when contains_sqli(Request.Query) || contains_sqli(Request.Body)
                then
                    Request.RiskScore = Request.RiskScore + 80;
                    block("sqli detected");
            }
        "#;
        let rules = parse(src).expect("parse");
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.name, "BlockSqli");
        assert_eq!(r.salience, 90);
        assert_eq!(r.then.len(), 2);
        // when clause must be a binary OR of two calls
        match &r.when {
            Expr::Binary { op: BinOp::Or, .. } => {}
            other => panic!("expected OR expr, got {:?}", other),
        }
    }

    #[test]
    fn parses_multiple_rules() {
        let src = r#"
            rule "A" { when true then allow(); }
            rule "B" salience 5 { when false then block("x"); }
        "#;
        let rules = parse(src).expect("parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].salience, 5);
    }

    #[test]
    fn parses_path_with_index() {
        let src = r#"
            rule "Hdr" {
                when Request.Headers["X-Forwarded-For"] == "1.2.3.4"
                then block("xff");
            }
        "#;
        let rules = parse(src).expect("parse");
        match &rules[0].when {
            Expr::Binary { op: BinOp::Eq, left, .. } => match left.as_ref() {
                Expr::Path(p) => {
                    assert_eq!(p.segments.len(), 3);
                    assert!(matches!(&p.segments[2], PathSeg::Index(s) if s == "X-Forwarded-For"));
                }
                _ => panic!("expected path"),
            },
            _ => panic!("expected eq"),
        }
    }

    #[test]
    fn parses_nested_logic() {
        let src = r#"
            rule "Mix" {
                when (Request.Method == "POST" && contains_sqli(Request.Body)) || !ip_in_whitelist(Request.ClientIp)
                then block("nested");
            }
        "#;
        parse(src).expect("parse");
    }
}
