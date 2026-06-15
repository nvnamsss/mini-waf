//! Typed AST for the GRL rule language.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct RuleAst {
    pub name: String,
    pub salience: i32,
    pub when: Expr,
    pub then: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `Request.RiskScore = Request.RiskScore + 80`
    Assign { target: Path, value: Expr },
    /// `block("reason")`, `allow()`, `challenge()`, `rate_limit(60)`, `log("msg")`
    Call(CallExpr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Value),
    Path(Path),
    Call(CallExpr),
    Binary { op: BinOp, left: Box<Expr>, right: Box<Expr> },
    Unary { op: UnaryOp, expr: Box<Expr> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallExpr {
    pub name: String,
    pub args: Vec<Expr>,
}

/// `Request.Path` or `Request.Headers["X-Forwarded-For"]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path {
    pub segments: Vec<PathSeg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSeg {
    Field(String),
    Index(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    And, Or,
    Eq, Neq, Lt, Lte, Gt, Gte,
    Add, Sub, Mul, Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl Value {
    pub fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b)  => *b,
            Value::Null     => false,
            Value::Int(i)   => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s)   => !s.is_empty(),
        }
    }

    pub fn as_int(&self) -> i64 {
        match self {
            Value::Int(i)   => *i,
            Value::Float(f) => *f as i64,
            Value::Bool(b)  => *b as i64,
            Value::Str(s)   => s.parse().unwrap_or(0),
            Value::Null     => 0,
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Value::Str(s)   => s.clone(),
            Value::Int(i)   => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Bool(b)  => b.to_string(),
            Value::Null     => String::new(),
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.segments.iter().enumerate() {
            match seg {
                PathSeg::Field(name) => {
                    if i > 0 { write!(f, ".")?; }
                    write!(f, "{}", name)?;
                }
                PathSeg::Index(key) => write!(f, "[\"{}\"]", key)?,
            }
        }
        Ok(())
    }
}
