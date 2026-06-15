//! Function registry — maps GRL function names to context-aware implementations.
//!
//! Built-in pure functions in `grl/functions.rs` (those with no request context
//! dependency) remain as-is and are called as a fallback.
//!
//! # Plugin pattern
//!
//! The idiomatic way to add a new function is:
//!
//! 1. Add a typed method to `RequestContext` in `context.rs`:
//!    ```ignore
//!    impl RequestContext {
//!        pub fn header_count(&self) -> i64 { self.headers.len() as i64 }
//!    }
//!    ```
//!
//! 2. Register it on the `Engine` before use (e.g. in `AppState::new`):
//!    ```ignore
//!    engine.registry.register("header_count", |ctx, _args| {
//!        Value::Int(ctx.header_count())
//!    });
//!    ```
//!
//! 3. Use it in a GRL rule:
//!    ```grl
//!    rule "TooManyHeaders" salience 500 {
//!        when header_count() > 50
//!        then block("header flood");
//!    }
//!    ```
//!
//! # Resolution order
//!
//! When the engine evaluates a function call:
//! 1. Registry lookup (context-aware, registered functions)
//! 2. `functions::dispatch` fallback (pure built-ins: `contains_sqli`, `matches`, …)
//! 3. `Value::Null`

use std::collections::HashMap;

use crate::context::RequestContext;
use crate::rules::grl::ast::Value;
use crate::rules::grl::functions;

/// A context-aware GRL function: receives the current request + evaluated args.
pub type CtxFn = Box<dyn Fn(&RequestContext, &[Value]) -> Value + Send + Sync>;

/// Per-engine function registry.
///
/// Stores context-aware functions alongside their GRL names. Falls back to the
/// built-in `functions::dispatch` for pure functions (no context needed).
#[derive(Default)]
pub struct FunctionRegistry {
    fns: HashMap<String, CtxFn>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named function. Overwrites any previous registration.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        f: impl Fn(&RequestContext, &[Value]) -> Value + Send + Sync + 'static,
    ) {
        self.fns.insert(name.into(), Box::new(f));
    }

    /// Invoke `name` with evaluated `args` against the request `ctx`.
    ///
    /// Registry entries win over built-ins, so you can override a built-in by
    /// registering a function with the same name.
    pub fn call(&self, name: &str, ctx: &RequestContext, args: &[Value]) -> Value {
        if let Some(f) = self.fns.get(name) {
            return f(ctx, args);
        }
        functions::dispatch(name, args)
    }
}

/// Register the default `RequestContext`-method wrappers.
///
/// Usually called once when constructing an `Engine`. Adds: `header_count`,
/// `has_header`, `is_path_under`. Add more registrations here as the
/// context grows.
pub fn register_context_defaults(registry: &mut FunctionRegistry) {
    registry.register("header_count", |ctx, _args| {
        Value::Int(ctx.header_count())
    });
    registry.register("has_header", |ctx, args| {
        let name = args.first().map(|v| v.as_str()).unwrap_or_default();
        Value::Bool(ctx.has_header(&name))
    });
    registry.register("is_path_under", |ctx, args| {
        let prefix = args.first().map(|v| v.as_str()).unwrap_or_default();
        Value::Bool(ctx.is_path_under(&prefix))
    });
}
