//! Plugin system — install new GRL functions and per-request context enrichers
//! without touching the engine core.
//!
//! # Implementing a plugin
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use waf_engine::context::RequestContext;
//! use waf_engine::plugin::Plugin;
//! use waf_engine::rules::grl::registry::FunctionRegistry;
//! use waf_engine::rules::grl::ast::Value;
//!
//! pub struct GeoPlugin { db: Arc<GeoDb> }
//!
//! impl Plugin for GeoPlugin {
//!     fn name(&self) -> &'static str { "geo" }
//!
//!     fn register(&self, registry: &mut FunctionRegistry) {
//!         // Arc-clone into the closure so it is 'static + Send + Sync.
//!         let db = Arc::clone(&self.db);
//!         registry.register("country_code", move |ctx, _args| {
//!             Value::Str(db.lookup(&ctx.client_ip))
//!         });
//!     }
//!
//!     // Optional: pre-populate ctx.extensions so rules can read
//!     // Request.Ext["geo.country"] without calling a function.
//!     fn enrich(&self, ctx: &mut RequestContext) {
//!         ctx.extensions.insert("geo.country".into(), self.db.lookup(&ctx.client_ip));
//!     }
//! }
//!
//! // Install once at startup:
//! engine.install(GeoPlugin { db: Arc::clone(&geo_db) });
//!
//! // Call once per request, before engine.fire():
//! engine.enrich(&mut ctx);
//! ```
//!
//! After installation:
//! - GRL rule: `when country_code() == "CN" then block("geo-block");`
//! - GRL rule: `when Request.Ext["geo.country"] == "CN" then block("geo-block");`

use crate::context::RequestContext;
use crate::rules::grl::registry::FunctionRegistry;

/// A WAF plugin.
///
/// Plugins operate at two points in the request lifecycle:
///
/// | Point | Method | When |
/// |---|---|---|
/// | Startup | [`register`](Plugin::register) | Called once when installed on an `Engine` |
/// | Per-request | [`enrich`](Plugin::enrich) | Called per request via [`Engine::enrich`] |
///
/// The separation lets plugins choose: compute inside a GRL closure (lazily,
/// only if the rule fires) or pre-populate `ctx.extensions` (eagerly, always
/// available via `Request.Ext["key"]`).
pub trait Plugin: Send + Sync + 'static {
    /// Short unique name used for identification and debug logging.
    fn name(&self) -> &'static str;

    /// Register GRL-callable functions contributed by this plugin.
    ///
    /// Any state the closure needs must be captured at registration time.
    /// Wrap shared resources in `Arc` and clone into each closure:
    ///
    /// ```rust,ignore
    /// let handle = Arc::clone(&self.handle);
    /// registry.register("my_fn", move |ctx, args| { handle.query(ctx) });
    /// ```
    fn register(&self, registry: &mut FunctionRegistry);

    /// Enrich `ctx.extensions` before rules fire (optional — default is no-op).
    ///
    /// Extensions are accessible in GRL as `Request.Ext["key"]`.
    /// An empty default implementation is provided so you only override when
    /// you actually need per-request enrichment.
    fn enrich(&self, _ctx: &mut RequestContext) {}
}
