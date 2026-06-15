use std::sync::Arc;

use crate::{
    context::RequestContext,
    lists::ip_list::IpListStore,
    plugin::Plugin,
    rules::grl::{ast::Value, registry::FunctionRegistry},
};

/// WAF plugin that wires `IpListStore` into the GRL rule engine.
///
/// # GRL functions registered
///
/// | Function | Argument | Returns |
/// |---|---|---|
/// | `ip_in_blacklist(ip_str)` | any string (usually `Request.ClientIp`) | `bool` |
/// | `ip_in_whitelist(ip_str)` | any string | `bool` |
///
/// # Per-request enrichment
///
/// Before rules fire, the plugin calls [`enrich`](Plugin::enrich) and sets:
/// - `ctx.extensions["blacklisted"]` = `"true"` / `"false"`
/// - `ctx.extensions["whitelisted"]` = `"true"` / `"false"`
///
/// These are then accessible in GRL as:
/// ```grl
/// when Request.Ext["blacklisted"] == "true" then block("blacklisted ip");
/// ```
///
/// # Usage
///
/// ```rust,ignore
/// let store = Arc::new(IpListStore::new());
/// store.load_blacklist_from_file(Path::new("config/blacklist.txt"))?;
///
/// engine.install(BlacklistPlugin::new(Arc::clone(&store)));
/// // per request:
/// engine.enrich(&mut ctx);
/// let outcome = engine.fire(&ctx);
/// ```
pub struct BlacklistPlugin {
    store: Arc<IpListStore>,
}

impl BlacklistPlugin {
    pub fn new(store: Arc<IpListStore>) -> Self {
        Self { store }
    }
}

impl Plugin for BlacklistPlugin {
    fn name(&self) -> &'static str { "blacklist" }

    fn register(&self, registry: &mut FunctionRegistry) {
        let bl = Arc::clone(&self.store);
        registry.register("ip_in_blacklist", move |ctx, args| {
            // Prefer the explicit argument; fall back to Request.ClientIp.
            let ip = args.first().map(|v| v.as_str()).unwrap_or_else(|| ctx.client_ip.clone());
            Value::Bool(bl.is_blacklisted(&ip))
        });

        let wl = Arc::clone(&self.store);
        registry.register("ip_in_whitelist", move |ctx, args| {
            let ip = args.first().map(|v| v.as_str()).unwrap_or_else(|| ctx.client_ip.clone());
            Value::Bool(wl.is_whitelisted(&ip))
        });
    }

    fn enrich(&self, ctx: &mut RequestContext) {
        ctx.extensions.insert(
            "blacklisted".into(),
            self.store.is_blacklisted(&ctx.client_ip).to_string(),
        );
        ctx.extensions.insert(
            "whitelisted".into(),
            self.store.is_whitelisted(&ctx.client_ip).to_string(),
        );
    }
}
