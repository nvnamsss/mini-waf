//! Geo-blocking plugin — resolves a request's country code and exposes it to GRL.
//!
//! Country resolution order (first non-empty value wins):
//! 1. Request header (e.g. `CF-IPCountry` set by a CDN/load balancer)
//! 2. MaxMind GeoLite2-Country database lookup on the canonical client IP
//! 3. Empty string — no data available
//!
//! The resolved code is stored in `ctx.extensions["geo.country"]` by
//! [`GeoPlugin::enrich`] so every subsequent GRL call is a cheap O(1) read.
//!
//! # GRL functions registered
//!
//! | Function | Args | Returns |
//! |---|---|---|
//! | `GetCountry()` | — | Country code from pre-enriched context (header → DB) |
//! | `GetCountry(ip)` | IP string | Direct DB lookup for an explicit IP |
//! | `geo_blocked()` | — | `true` if the resolved country is in the blocked list |
//!
//! # Example GRL rules
//!
//! ```grl
//! // Simple block using the configured blocked_countries list:
//! rule "GeoBlock" salience 950 {
//!     when geo_blocked()
//!     then
//!         Request.RiskScore = Request.RiskScore + 80;
//!         block("geo-block");
//! }
//!
//! // Custom per-rule country check:
//! rule "GeoHighRisk" salience 900 {
//!     when GetCountry() == "KP" || GetCountry() == "IR"
//!     then block("geo-block");
//! }
//!
//! // Explicit IP lookup (e.g. from a header carrying the original IP):
//! rule "GeoCheckXFF" salience 890 {
//!     when GetCountry(Request.Xff) == "KP"
//!     then block("geo-block");
//! }
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use crate::context::RequestContext;
use crate::plugin::Plugin;
use crate::rules::grl::ast::Value;
use crate::rules::grl::registry::FunctionRegistry;

/// Default header names (lowercase) checked for a pre-resolved country code.
const DEFAULT_COUNTRY_HEADERS: &[&str] = &[
    "cf-ipcountry",        // Cloudflare
    "x-country",           // generic CDN
    "x-geoip-country",     // nginx GeoIP module
    "x-geo-country",       // AWS / custom
];

/// Geo-blocking WAF plugin.
pub struct GeoPlugin {
    /// MaxMind reader. `None` when no `db_path` is configured or the file
    /// could not be opened — the plugin degrades gracefully to header-only mode.
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    /// Additional header names (lowercase) to check before the DB lookup.
    /// Merged with `DEFAULT_COUNTRY_HEADERS` at check time.
    extra_headers: Vec<String>,
    /// Set of uppercase country codes that trigger a block.
    blocked_countries: Vec<String>,
}

impl GeoPlugin {
    /// Build the plugin.
    ///
    /// * `db_path` — optional path to a `GeoLite2-Country.mmdb` file.
    /// * `extra_headers` — additional header names (any case) to check for a
    ///   pre-resolved country code before falling back to the database.
    /// * `blocked_countries` — ISO 3166-1 alpha-2 country codes that should be
    ///   blocked. An empty list disables geo-blocking (the plugin still enriches
    ///   `ctx.extensions["geo.country"]` for use in custom rules).
    pub fn new(
        db_path: Option<&str>,
        extra_headers: impl IntoIterator<Item = String>,
        blocked_countries: impl IntoIterator<Item = String>,
    ) -> Self {
        let reader = db_path.and_then(|p| {
            match maxminddb::Reader::open_readfile(p) {
                Ok(r) => {
                    tracing::info!("geo: loaded database from '{}'", p);
                    Some(Arc::new(r))
                }
                Err(e) => {
                    tracing::warn!("geo: could not open database '{}': {} — header-only mode", p, e);
                    None
                }
            }
        });

        Self {
            reader,
            extra_headers: extra_headers.into_iter().map(|h| h.to_lowercase()).collect(),
            blocked_countries: blocked_countries.into_iter().map(|c| c.to_uppercase()).collect(),
        }
    }

    // ── private helpers ───────────────────────────────────────────────────

    /// Look up the ISO country code for `ip` in the MaxMind database.
    /// Returns an empty string when the reader is absent or the IP is unknown.
    fn lookup_ip(&self, ip: &str) -> String {
        let addr: IpAddr = match ip.trim().parse() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };
        let Some(reader) = &self.reader else { return String::new(); };
        match reader.lookup::<maxminddb::geoip2::Country>(addr) {
            Ok(record) => record
                .country
                .and_then(|c| c.iso_code)
                .unwrap_or_default()
                .to_uppercase(),
            Err(_) => String::new(),
        }
    }

    /// Extract a country code from the request headers.
    /// Returns `None` when no matching, non-empty header is found.
    fn country_from_headers(&self, ctx: &RequestContext) -> Option<String> {
        for name in DEFAULT_COUNTRY_HEADERS
            .iter()
            .copied()
            .chain(self.extra_headers.iter().map(|s| s.as_str()))
        {
            let val = ctx.headers.iter()
                .find(|(k, _)| k.to_lowercase() == name)
                .map(|(_, v)| v.trim().to_uppercase());

            if let Some(v) = val {
                // Cloudflare uses "XX" for unknown; treat dashes and "XX" as absent.
                if !v.is_empty() && v != "-" && v != "XX" {
                    return Some(v);
                }
            }
        }
        None
    }
}

impl Plugin for GeoPlugin {
    fn name(&self) -> &'static str { "geo" }

    /// Pre-compute the country code for this request and store it in
    /// `ctx.extensions["geo.country"]` so GRL calls to `GetCountry()` are
    /// instant O(1) reads rather than repeated DB lookups.
    fn enrich(&self, ctx: &mut RequestContext) {
        let country = self.country_from_headers(ctx)
            .unwrap_or_else(|| self.lookup_ip(&ctx.client_ip));
        ctx.extensions.insert("geo.country".into(), country);
    }

    fn register(&self, registry: &mut FunctionRegistry) {
        // `GetCountry()` — no args: reads the value pre-computed by enrich().
        // `GetCountry(ip)` — explicit IP: does a direct DB lookup (no header check).
        let reader = self.reader.as_ref().map(Arc::clone);
        registry.register("GetCountry", move |ctx, args| {
            if let Some(ip_val) = args.first() {
                // Explicit IP argument path: bypass header logic, hit DB directly.
                let ip = ip_val.as_str();
                if !ip.is_empty() {
                    let country = reader.as_ref()
                        .and_then(|r| {
                            ip.trim().parse::<IpAddr>().ok().and_then(|addr| {
                                r.lookup::<maxminddb::geoip2::Country>(addr).ok()
                            })
                        })
                        .and_then(|rec| rec.country)
                        .and_then(|c| c.iso_code)
                        .map(|s| s.to_uppercase())
                        .unwrap_or_default();
                    return Value::Str(country);
                }
            }
            // No arg: return the value set by enrich() (header → DB).
            Value::Str(ctx.extensions.get("geo.country").cloned().unwrap_or_default())
        });

        // `geo_blocked()` — returns true when the request's country is in the
        // configured blocked_countries list.
        let blocked = self.blocked_countries.clone();
        registry.register("geo_blocked", move |ctx, _args| {
            let country = ctx.extensions.get("geo.country").map(|s| s.as_str()).unwrap_or("");
            Value::Bool(!country.is_empty() && blocked.iter().any(|b| b == country))
        });
    }
}
