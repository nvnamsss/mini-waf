//! CRS ruleset evaluator backed by zentinel-modsec.

use crate::context::RequestContext;
use crate::rules::crs::types::{CrsResult, CrsRuntime};
use zentinel_modsec::variables::Collection;

/// A loaded and ready-to-evaluate CRS ruleset.
pub struct CrsRuleset {
    pub(crate) runtime: CrsRuntime,
    pub(crate) rule_count: usize,
}

impl CrsRuleset {
    /// Number of rule items (SecRule + SecMarker) parsed from conf files.
    pub fn len(&self) -> usize { self.rule_count }

    /// Evaluate _all_ CRS rules against `ctx` and return the accumulated scores
    /// and matched tags.
    pub fn evaluate(&self, ctx: &RequestContext) -> CrsResult {
        let mut result = CrsResult::default();
        let mut tx = self.runtime.modsec.new_transaction();
        let uri = match &ctx.query {
            Some(query) if !query.is_empty() => format!("{}?{}", ctx.path, query),
            _ => ctx.path.clone(),
        };

        if let Err(err) = tx.process_uri(&uri, &ctx.method, "HTTP/1.1") {
            tracing::warn!("crs: process_uri failed: {}", err);
            return result;
        }

        for (name, value) in &ctx.headers {
            if let Err(err) = tx.add_request_header(name, value) {
                tracing::debug!("crs: skipping request header {name}: {err}");
            }
        }

        if let Err(err) = tx.process_request_headers() {
            tracing::warn!("crs: process_request_headers failed: {}", err);
            return result;
        }

        if let Some(body) = &ctx.body {
            if let Err(err) = tx.append_request_body(body) {
                tracing::debug!("crs: append_request_body failed: {}", err);
            } else if let Err(err) = tx.process_request_body() {
                tracing::warn!("crs: process_request_body failed: {}", err);
            }
        }

        result.inbound_score = tx.anomaly_score() as i64;
        result.sql_injection_score = tx_value(&tx, "sql_injection_score");
        result.xss_score = tx_value(&tx, "xss_score");
        result.lfi_score = tx_value(&tx, "lfi_score");
        result.rce_score = tx_value(&tx, "rce_score");

        for rule_id in tx.matched_rules() {
            if let Ok(rule_id) = rule_id.parse::<u32>() {
                result.matched_rule_ids.push(rule_id);
                if let Some(tags) = self.runtime.rule_tags.get(&rule_id) {
                    for tag in tags {
                        result.matched_tags.insert(tag.clone());
                    }
                }
            }
        }

        if std::env::var("CRS_DEBUG").is_ok() && result.inbound_score > 0 {
            eprintln!(
                "[CRS_DEBUG] score={} matched_rule_ids={:?}",
                result.inbound_score,
                result.matched_rule_ids
            );
        }
        result
    }
}

fn tx_value(tx: &zentinel_modsec::Transaction, key: &str) -> i64 {
    tx.tx()
        .get(key)
        .and_then(|values| values.first().and_then(|value| value.parse::<i64>().ok()))
        .unwrap_or_default()
}
