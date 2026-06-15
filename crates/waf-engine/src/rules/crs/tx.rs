//! Per-request CRS transaction state (mirrors ModSecurity's `TX:` variable collection).

use std::collections::HashMap;
use crate::rules::crs::types::{SetVarOp, SetVarRhs, VarOp};

/// Mutable scoring variables for one request evaluation.
pub struct TxState {
    vars: HashMap<String, i64>,
    /// String-valued TX variables (e.g. `allowed_methods`).
    str_vars: HashMap<String, String>,
}

impl TxState {
    /// Initialise with CRS v4 defaults (paranoia level 2, threshold 5).
    pub fn new() -> Self {
        let mut vars = HashMap::with_capacity(32);

        // Severity weights used in setvar arithmetic
        vars.insert("critical_anomaly_score".into(), 5);
        vars.insert("error_anomaly_score".into(),    4);
        vars.insert("warning_anomaly_score".into(),  3);
        vars.insert("notice_anomaly_score".into(),   2);

        // Paranoia and threshold settings
        vars.insert("detection_paranoia_level".into(),       2);
        vars.insert("blocking_paranoia_level".into(),        2);
        vars.insert("inbound_anomaly_score_threshold".into(), 5);
        vars.insert("outbound_anomaly_score_threshold".into(), 4);

        // Running inbound anomaly scores (accumulated by setvars)
        vars.insert("inbound_anomaly_score_pl1".into(), 0);
        vars.insert("inbound_anomaly_score_pl2".into(), 0);
        vars.insert("inbound_anomaly_score_pl3".into(), 0);
        vars.insert("inbound_anomaly_score_pl4".into(), 0);

        // Attack-category breakdown scores
        vars.insert("sql_injection_score".into(), 0);
        vars.insert("xss_score".into(),           0);
        vars.insert("lfi_score".into(),           0);
        vars.insert("rce_score".into(),           0);
        vars.insert("http_violation_score".into(), 0);
        vars.insert("php_injection_score".into(),  0);
        vars.insert("rbl_score".into(),            0);
        vars.insert("session_score".into(),        0);

        // Argument limits (mirrors crs-setup.conf.example defaults, rules 920360/920370/920380)
        vars.insert("arg_name_length".into(),   100);
        vars.insert("arg_length".into(),        400);
        vars.insert("total_arg_length".into(), 64000);
        vars.insert("max_num_args".into(),      255);

        // Suppresses rule 901001 ("CRS deployed without configuration")
        vars.insert("crs_setup_version".into(), 400);

        // Enable UTF-8 encoding validation (rule 920250); mirrors crs-setup.conf rule 900950
        vars.insert("crs_validate_utf8_encoding".into(), 1);

        let mut str_vars = HashMap::with_capacity(8);
        // Default allowed HTTP methods (mirrors crs-setup.conf default)
        str_vars.insert("allowed_methods".into(), "GET HEAD POST OPTIONS".into());
        str_vars.insert("allowed_request_content_type".into(),
            "application/x-www-form-urlencoded|multipart/form-data|multipart/related|text/xml|application/xml|application/soap+xml|application/json|application/cloudevents+json|application/cloudevents-batch+json".into());

        Self { vars, str_vars }
    }

    /// Get the value of a TX variable (case-insensitive; returns 0 if absent).
    pub fn get(&self, var: &str) -> i64 {
        *self.vars.get(&var.to_lowercase()).unwrap_or(&0)
    }

    /// Get a string TX variable (case-insensitive; returns "" if absent).
    pub fn get_str(&self, var: &str) -> &str {
        self.str_vars.get(&var.to_lowercase()).map(|s| s.as_str()).unwrap_or("")
    }

    /// Apply a `setvar` operation.
    pub fn apply(&mut self, op: &SetVarOp) {
        let rhs = match &op.rhs {
            SetVarRhs::Int(n)    => *n,
            SetVarRhs::TxRef(r) => self.get(r),
        };
        let entry = self.vars.entry(op.var.to_lowercase()).or_insert(0);
        match op.op {
            VarOp::Assign => *entry = rhs,
            VarOp::IncrBy => *entry += rhs,
            VarOp::DecrBy => *entry -= rhs,
        }
    }

    /// Sum of inbound anomaly scores across all four PL tiers.
    pub fn inbound_score(&self) -> i64 {
        self.get("inbound_anomaly_score_pl1")
            + self.get("inbound_anomaly_score_pl2")
            + self.get("inbound_anomaly_score_pl3")
            + self.get("inbound_anomaly_score_pl4")
    }
}

impl Default for TxState {
    fn default() -> Self { Self::new() }
}
