//! CRS operator evaluation — decides whether a transformed value matches.

use std::net::IpAddr;
use crate::rules::crs::types::{CrsOperator, DataAutomata};
use crate::rules::crs::tx::TxState;
use crate::rules::grl::functions::{detect_sqli, detect_xss};

/// Returns `true` if `value` matches `op`.
pub fn match_operator(op: &CrsOperator, value: &str, data_automata: &DataAutomata, tx: &TxState) -> bool {
    match op {
        CrsOperator::Rx(re) => re.is_match(value),

        CrsOperator::Pm(ac) => {
            if value.is_empty() { return false; }
            ac.is_match(value)
        }

        CrsOperator::PmFromFile(filename) => {
            if value.is_empty() { return false; }
            match data_automata.get(filename) {
                Some(ac) => ac.is_match(value),
                None => false,
            }
        }

        CrsOperator::DetectSQLi => detect_sqli(value),
        CrsOperator::DetectXSS  => detect_xss(value),

        CrsOperator::Lt(n) => value.parse::<i64>().map_or(false, |v| v < *n),
        CrsOperator::Le(n) => value.parse::<i64>().map_or(false, |v| v <= *n),
        CrsOperator::Gt(n) => value.parse::<i64>().map_or(false, |v| v > *n),
        CrsOperator::Ge(n) => value.parse::<i64>().map_or(false, |v| v >= *n),
        CrsOperator::Eq(n) => value.parse::<i64>().map_or(false, |v| v == *n),

        CrsOperator::Contains(s)    => value.to_lowercase().contains(s.as_str()),
        CrsOperator::Streq(s)       => value == s.as_str(),
        CrsOperator::Within(list)   => {
            // Expand any `%{tx.VAR}` references against the transaction state.
            list.iter().any(|item| {
                if let Some(var_name) = item.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                    tx.get_str(var_name).split_whitespace().any(|allowed| allowed == value)
                } else {
                    item == value
                }
            })
        },
        CrsOperator::BeginsWith(p)  => value.starts_with(p.as_str()),
        CrsOperator::EndsWith(s)    => value.ends_with(s.as_str()),

        CrsOperator::IpMatch(nets) => {
            value.trim().parse::<IpAddr>().map_or(false, |ip| {
                nets.iter().any(|net| net.contains(&ip))
            })
        }

        // Validation operators fire when encoding is *invalid*.
        // We stub them to false (miss evasions, no false positives).
        CrsOperator::ValidateUrlEncoding => false,
        CrsOperator::ValidateUtf8Encoding => !is_valid_utf8_encoded(value),

        CrsOperator::GtTxRef(var) => value.parse::<i64>().map_or(false, |v| v > tx.get(var)),
        CrsOperator::GeTxRef(var) => value.parse::<i64>().map_or(false, |v| v >= tx.get(var)),
        CrsOperator::LtTxRef(var) => value.parse::<i64>().map_or(false, |v| v < tx.get(var)),
        CrsOperator::LeTxRef(var) => value.parse::<i64>().map_or(false, |v| v <= tx.get(var)),
        CrsOperator::EqTxRef(var) => value.parse::<i64>().map_or(false, |v| v == tx.get(var)),
    }
}

/// Returns true if the value contains no invalid UTF-8.
/// `pct_decode()` in target.rs uses `from_utf8_lossy`, which replaces invalid
/// bytes with U+FFFD (\u{FFFD}).  So we just check for the replacement char.
fn is_valid_utf8_encoded(value: &str) -> bool {
    !value.contains('\u{FFFD}')
}

