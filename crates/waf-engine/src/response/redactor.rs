/// Mask sensitive fields in a JSON response body.
///
/// Fields listed in `sensitive_fields` (e.g. `["card_number", "bank_account"]`)
/// are replaced with `"***REDACTED***"`.
pub fn redact_json(_body: &[u8], _sensitive_fields: &[&str]) -> Vec<u8> {
    todo!("parse JSON, walk object tree, replace matching field values, re-serialise")
}
