//! OWASP Core Rule Set (CRS) integration.
//!
//! Exposes two GRL built-in functions via `CrsPlugin`:
//! - `crs_score()` — returns the CRS inbound anomaly score for the request
//! - `crs_match(tag)` — returns `true` if a CRS rule tagged with `tag` fired
//!
//! # Startup wiring
//!
//! ```rust,ignore
//! let ruleset = CrsRuleset::load_from_dir(
//!     Path::new("config/rules/crs"),
//!     Path::new("config/rules/data"),
//! )?;
//! engine.install(CrsPlugin::new(Arc::new(ruleset)));
//! ```
//!
//! # GRL rule
//!
//! ```grl
//! rule "CrsBlock" salience 1000 {
//!     when  crs_score() >= 5
//!     then
//!         Request.RiskScore = Request.RiskScore + 90;
//!         block("crs");
//! }
//! ```

pub mod evaluator;
pub mod loader;
pub mod operator;
pub mod parser;
pub mod plugin;
pub mod target;
pub mod transform;
pub mod tx;
pub mod types;

pub use evaluator::CrsRuleset;
pub use plugin::CrsPlugin;
pub use types::CrsResult;
