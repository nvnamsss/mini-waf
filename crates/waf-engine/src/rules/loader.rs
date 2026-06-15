use std::path::Path;

use crate::rules::grl::converter::yaml_to_grl;
use crate::rules::grl::ast::RuleAst;
use crate::rules::grl::parser::parse as parse_grl;
use crate::rules::rule::Rule;

/// Parse all YAML rule files found in `dir` and return a flat list sorted by
/// priority (ascending — lower priority number = earlier evaluation).
pub fn load_from_dir(dir: &Path) -> anyhow::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("cannot read rules dir {:?}: {}", dir, e))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            match load_from_file(&path) {
                Ok(r) => rules.extend(r),
                Err(e) => tracing::warn!("skipping {:?}: {}", path, e),
            }
        }
    }
    rules.sort_by_key(|r| r.priority);
    Ok(rules)
}

/// Parse a single YAML rule file.
pub fn load_from_file(path: &Path) -> anyhow::Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {:?}: {}", path, e))?;
    let rules: Vec<Rule> = serde_yaml::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid rules in {:?}: {}", path, e))?;
    Ok(rules)
}

/// Load all `.yaml` (auto-converted) and `.grl` files from `dir` into a single
/// list of GRL rule ASTs ready for RETE compilation. Bad files are warned
/// about but do not abort startup.
pub fn load_grl_from_dir(dir: &Path) -> anyhow::Result<Vec<RuleAst>> {
    let mut rules = Vec::new();
    if !dir.exists() {
        return Ok(rules);
    }
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("cannot read rules dir {:?}: {}", dir, e))?
    {
        let path = entry?.path();
        if !path.is_file() { continue; }
        let ext  = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let txt  = match std::fs::read_to_string(&path) {
            Ok(t)  => t,
            Err(e) => { tracing::warn!("skip {:?}: {}", path, e); continue; }
        };
        let grl_src = match ext {
            "grl"  => txt,
            "yaml" | "yml" => {
                let doc: serde_yaml::Value = match serde_yaml::from_str(&txt) {
                    Ok(d)  => d,
                    Err(e) => { tracing::warn!("skip {:?}: yaml parse {}", path, e); continue; }
                };
                match yaml_to_grl(&doc) {
                    Ok(s)  => s,
                    Err(e) => { tracing::warn!("skip {:?}: yaml→grl {}", path, e); continue; }
                }
            }
            _ => continue,
        };
        match parse_grl(&grl_src) {
            Ok(mut r) => {
                tracing::info!("loaded {} rules from {:?}", r.len(), path);
                rules.append(&mut r);
            }
            Err(e) => tracing::warn!("skip {:?}: grl parse {}", path, e),
        }
    }
    Ok(rules)
}
