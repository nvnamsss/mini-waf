//! Rule file loader — reads YAML files from the `rules/` directory,
//! validates them, deduplicates IDs, sorts by priority, and compiles
//! regexes into the [`RuleSet`].

use super::{
    types::{Rule, RuleFile, RuleRaw, RuleSet},
    RuleError,
};
use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::Arc,
};
use tracing::{error, info, warn};

pub struct RuleLoader;

impl RuleLoader {
    /// Build the full rule set from embedded defaults.
    /// Call this once on startup; rules are immutable until next hot-reload.
    pub fn load_from_path<P: AsRef<Path>>(base_path: P) -> Result<Arc<RuleSet>, RuleError> {
        let mut raw: Vec<RuleRaw> = Vec::new();
        let base = base_path.as_ref();

        // The specific files you want to load in order
        let file_names = [
            "global.yaml",
            "critical.yaml",
            "high.yaml",
            "medium.yaml",
            "catch-all.yaml",
        ];

        for name in &file_names {
            // Construct the full path to the file
            let file_path = base.join(name);

            // Read the file contents at runtime
            let content = fs::read_to_string(&file_path).map_err(|e| RuleError::IoError {
                file: file_path.to_string_lossy().into_owned(),
                source: e,
            })?;

            // Parse the YAML string
            let file_parsed: RuleFile =
                serde_yaml::from_str(&content).map_err(|e| RuleError::ParseError {
                    file: name.to_string(),
                    source: e,
                })?;

            let mut rules = file_parsed.rules;
            for r in &mut rules {
                r.source = Some("system".to_string());
            }
            raw.extend(rules);
        }

        Self::compile(raw)
    }

    /// Load from a directory (for custom rules in `rules/custom/`).
    /// Merges with existing compiled rule set.
    pub async fn load_from_dir(dir: &Path) -> Result<Vec<RuleRaw>, RuleError> {
        let mut raw: Vec<RuleRaw> = Vec::new();

        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| RuleError::IoError {
                file: dir.display().to_string(),
                source: e,
            })?;

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }

            let content =
                tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| RuleError::IoError {
                        file: path.display().to_string(),
                        source: e,
                    })?;

            let file: RuleFile =
                serde_yaml::from_str(&content).map_err(|e| RuleError::ParseError {
                    file: path.display().to_string(),
                    source: e,
                })?;

            info!(file = %path.display(), count = file.rules.len(), "Loaded custom rule file");
            raw.extend(file.rules);
        }

        Ok(raw)
    }

    /// Validate, deduplicate, sort, and compile a list of raw rules into a [`RuleSet`].
    pub fn compile(raw: Vec<RuleRaw>) -> Result<Arc<RuleSet>, RuleError> {
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut rules: Vec<Rule> = Vec::with_capacity(raw.len());

        for r in raw {
            // Duplicate ID check
            if seen_ids.contains(&r.id) {
                return Err(RuleError::DuplicateId(r.id));
            }
            seen_ids.insert(r.id.clone());

            // risk_score_delta range [-100, 100]
            if r.risk_score_delta < -100 || r.risk_score_delta > 100 {
                return Err(RuleError::ValidationError {
                    id: r.id.clone(),
                    reason: format!(
                        "risk_score_delta {} out of range [-100, 100]",
                        r.risk_score_delta
                    ),
                });
            }

            // Priority must be positive
            if r.priority == 0 {
                return Err(RuleError::ValidationError {
                    id: r.id.clone(),
                    reason: "priority must be >= 1".to_string(),
                });
            }

            // Pre-compile regexes in condition tree (validates patterns eagerly)
            validate_condition_regexes(&r.id, &r.condition)?;

            rules.push(Rule {
                id: r.id,
                source: r.source.unwrap_or_else(|| "system".to_string()),
                description: r.description,
                enabled: r.enabled,
                priority: r.priority,
                condition: r.condition,
                action: r.action,
                risk_score_delta: r.risk_score_delta,
                response: r.response,
                rate_limit: r.rate_limit,
                challenge: r.challenge,
                tier: r.tier,
            });
        }

        // Sort by priority ascending (lower = higher precedence)
        rules.sort_unstable_by_key(|r| r.priority);

        Ok(Arc::new(RuleSet { rules }))
    }

    /// Load all rules from Consul KV prefix 'waf/rules/'.
    pub async fn load_from_consul() -> Result<Arc<RuleSet>, RuleError> {
        Err(RuleError::IoError {
            file: "consul:waf/rules/".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::Other, "Consul support not available"),
        })
    }

    /// Read local YAML rules files, merge with existing Consul rules under waf/rules/rules.yaml,
    /// and save them back. Clean up deprecated split keys.
    pub async fn seed_rules_to_consul(_rules_dir: &str) -> Result<(), RuleError> {
        Err(RuleError::IoError {
            file: "consul:waf/rules/".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::Other, "Consul support not available"),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::ConditionNode;

fn validate_condition_regexes(rule_id: &str, node: &ConditionNode) -> Result<(), RuleError> {
    match node {
        ConditionNode::And(children) | ConditionNode::Or(children) => {
            for child in children {
                validate_condition_regexes(rule_id, child)?;
            }
            Ok(())
        }
        ConditionNode::Leaf(leaf) => {
            use crate::types::MatchType;
            if leaf.match_type == MatchType::Regex {
                regex::Regex::new(&leaf.value).map_err(|e| RuleError::RegexError {
                    id: rule_id.to_string(),
                    source: e,
                })?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConditionNode, ConditionLeaf, Field, MatchType};

    #[test]
    fn test_compile_basic_rule() {
        let raw = vec![RuleRaw {
            id: "test-rule".to_string(),
            description: "Test".to_string(),
            enabled: true,
            priority: 10,
            condition: ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path,
                match_type: MatchType::Exact,
                value: "/login".to_string(),
                header_name: None,
                cookie_name: None,
                case_sensitive: false,
                negate: false,
            }),
            action: crate::types::Action::Block,
            risk_score_delta: 5,
            response: None,
            rate_limit: None,
            challenge: None,
            tier: None,
            source: None,
        }];

        let compiled = RuleLoader::compile(raw).expect("compile failed");
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].id, "test-rule");
    }

    #[test]
    fn test_compile_rejects_duplicate_ids() {
        let raw = vec![
            RuleRaw {
                id: "rule-1".to_string(),
                description: "First".to_string(),
                enabled: true,
                priority: 10,
                condition: ConditionNode::Leaf(ConditionLeaf {
                    field: Field::Path,
                    match_type: MatchType::Exact,
                    value: "/a".to_string(),
                    header_name: None,
                    cookie_name: None,
                    case_sensitive: false,
                    negate: false,
                }),
                action: crate::types::Action::Block,
                risk_score_delta: 0,
                response: None,
                rate_limit: None,
                challenge: None,
                tier: None,
                source: None,
            },
            RuleRaw {
                id: "rule-1".to_string(),
                description: "Second (dup)".to_string(),
                enabled: true,
                priority: 20,
                condition: ConditionNode::Leaf(ConditionLeaf {
                    field: Field::Path,
                    match_type: MatchType::Exact,
                    value: "/b".to_string(),
                    header_name: None,
                    cookie_name: None,
                    case_sensitive: false,
                    negate: false,
                }),
                action: crate::types::Action::Block,
                risk_score_delta: 0,
                response: None,
                rate_limit: None,
                challenge: None,
                tier: None,
                source: None,
            },
        ];

        let err = RuleLoader::compile(raw).expect_err("should reject duplicate");
        matches!(err, RuleError::DuplicateId(id) if id == "rule-1");
    }
}
