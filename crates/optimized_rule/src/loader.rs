//! Load and compile rules with pre-compiled regex caching

use crate::types::*;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};

pub struct RuleLoader;

impl RuleLoader {
    /// Load all YAML files from a directory, compile regexes, build cache
    pub fn load_from_path(rules_dir: &Path) -> Result<RuleSet> {
        let mut all_rules = Vec::new();

        // Load all YAML files
        for entry in std::fs::read_dir(rules_dir)
            .context("Failed to read rules directory")?
        {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "yaml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)
                    .context(format!("Failed to read {}", path.display()))?;

                let doc: serde_yaml::Value = serde_yaml::from_str(&content)
                    .context(format!("Failed to parse YAML in {}", path.display()))?;

                if let Some(rules_seq) = doc.get("rules").and_then(|v| v.as_sequence()) {
                    for rule_value in rules_seq {
                        let raw: RuleRaw = serde_yaml::from_value(rule_value.clone())
                            .context("Failed to deserialize rule")?;
                        all_rules.push((raw, path.to_string_lossy().to_string()));
                    }
                }
            }
        }

        // Validate all rules
        for (raw, _) in &all_rules {
            Self::validate_rule_structure(raw)?;
        }

        // Collect all regex patterns and compile them with deduplication
        let mut regex_cache = HashMap::new();
        let mut pattern_to_key: HashMap<String, String> = HashMap::new();

        for (raw, _) in &all_rules {
            Self::collect_regex_patterns(&raw.condition, &mut pattern_to_key, &mut regex_cache)?;
        }

        // Compile collected regexes (with deduplication)
        for (pattern, key) in &pattern_to_key {
            if !regex_cache.contains_key(key) {
                let regex = Regex::new(pattern)
                    .context(format!("Invalid regex pattern: {}", pattern))?;
                regex_cache.insert(key.clone(), regex);
            }
        }

        // Build compiled rules, populating regex keys
        let mut compiled_rules = Vec::new();
        for (raw, source) in all_rules {
            let mut condition = raw.condition.clone();
            Self::populate_regex_keys(&mut condition, &pattern_to_key);

            compiled_rules.push(Rule {
                id: raw.id,
                source,
                description: raw.description,
                enabled: raw.enabled,
                priority: raw.priority,
                condition,
                action: raw.action,
                risk_score_delta: raw.risk_score_delta,
                response: raw.response,
                rate_limit: raw.rate_limit,
                challenge: raw.challenge,
                tier: raw.tier,
            });
        }

        // Sort by priority (ascending)
        compiled_rules.sort_by_key(|r| r.priority);

        Ok(RuleSet {
            rules: compiled_rules,
            compiled_regexes: Arc::new(regex_cache),
        })
    }

    /// Validate that rule structure is correct
    fn validate_rule_structure(raw: &RuleRaw) -> Result<()> {
        if raw.id.is_empty() {
            anyhow::bail!("Rule must have an id");
        }
        if raw.priority == 0 {
            anyhow::bail!("Rule priority must be > 0");
        }
        Ok(())
    }

    /// Walk the condition tree and collect all regex patterns
    fn collect_regex_patterns(
        node: &ConditionNode,
        pattern_to_key: &mut HashMap<String, String>,
        regex_cache: &mut HashMap<String, Regex>,
    ) -> Result<()> {
        match node {
            ConditionNode::And(nodes) | ConditionNode::Or(nodes) => {
                for n in nodes {
                    Self::collect_regex_patterns(n, pattern_to_key, regex_cache)?;
                }
            }
            ConditionNode::Leaf(leaf) => {
                if leaf.match_type == MatchType::Regex {
                    // Use pattern as the key, dedup happens automatically via HashMap
                    let key = leaf.value.clone();
                    pattern_to_key.insert(leaf.value.clone(), key);
                }
            }
        }
        Ok(())
    }

    /// Walk the condition tree and populate compiled_regex_key for regex leaves
    fn populate_regex_keys(
        node: &mut ConditionNode,
        pattern_to_key: &HashMap<String, String>,
    ) {
        match node {
            ConditionNode::And(nodes) | ConditionNode::Or(nodes) => {
                for n in nodes {
                    Self::populate_regex_keys(n, pattern_to_key);
                }
            }
            ConditionNode::Leaf(leaf) => {
                if leaf.match_type == MatchType::Regex {
                    if let Some(key) = pattern_to_key.get(&leaf.value) {
                        leaf.compiled_regex_key = Some(key.clone());
                    }
                }
            }
        }
    }
}
