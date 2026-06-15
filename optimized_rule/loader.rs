//! Rule file loader — reads YAML files from the `rules/` directory,
//! validates them, deduplicates IDs, sorts by priority, and compiles
//! regexes into the [`RuleSet`].

use super::{
    types::{Rule, RuleFile, RuleRaw, RuleSet, ConditionNode, ConditionLeaf, MatchType},
    RuleError,
};
use std::{
    collections::{HashMap, HashSet},
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
    /// Pre-compiles all regexes and populates a shared cache for deduplication.
    pub fn compile(mut raw: Vec<RuleRaw>) -> Result<Arc<RuleSet>, RuleError> {
        use std::collections::HashMap;
        
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut rules: Vec<Rule> = Vec::with_capacity(raw.len());
        let mut regex_cache: HashMap<String, String> = HashMap::new();  // pattern_str -> cache_key
        let mut compiled_regexes: HashMap<String, regex::Regex> = HashMap::new();

        // First pass: collect all regex patterns and validate
        for r in &raw {
            collect_regex_patterns(&r.id, &r.condition, &mut regex_cache, &mut compiled_regexes)?;
        }

        // Validate other rule properties
        for r in &raw {
            // Duplicate ID check
            if seen_ids.contains(&r.id) {
                return Err(RuleError::DuplicateId(r.id.clone()));
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
        }

        // Second pass: populate compiled_regex_key in condition trees
        for r in &mut raw {
            populate_regex_keys(&r.id, &mut r.condition, &regex_cache)?;
        }

        // Build final rules with populated regex keys
        for r in raw {
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

        Ok(Arc::new(RuleSet {
            rules,
            compiled_regexes: Arc::new(compiled_regexes),
        }))
    }

    /// Load all rules from Consul KV prefix 'waf/rules/'.
    pub async fn load_from_consul(
        client: &reqwest::Client,
        consul_addr: &str,
    ) -> Result<Arc<RuleSet>, RuleError> {
        let url = format!("{}/v1/kv/waf/rules/?recurse&raw", consul_addr);
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| RuleError::IoError {
                file: "consul:waf/rules/".to_string(),
                source: std::io::Error::other(e),
            })?;

        if !resp.status().is_success() {
            return Err(RuleError::IoError {
                file: "consul:waf/rules/".to_string(),
                source: std::io::Error::other(
                    format!("HTTP {}", resp.status()),
                ),
            });
        }

        // Consul recurse?raw returns a list of values if multiple keys exist, but we need the individual keys.
        // Wait, recurse&raw only works if it's a single key? No, it returns a JSON array of KV objects if not using ?raw.
        // Let's use the standard KV API (no ?raw) to get all keys and their values.
        let url_full = format!("{}/v1/kv/waf/rules/?recurse", consul_addr);
        let resp = client
            .get(&url_full)
            .send()
            .await
            .map_err(|e| RuleError::IoError {
                file: "consul:waf/rules/".to_string(),
                source: std::io::Error::other(e),
            })?;

        #[derive(serde::Deserialize)]
        struct ConsulKV {
            #[serde(rename = "Key")]
            key: String,
            #[serde(rename = "Value")]
            value: Option<String>,
        }

        let kvs: Vec<ConsulKV> = resp.json().await.map_err(|e| RuleError::IoError {
            file: "consul:waf/rules/".to_string(),
            source: std::io::Error::other(e),
        })?;

        let mut raw_rules: Vec<RuleRaw> = Vec::new();
        for kv in kvs {
            if !kv.key.ends_with(".yaml") {
                continue;
            }
            if let Some(encoded_val) = kv.value {
                use base64::{engine::general_purpose, Engine as _};
                let decoded = general_purpose::STANDARD.decode(encoded_val).map_err(|e| {
                    RuleError::IoError {
                        file: kv.key.clone(),
                        source: std::io::Error::other(e),
                    }
                })?;
                let content = String::from_utf8(decoded).map_err(|e| RuleError::IoError {
                    file: kv.key.clone(),
                    source: std::io::Error::other(e),
                })?;

                // Support both a list of rules directly or a { rules: [] } object
                if let Ok(file) = serde_yaml::from_str::<RuleFile>(&content) {
                    raw_rules.extend(file.rules);
                } else if let Ok(rules) = serde_yaml::from_str::<Vec<RuleRaw>>(&content) {
                    raw_rules.extend(rules);
                }
            }
        }

        Self::compile(raw_rules)
    }

    /// Read local YAML rules files, merge with existing Consul rules under waf/rules/rules.yaml,
    /// and save them back. Clean up deprecated split keys.
    pub async fn seed_rules_to_consul(
        client: &reqwest::Client,
        consul_addr: &str,
        rules_dir: &str,
    ) -> Result<(), RuleError> {
        let dir_path = Path::new(rules_dir);
        if !dir_path.exists() {
            warn!(path = %rules_dir, "Rules directory not found, skipping rule seeding.");
            return Ok(());
        }

        // 1. Fetch existing rules from Consul
        let get_url = format!("{}/v1/kv/waf/rules/rules.yaml", consul_addr);
        let mut existing_rules: Vec<serde_json::Value> = Vec::new();
        if let Ok(r) = client.get(&get_url).send().await {
            if r.status().is_success() {
                #[derive(serde::Deserialize)]
                struct ConsulKV {
                    #[serde(rename = "Value")]
                    value: Option<String>,
                }
                if let Ok(kvs) = r.json::<Vec<ConsulKV>>().await {
                    if let Some(kv) = kvs.first() {
                        if let Some(encoded_val) = &kv.value {
                            use base64::{engine::general_purpose, Engine as _};
                            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded_val) {
                                if let Ok(content) = String::from_utf8(decoded) {
                                    if let Ok(rules) = serde_yaml::from_str::<Vec<serde_json::Value>>(&content) {
                                        existing_rules = rules;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Read and merge default rules
        let file_names = ["global.yaml", "critical.yaml", "high.yaml", "medium.yaml", "catch-all.yaml"];
        let mut changed = false;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        for name in &file_names {
            let file_path = dir_path.join(name);
            if !file_path.exists() {
                continue;
            }
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let parsed: serde_json::Value = match serde_yaml::from_str(&content) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let rules = if let Some(arr) = parsed.get("rules").and_then(|v| v.as_array()) {
                arr.clone()
            } else if let Some(arr) = parsed.as_array() {
                arr.clone()
            } else {
                continue;
            };

            let tier_name = name.split('.').next().unwrap_or("").to_uppercase().replace('-', "_");

            for dr in rules {
                let id = match dr.get("id").and_then(|v| v.as_str()) {
                    Some(id) => id,
                    None => continue,
                };

                let mut rule_data = dr.clone();
                if let Some(obj) = rule_data.as_object_mut() {
                    if !obj.contains_key("enabled") {
                        obj.insert("enabled".to_string(), serde_json::Value::Bool(true));
                    }
                    obj.insert("is_default".to_string(), serde_json::Value::Bool(true));
                    obj.insert("tier".to_string(), serde_json::Value::String(tier_name.clone()));
                    obj.insert("source".to_string(), serde_json::Value::String("system".to_string()));
                    obj.insert("updated_ms".to_string(), serde_json::Value::Number(serde_json::Number::from(now_ms)));
                }

                let existing_idx = existing_rules
                    .iter()
                    .position(|r| r.get("id").and_then(|v| v.as_str()) == Some(id));

                match existing_idx {
                    None => {
                        let mut new_rule = rule_data.clone();
                        if let Some(obj) = new_rule.as_object_mut() {
                            obj.insert("created_ms".to_string(), serde_json::Value::Number(serde_json::Number::from(now_ms)));
                            obj.insert("created_by".to_string(), serde_json::Value::String("system".to_string()));
                        }
                        existing_rules.push(new_rule);
                        changed = true;
                    }
                    Some(idx) => {
                        let existing_rule = &mut existing_rules[idx];
                        if existing_rule.get("is_default").and_then(|v| v.as_bool()) == Some(true) {
                            let old_str = serde_json::to_string(existing_rule).unwrap_or_default();
                            let mut merged = existing_rule.clone();
                            if let (Some(m_obj), Some(r_obj)) = (merged.as_object_mut(), rule_data.as_object()) {
                                for (k, v) in r_obj {
                                    m_obj.insert(k.clone(), v.clone());
                                }
                            }
                            if serde_json::to_string(&merged).unwrap_or_default() != old_str {
                                *existing_rule = merged;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        // 3. Put back to Consul if changed
        if changed {
            let body = serde_yaml::to_string(&existing_rules).map_err(|e| RuleError::IoError {
                file: "serialize rules".to_string(),
                source: std::io::Error::other(e),
            })?;
            let put_url = format!("{}/v1/kv/waf/rules/rules.yaml", consul_addr);
            client.put(&put_url).body(body).send().await.map_err(|e| RuleError::IoError {
                file: "consul:waf/rules/rules.yaml".to_string(),
                source: std::io::Error::other(e),
            })?;
            info!("Unified rules seeded to Consul");
        }

        // 4. Cleanup old split keys
        let old_files = ["all.yaml", "critical.yaml", "high.yaml", "medium.yaml", "catch-all.yaml"];
        for file in &old_files {
            let old_key = format!("waf/rules/{}", file);
            let check_url = format!("{}/v1/kv/{}", consul_addr, old_key);
            if let Ok(check_resp) = client.get(&check_url).send().await {
                if check_resp.status().is_success() {
                    let del_url = format!("{}/v1/kv/{}", consul_addr, old_key);
                    let _ = client.delete(&del_url).send().await;
                }
            }
        }

        Ok(())
    }
}

pub struct RuleWatcher {
    consul_addr: String,
    client: reqwest::Client,
}

impl RuleWatcher {
    pub fn new(consul_addr: impl Into<String>) -> Self {
        Self {
            consul_addr: consul_addr.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn spawn_watcher(
        self: Arc<Self>,
        evaluator: Arc<super::RuleEvaluator>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut last_index: u64 = 0;
            loop {
                let url = format!(
                    "{}/v1/kv/waf/rules/?recurse&index={}&wait=60s",
                    self.consul_addr, last_index
                );

                match self.client.get(&url).send().await {
                    Ok(resp) => {
                        let new_index = resp
                            .headers()
                            .get("X-Consul-Index")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(last_index);

                        if new_index == last_index {
                            continue;
                        }

                        match RuleLoader::load_from_consul(&self.client, &self.consul_addr).await {
                            Ok(new_ruleset) => {
                                evaluator.update_ruleset(new_ruleset);
                                last_index = new_index;
                                info!(
                                    index = new_index,
                                    "Hot-reload: rules updated successfully from Consul"
                                );
                            }
                            Err(e) => {
                                error!(error = ?e, "Hot-reload: failed to reload rules — keeping current");
                                last_index = new_index;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "RuleWatcher: Consul unreachable — retrying in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        })
    }
}

/// Collect all regex patterns from the condition tree and pre-compile them.
/// Deduplicates patterns so the same regex is only compiled once.
fn collect_regex_patterns(
    rule_id: &str,
    node: &ConditionNode,
    regex_cache: &mut HashMap<String, String>,  // pattern_str -> cache_key
    compiled_regexes: &mut HashMap<String, regex::Regex>,
) -> Result<(), RuleError> {
    match node {
        ConditionNode::And(children) | ConditionNode::Or(children) => {
            for child in children {
                collect_regex_patterns(rule_id, child, regex_cache, compiled_regexes)?;
            }
        }
        ConditionNode::Leaf(leaf) => {
            if leaf.match_type == MatchType::Regex {
                // Normalize the pattern (apply case-insensitive prefix if needed)
                let pattern = if !leaf.case_sensitive && !leaf.value.starts_with("(?i)") {
                    format!("(?i){}", leaf.value)
                } else {
                    leaf.value.clone()
                };
                
                // Check if already cached
                if !regex_cache.contains_key(&pattern) {
                    // Compile and validate the regex
                    let compiled = regex::Regex::new(&pattern).map_err(|e| RuleError::RegexError {
                        id: rule_id.to_string(),
                        source: e,
                    })?;
                    
                    // Generate a cache key (hash-based for deduplication)
                    let cache_key = format!("regex_{}", compiled_regexes.len());
                    regex_cache.insert(pattern.clone(), cache_key.clone());
                    compiled_regexes.insert(cache_key, compiled);
                }
            }
        }
    }
    Ok(())
}

/// Populate the compiled_regex_key in each ConditionLeaf after regexes have been pre-compiled.
fn populate_regex_keys(
    rule_id: &str,
    node: &mut ConditionNode,
    regex_cache: &HashMap<String, String>,
) -> Result<(), RuleError> {
    match node {
        ConditionNode::And(children) | ConditionNode::Or(children) => {
            for child in children {
                populate_regex_keys(rule_id, child, regex_cache)?;
            }
        }
        ConditionNode::Leaf(leaf) => {
            if leaf.match_type == MatchType::Regex {
                // Normalize the pattern same way as in collect_regex_patterns
                let pattern = if !leaf.case_sensitive && !leaf.value.starts_with("(?i)") {
                    format!("(?i){}", leaf.value)
                } else {
                    leaf.value.clone()
                };
                
                if let Some(cache_key) = regex_cache.get(&pattern) {
                    leaf.compiled_regex_key = Some(cache_key.clone());
                } else {
                    return Err(RuleError::ValidationError {
                        id: rule_id.to_string(),
                        reason: format!("Regex pattern not found in cache: {}", pattern),
                    });
                }
            }
        }
    }
    Ok(())
}
