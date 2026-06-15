//! `CrsRuleset` loader — reads `.conf` and `.data` files from disk.

use std::path::Path;
use crate::rules::crs::evaluator::CrsRuleset;
use crate::rules::crs::parser::parse_conf;
use crate::rules::crs::types::CrsRuntime;
use zentinel_modsec::ModSecurity;

impl CrsRuleset {
    /// Build a `CrsRuleset` from a directory of CRS `.conf` files and a
    /// companion directory of `.data` phrase files.
    ///
    /// - `conf_dir`  — directory containing `REQUEST-*.conf` files (alphabetical order)
    /// - `data_dir`  — directory containing `*.data` phrase files referenced by
    ///                 `@pmFromFile` operators
    pub fn load_from_dir(conf_dir: &Path, data_dir: &Path) -> anyhow::Result<Self> {
        if !data_dir.exists() {
            tracing::warn!("crs: data directory {:?} not found; pmFromFile rules will not match", data_dir);
        }

        let mut source = String::new();
        let mut rule_count = 0usize;
        let mut rule_tags = std::collections::HashMap::new();

        if conf_dir.exists() {
            let mut entries: Vec<_> = std::fs::read_dir(conf_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |x| x == "conf"))
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let path = entry.path();
                let raw_src = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("crs: reading {:?}: {}", path, e))?;
                let src = rewrite_pm_from_file_paths(&raw_src, data_dir);
                let items = parse_conf(&src);
                tracing::debug!(
                    "crs: {} items from {:?}",
                    items.len(),
                    path.file_name().unwrap_or_default()
                );
                collect_rule_tags(&items, &mut rule_tags);
                rule_count += items.len();
                source.push_str(&src);
                if !source.ends_with('\n') {
                    source.push('\n');
                }
            }
        } else {
            tracing::warn!("crs: conf directory {:?} not found; CRS rules disabled", conf_dir);
        }

        tracing::info!("crs: {} rule items loaded from {:?}", rule_count, conf_dir);

        let modsec = ModSecurity::from_string(&source)
            .map_err(|e| anyhow::anyhow!("crs: compile failed: {}", e))?;

        Ok(CrsRuleset {
            runtime: CrsRuntime {
                modsec,
                rule_tags,
                source_dir: conf_dir.to_path_buf(),
            },
            rule_count,
        })
    }
}

fn rewrite_pm_from_file_paths(source: &str, data_dir: &Path) -> String {
    let data_dir = data_dir.to_string_lossy();
    let regex = regex::Regex::new(r"@pmFromFile\s+([A-Za-z0-9._/-]+\.data)").unwrap();
    regex
        .replace_all(source, |caps: &regex::Captures| {
            let file_name = &caps[1];
            let full_path = Path::new(data_dir.as_ref()).join(file_name);
            format!("@pmFromFile {}", full_path.to_string_lossy())
        })
        .into_owned()
}

fn collect_rule_tags(
    items: &[crate::rules::crs::types::RuleItem],
    rule_tags: &mut std::collections::HashMap<u32, Vec<String>>,
) {
    for item in items {
        match item {
            crate::rules::crs::types::RuleItem::Rule(rule) => {
                if !rule.actions.tags.is_empty() {
                    rule_tags.insert(rule.id, rule.actions.tags.clone());
                }
            }
            crate::rules::crs::types::RuleItem::Chain(chain) => {
                let mut tags = chain.head.actions.tags.clone();
                for member in &chain.members {
                    tags.extend(member.actions.tags.clone());
                }
                if !tags.is_empty() {
                    rule_tags.insert(chain.head.id, tags);
                }
            }
            crate::rules::crs::types::RuleItem::Marker(_) => {}
        }
    }
}
