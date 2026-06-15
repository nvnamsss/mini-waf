use std::{
    fs::OpenOptions,
    io::{self},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use waf_types::audit::AuditEntry;

/// Append-only, SIEM-ingestible JSON audit log writer.
/// Each line is a complete, newline-delimited JSON object (NDJSON).
#[derive(Clone)]
#[allow(dead_code)]
pub struct AuditLogger(Arc<Mutex<AuditLoggerInner>>);

#[allow(dead_code)]
struct AuditLoggerInner {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(AuditLogger(Arc::new(Mutex::new(AuditLoggerInner {
            path,
            file: Some(file),
        }))))
    }

    /// Serialise `entry` as a single JSON line and append it to the log file.
    pub fn write(&self, _entry: &AuditEntry) {
        todo!("lock inner, serde_json::to_string entry, write line + newline, flush")
    }
}
