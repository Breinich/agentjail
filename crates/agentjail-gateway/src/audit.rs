//! The two log streams.
//!
//! Audit (one line per connection, including denials) and DNS (one line per
//! query) are separate streams on purpose: a DNS flood must not push the
//! connection decisions out of the log an operator reads, and a query name is
//! not evidence that a connection happened.
//!
//! `-` puts the audit stream on stdout and the DNS stream on stderr, which
//! keeps them apart for `podman logs` and for tests that capture one pipe. Any
//! other value is a file path, appended.

use std::io::Write;
use std::sync::{Arc, Mutex};

use agentjail_core::class::ClassConfig;

#[derive(Clone)]
pub struct Logs {
    class: Arc<String>,
    jail: Arc<String>,
    audit: Arc<Mutex<Box<dyn Write + Send>>>,
    dns: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Logs {
    pub fn open(config: &ClassConfig) -> Result<Logs, String> {
        Ok(Logs {
            class: Arc::new(config.class.clone()),
            jail: Arc::new(String::new()),
            audit: Arc::new(Mutex::new(open_stream(
                &config.audit_log,
                Box::new(std::io::stdout()),
            )?)),
            dns: Arc::new(Mutex::new(open_stream(
                &config.dns_log,
                Box::new(std::io::stderr()),
            )?)),
        })
    }

    /// Bind the jail id onto the log, so every line says which run it belongs to.
    pub fn with_jail(&self, jail_id: &str) -> Logs {
        Logs {
            class: self.class.clone(),
            jail: Arc::new(jail_id.to_string()),
            audit: self.audit.clone(),
            dns: self.dns.clone(),
        }
    }

    /// One decision line: timestamp, class, jail, and the caller's fields.
    pub fn audit(&self, fields: &[(&str, String)]) {
        self.write(&self.audit, fields);
    }

    /// One DNS line, on the other stream.
    pub fn dns(&self, fields: &[(&str, String)]) {
        self.write(&self.dns, fields);
    }

    fn write(&self, sink: &Mutex<Box<dyn Write + Send>>, fields: &[(&str, String)]) {
        let mut line = format!(
            "ts={} class={} jail={}",
            now_millis(),
            clean(&self.class),
            clean(&self.jail)
        );
        for (key, value) in fields {
            line.push(' ');
            line.push_str(key);
            line.push('=');
            line.push_str(&clean(value));
        }
        line.push('\n');
        if let Ok(mut sink) = sink.lock() {
            let _ = sink.write_all(line.as_bytes());
            let _ = sink.flush();
        }
    }
}

fn open_stream(
    path: &str,
    default: Box<dyn Write + Send>,
) -> Result<Box<dyn Write + Send>, String> {
    if path == "-" {
        return Ok(default);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open log {path:?}: {error}"))?;
    Ok(Box::new(file))
}

/// Values come from the network (a hostname, a query name), so nothing in them
/// may forge a field or a line.
fn clean(value: &str) -> String {
    let mut out: String = value
        .chars()
        .take(200)
        .map(|c| {
            if c.is_ascii_graphic() && c != '=' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_cannot_forge_a_field_or_a_line() {
        assert_eq!(clean("api.example.com:443"), "api.example.com:443");
        assert_eq!(clean("evil name=allow\nnext"), "evil_name_allow_next");
        assert_eq!(clean(""), "-");
    }
}
