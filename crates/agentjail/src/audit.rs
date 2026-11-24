//! Read the two gateway streams back.
//!
//! The gateway writes one line per decision on two streams: audit (connections,
//! allows and denials) and DNS (one line per query). During an incident the
//! question is "what did jail X do", which spans both streams and both need to
//! be read in time order. Grepping two files by hand is how evidence gets
//! missed, so this is the view: merge, filter, and take the tail.
//!
//! Nothing here parses the fields the gateway sanitises differently: a line is
//! `key=value` pairs, and a filter is an exact match on one of them.

use std::collections::BTreeMap;

/// The audit stream's tag in the merged view.
pub const AUDIT: &str = "audit";
/// The DNS stream's tag in the merged view.
pub const DNS: &str = "dns";

/// Which stream(s) to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Streams {
    Both,
    Audit,
    Dns,
}

/// What to keep.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub jail: Option<String>,
    pub class: Option<String>,
    pub decision: Option<String>,
    pub streams: Option<Streams>,
    /// Keep only the last N matching lines.
    pub tail: Option<usize>,
}

/// One parsed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub stream: &'static str,
    pub ts: u128,
    pub raw: String,
    fields: BTreeMap<String, String>,
}

impl Line {
    fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// The line as the view prints it: which stream it came from, then the
    /// original line unchanged.
    pub fn render(&self) -> String {
        format!("stream={} {}", self.stream, self.raw)
    }
}

/// Parse one line. A line without a `ts` is not a line this gateway wrote, so
/// it is kept with `ts=0` rather than dropped: an operator looking for evidence
/// should see what is in the file.
pub fn parse(stream: &'static str, raw: &str) -> Line {
    let mut fields = BTreeMap::new();
    for token in raw.split(' ') {
        if let Some((key, value)) = token.split_once('=') {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    let ts = fields
        .get("ts")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    Line {
        stream,
        ts,
        raw: raw.trim_end().to_string(),
        fields,
    }
}

fn keeps(line: &Line, filter: &Filter) -> bool {
    if let Some(streams) = filter.streams {
        let wanted = match streams {
            Streams::Both => true,
            Streams::Audit => line.stream == AUDIT,
            Streams::Dns => line.stream == DNS,
        };
        if !wanted {
            return false;
        }
    }
    for (key, wanted) in [
        ("jail", &filter.jail),
        ("class", &filter.class),
        ("decision", &filter.decision),
    ] {
        if let Some(wanted) = wanted {
            if line.field(key) != Some(wanted.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Merge the streams, filter, order by timestamp, and keep the tail.
pub fn view(streams: &[(&'static str, &str)], filter: &Filter) -> Vec<Line> {
    let mut lines: Vec<Line> = Vec::new();
    for (stream, text) in streams {
        for raw in text.lines() {
            if raw.trim().is_empty() {
                continue;
            }
            let line = parse(stream, raw);
            if keeps(&line, filter) {
                lines.push(line);
            }
        }
    }
    // Stable: two lines with the same millisecond keep their stream order.
    lines.sort_by_key(|line| line.ts);
    if let Some(tail) = filter.tail {
        if lines.len() > tail {
            lines.drain(..lines.len() - tail);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT: &str = "\
ts=1 class=model jail=run-7 dest=a.example:443 decision=allow reason=- bytes=0/0
ts=3 class=model jail=run-7 dest=b.example:443 decision=deny reason=not-in-class bytes=0/0
ts=5 class=model jail=run-8 dest=c.example:443 decision=deny reason=byte-budget bytes=0/10 budget=1024
";

    const DNS: &str = "\
ts=2 class=model jail=run-7 qname=a.example qtype=1 decision=answer reason=in-class
ts=4 class=model jail=run-7 qname=b.example qtype=1 decision=nxdomain reason=not-in-class
";

    fn filter() -> Filter {
        Filter::default()
    }

    #[test]
    fn both_streams_are_merged_in_time_order() {
        let lines = view(&[(AUDIT_STREAM, AUDIT), (DNS_STREAM, DNS)], &filter());
        let decisions: Vec<&str> = lines
            .iter()
            .map(|line| line.field("decision").unwrap_or("-"))
            .collect();
        assert_eq!(decisions, ["allow", "answer", "deny", "nxdomain", "deny"]);
        assert_eq!(lines[0].stream, AUDIT_STREAM);
        assert_eq!(lines[1].stream, DNS_STREAM);
        assert!(lines[0].render().starts_with("stream=audit ts=1 "));
    }

    #[test]
    fn a_jail_filter_spans_both_streams_and_a_decision_filter_narrows_it() {
        let lines = view(
            &[(AUDIT_STREAM, AUDIT), (DNS_STREAM, DNS)],
            &Filter {
                jail: Some("run-7".to_string()),
                ..filter()
            },
        );
        assert_eq!(lines.len(), 4);

        let lines = view(
            &[(AUDIT_STREAM, AUDIT), (DNS_STREAM, DNS)],
            &Filter {
                jail: Some("run-7".to_string()),
                decision: Some("deny".to_string()),
                ..filter()
            },
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].raw.contains("dest=b.example:443"));

        let lines = view(
            &[(AUDIT_STREAM, AUDIT), (DNS_STREAM, DNS)],
            &Filter {
                class: Some("model".to_string()),
                streams: Some(Streams::Dns),
                ..filter()
            },
        );
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.stream == DNS_STREAM));
    }

    #[test]
    fn the_tail_is_the_last_matching_lines() {
        let lines = view(
            &[(AUDIT_STREAM, AUDIT), (DNS_STREAM, DNS)],
            &Filter {
                tail: Some(2),
                ..filter()
            },
        );
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].ts, 4);
        assert_eq!(lines[1].ts, 5);
    }

    #[test]
    fn a_line_without_a_timestamp_is_kept_not_dropped() {
        let lines = view(&[(AUDIT_STREAM, "not a gateway line\n")], &filter());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].ts, 0);
        assert_eq!(lines[0].render(), "stream=audit not a gateway line");
    }

    const AUDIT_STREAM: &str = super::AUDIT;
    const DNS_STREAM: &str = super::DNS;
}
