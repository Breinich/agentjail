//! The DNS half: a resolver with one answer.
//!
//! Allowlisted names answer `127.0.0.1`; everything else is NXDOMAIN. The
//! answer is not the real address on purpose: if the agent resolves a name and
//! dials it without the proxy, it dials its own loopback and fails, rather than
//! reaching the destination and bypassing the allowlist. The proxy is the only
//! half that resolves for real.
//!
//! Every query is logged, answered or not. This is a deliberately small
//! resolver: one question per packet, `A` only, no recursion, no cache, no
//! upstream. That is the whole DNS policy, so nothing here can disagree with the
//! CONNECT allowlist -- both halves read the same committed class config.

use std::net::UdpSocket;

use agentjail_core::class::{ClassConfig, DnsPolicy};

use crate::audit::Logs;

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NOERROR: u16 = 0;
const RCODE_NXDOMAIN: u16 = 3;

pub fn serve(config: &ClassConfig, logs: &Logs) -> Result<(), String> {
    let socket = UdpSocket::bind(&config.dns)
        .map_err(|error| format!("cannot bind DNS listener {}: {error}", config.dns))?;
    if let Ok(local) = socket.local_addr() {
        eprintln!("agentjail-gateway: dns listening on {local}");
    }
    loop {
        let mut buffer = [0u8; 512];
        let (len, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) => {
                eprintln!("agentjail-gateway: dns receive failed: {error}");
                continue;
            }
        };
        let packet = &buffer[..len];
        let Some(query) = Query::parse(packet) else {
            logs.dns(&[
                ("peer", peer.to_string()),
                ("qname", "-".to_string()),
                ("qtype", "-".to_string()),
                ("decision", "drop".to_string()),
                ("reason", "malformed".to_string()),
            ]);
            continue;
        };

        let (rcode, answer, decision, reason) = decide(config, &query);
        logs.dns(&[
            ("peer", peer.to_string()),
            ("qname", query.name.clone()),
            ("qtype", query.qtype.to_string()),
            ("decision", decision.to_string()),
            ("reason", reason.to_string()),
        ]);
        let response = build_response(packet, &query, rcode, answer);
        if let Err(error) = socket.send_to(&response, peer) {
            eprintln!("agentjail-gateway: dns reply to {peer} failed: {error}");
        }
    }
}

fn decide(config: &ClassConfig, query: &Query) -> (u16, bool, &'static str, &'static str) {
    if query.class != CLASS_IN {
        return (RCODE_NOERROR, false, "refused", "not-internet-class");
    }
    if config.dns_policy == DnsPolicy::Off {
        return (RCODE_NXDOMAIN, false, "nxdomain", "policy-off");
    }
    if query.qtype != TYPE_A {
        // AAAA has no answer rather than NXDOMAIN: the name exists, this
        // resolver has no address of that family.
        let decision = if query.qtype == TYPE_AAAA {
            "refused"
        } else {
            "nxdomain"
        };
        return (RCODE_NOERROR, false, decision, "qtype-not-answerable");
    }
    if query.name.parse::<std::net::IpAddr>().is_ok() {
        return (RCODE_NXDOMAIN, false, "nxdomain", "ip-literal");
    }
    if config.permits_name(&query.name) {
        return (RCODE_NOERROR, true, "answer", "in-class");
    }
    // The name exists for the class but this jail was not granted it: NXDOMAIN
    // for the same reason a CONNECT would be refused, so a name the profile did
    // not ask for does not even resolve.
    if config.class_permits_name(&query.name) {
        return (RCODE_NXDOMAIN, false, "nxdomain", "not-in-profile");
    }
    (RCODE_NXDOMAIN, false, "nxdomain", "not-in-class")
}

/// Echo the question and append one `A 127.0.0.1` answer, or none.
fn build_response(packet: &[u8], query: &Query, rcode: u16, answer: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 16);
    let id = &packet[0..2];
    let flags: u16 = 0x8180 | (rcode & 0x000f); // QR, RD, RA
    out.extend_from_slice(id);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(u16::from(answer)).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&packet[HEADER_LEN..query.question_end]);
    if answer {
        out.extend_from_slice(&[0xc0, 0x0c]); // the question name, back where it was
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[127, 0, 0, 1]);
    }
    out
}

struct Query {
    name: String,
    qtype: u16,
    class: u16,
    question_end: usize,
}

impl Query {
    fn parse(packet: &[u8]) -> Option<Query> {
        if packet.len() < HEADER_LEN + 5 {
            return None;
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if flags & 0x8000 != 0 {
            return None; // a response, not a query
        }
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
            return None; // exactly one question, or nothing
        }
        let mut name = String::new();
        let mut offset = HEADER_LEN;
        loop {
            let label_len = *packet.get(offset)? as usize;
            offset += 1;
            if label_len == 0 {
                break;
            }
            if label_len > 63 {
                return None; // compression pointer inside a question, or garbage
            }
            let label = packet.get(offset..offset + label_len)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
            offset += label_len;
            if name.len() > 253 {
                return None;
            }
        }
        let qtype = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
        let class = u16::from_be_bytes([*packet.get(offset + 2)?, *packet.get(offset + 3)?]);
        Some(Query {
            name,
            qtype,
            class,
            question_end: offset + 4,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> ClassConfig {
        ClassConfig::parse(text).expect("valid class config")
    }

    const MODEL: &str = r#"
class = "model"
listen = "127.0.0.1:0"
dns = "127.0.0.1:0"
max_bytes = 1048576
max_connections = 4
allow = ["api.example.com:443"]
"#;

    fn query_packet(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet
    }

    #[test]
    fn an_allowlisted_name_answers_loopback_and_nothing_else_answers() {
        let config = config(MODEL);
        let packet = query_packet(0x1234, "api.example.com", TYPE_A);
        let query = Query::parse(&packet).expect("parse");
        assert_eq!(query.name, "api.example.com");

        let (rcode, answer, decision, _) = decide(&config, &query);
        assert_eq!((rcode, answer, decision), (RCODE_NOERROR, true, "answer"));
        let response = build_response(&packet, &query, rcode, answer);
        assert_eq!(&response[0..2], &[0x12, 0x34], "id is echoed");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1, "ANCOUNT");
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);

        let packet = query_packet(1, "evil.example.com", TYPE_A);
        let query = Query::parse(&packet).expect("parse");
        let (rcode, answer, decision, reason) = decide(&config, &query);
        assert_eq!(
            (rcode, answer, decision),
            (RCODE_NXDOMAIN, false, "nxdomain")
        );
        assert_eq!(reason, "not-in-class");
        let response = build_response(&packet, &query, rcode, answer);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0, "ANCOUNT");
        assert_eq!(response[3] & 0x0f, 3, "RCODE NXDOMAIN");
    }

    #[test]
    fn names_are_case_folded_and_a_raw_ip_question_is_never_answered() {
        let config = config(MODEL);
        let query = Query::parse(&query_packet(1, "API.Example.COM", TYPE_A)).expect("parse");
        assert_eq!(query.name, "api.example.com");
        assert!(config.permits_name(&query.name));

        let query = Query::parse(&query_packet(1, "127.0.0.1", TYPE_A)).expect("parse");
        assert_eq!(decide(&config, &query).0, RCODE_NXDOMAIN);
    }

    #[test]
    fn policy_off_nxdomains_everything() {
        let config = config(&format!("{MODEL}dns_policy = \"off\"\n"));
        let query = Query::parse(&query_packet(1, "api.example.com", TYPE_A)).expect("parse");
        assert_eq!(
            decide(&config, &query),
            (RCODE_NXDOMAIN, false, "nxdomain", "policy-off")
        );
    }

    #[test]
    fn compression_pointers_in_a_question_are_dropped() {
        let mut packet = query_packet(1, "api.example.com", TYPE_A);
        packet[HEADER_LEN] = 0xc0;
        assert!(Query::parse(&packet).is_none());
    }
}
