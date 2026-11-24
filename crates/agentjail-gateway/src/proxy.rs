//! The CONNECT half: one allowlist, every decision logged.
//!
//! The proxy never allows what the DNS half would NXDOMAIN, because both read
//! the same class config. A destination is either `host:port` on the class
//! allowlist (exact host, or `*.suffix`) or it is refused. A raw IP is refused
//! even when listed: an allowlist of names cannot be satisfied by an address.
//!
//! Denials are written to the audit stream as they happen. An allowed
//! connection is written once, when it closes, with the byte counts both ways.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use agentjail_core::class::ClassConfig;

use crate::audit::Logs;

const HEAD_LIMIT: usize = 8 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn serve(config: &ClassConfig, logs: &Logs) -> Result<(), String> {
    let listener = TcpListener::bind(&config.listen)
        .map_err(|error| format!("cannot bind CONNECT listener {}: {error}", config.listen))?;
    if let Ok(local) = listener.local_addr() {
        eprintln!("agentjail-gateway: connect listening on {local}");
    }
    // shortcut: one thread per connection, no cap; add a connection limit when a
    // jail is expected to open many at once rather than one agent session.
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("agentjail-gateway: accept failed: {error}");
                continue;
            }
        };
        let config = config.clone();
        let logs = logs.clone();
        std::thread::spawn(move || handle(stream, &config, &logs));
    }
    Ok(())
}

fn handle(mut stream: TcpStream, config: &ClassConfig, logs: &Logs) {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let _ = stream.set_read_timeout(Some(HEAD_TIMEOUT));

    let head = match read_head(&mut stream) {
        Ok(head) => head,
        Err(_) => {
            deny(logs, &peer, "-", "malformed");
            let _ = respond(&mut stream, 400, "Bad Request");
            return;
        }
    };

    let request = match Request::parse(&head) {
        Ok(request) => request,
        Err((status, reason, text)) => {
            deny(logs, &peer, "-", reason);
            let _ = respond(&mut stream, status, text);
            return;
        }
    };
    let dest = format!("{}:{}", request.host, request.port);

    if agentjail_core::class::is_ip_literal(&request.host) {
        deny(logs, &peer, &dest, "ip-literal");
        let _ = respond(&mut stream, 403, "Forbidden");
        return;
    }
    if !config.allows(&request.host, request.port) {
        deny(logs, &peer, &dest, "not-in-class");
        let _ = respond(&mut stream, 403, "Forbidden");
        return;
    }

    let target = match connect(&request.host, request.port) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("agentjail-gateway: {} failed: {error}", dest);
            deny(logs, &peer, &dest, "resolve-or-connect-failed");
            let _ = respond(&mut stream, 502, "Bad Gateway");
            return;
        }
    };

    if respond(&mut stream, 200, "Connection established").is_err() {
        return;
    }
    let _ = stream.set_read_timeout(None);
    let (up, down) = relay(stream, target);
    logs.audit(&[
        ("peer", peer),
        ("dest", dest),
        ("decision", "allow".to_string()),
        ("reason", "-".to_string()),
        ("bytes", format!("{up}/{down}")),
    ]);
}

fn deny(logs: &Logs, peer: &str, dest: &str, reason: &str) {
    logs.audit(&[
        ("peer", peer.to_string()),
        ("dest", dest.to_string()),
        ("decision", "deny".to_string()),
        ("reason", reason.to_string()),
        ("bytes", "0/0".to_string()),
    ]);
}

struct Request {
    host: String,
    port: u16,
}

impl Request {
    /// `CONNECT host:port HTTP/1.1` and nothing else. The remaining headers are
    /// read (they carry `Proxy-Authorization`) and ignored.
    fn parse(head: &str) -> Result<Request, (u16, &'static str, &'static str)> {
        let request_line = head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        if !method.eq_ignore_ascii_case("CONNECT") {
            return Err((405, "not-connect", "Method Not Allowed"));
        }
        let (host, port) = match target.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) if port > 0 => (host.trim_matches(['[', ']']), port),
                _ => return Err((400, "bad-port", "Bad Request")),
            },
            None => return Err((400, "no-port", "Bad Request")),
        };
        if host.is_empty() {
            return Err((400, "no-host", "Bad Request"));
        }
        Ok(Request {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Read up to the blank line that ends the request head.
fn read_head(stream: &mut TcpStream) -> Result<String, &'static str> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(0) => return Err("client-closed"),
            Ok(read) => read,
            Err(_) => return Err("read-timeout"),
        };
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if head.len() > HEAD_LIMIT {
            return Err("head-too-large");
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn respond(stream: &mut TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let body =
        format!("HTTP/1.1 {status} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve {host}: {error}"))?;
    let mut last = format!("{host} has no address");
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = format!("{address}: {error}"),
        }
    }
    Err(last)
}

/// Copy in both directions until each side is done. Returns (up, down) bytes.
fn relay(stream: TcpStream, target: TcpStream) -> (u64, u64) {
    let (mut client_read, mut client_write, mut target_read, mut target_write) = match (
        stream.try_clone(),
        stream.try_clone(),
        target.try_clone(),
        target.try_clone(),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        _ => return (0, 0),
    };
    let downstream = std::thread::spawn(move || {
        let bytes = std::io::copy(&mut target_read, &mut client_write).unwrap_or(0);
        let _ = client_write.shutdown(Shutdown::Write);
        bytes
    });
    let up = std::io::copy(&mut client_read, &mut target_write).unwrap_or(0);
    let _ = target_write.shutdown(Shutdown::Write);
    let down = downstream.join().unwrap_or(0);
    (up, down)
}
