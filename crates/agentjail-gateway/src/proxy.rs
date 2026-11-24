//! The CONNECT half: one allowlist, every decision logged, and the limits that
//! make an allowlisted destination a bounded channel rather than a pipe.
//!
//! The proxy never allows what the DNS half would NXDOMAIN, because both read
//! the same class config. A destination is either `host:port` on the class
//! allowlist (exact host, or `*.suffix`) or it is refused. A raw IP is refused
//! even when listed: an allowlist of names cannot be satisfied by an address.
//!
//! Two things happen on the way out, and both are enforcement rather than
//! documentation:
//!
//! * **the name is resolved once and every answer is checked** (see
//!   [`crate::egress`]) against the class's address policy, so a rebound or
//!   poisoned answer cannot point an allowed name at internal space;
//! * **the jail has a byte budget and a connection cap** ([`Jail`]), and
//!   reaching either is a refusal logged in the same shape as a policy denial,
//!   with the counters that caused it.
//!
//! Denials are written to the audit stream as they happen, and so are allows:
//! the `decision=allow` line is written the moment the connection exists, so a
//! tunnel that is established and then reset still leaves evidence. The byte
//! counts are written when the tunnel ends, on a second `decision=allow-close`
//! line -- or on a `decision=deny reason=byte-budget` line when the budget cut
//! it.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentjail_core::class::ClassConfig;

use crate::audit::Logs;
use crate::egress;

const HEAD_LIMIT: usize = 8 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_CHUNK: usize = 16 * 1024;

pub fn serve(config: &ClassConfig, logs: &Logs) -> Result<(), String> {
    let listener = TcpListener::bind(&config.listen)
        .map_err(|error| format!("cannot bind CONNECT listener {}: {error}", config.listen))?;
    if let Ok(local) = listener.local_addr() {
        eprintln!("agentjail-gateway: connect listening on {local}");
    }
    let jail = Arc::new(Jail::new(config));
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("agentjail-gateway: accept failed: {error}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        // The cap is checked before the request head is read: a jail that floods
        // connections must not cost one thread and one read each.
        let permit = match jail.admit() {
            Ok(permit) => permit,
            Err(active) => {
                deny_with(
                    logs,
                    &peer,
                    "-",
                    "connection-cap",
                    "0/0",
                    &[
                        ("connections", format!("{active}/{}", jail.max_connections)),
                        ("limit", jail.max_connections.to_string()),
                    ],
                );
                let mut stream = stream;
                let _ = respond(&mut stream, 429, "Too Many Requests");
                continue;
            }
        };
        let config = config.clone();
        let logs = logs.clone();
        let jail = jail.clone();
        std::thread::spawn(move || {
            // A denial is evidence, and a panic is exactly the failure an
            // incident review must still be able to see. Catch it, log it in the
            // denial shape, and let the connection die.
            guard(&logs, &peer, || {
                handle(stream, &config, &logs, &jail, permit)
            });
        });
    }
    Ok(())
}

/// Run one connection, logging a denial if it panics.
///
/// A panic is the case where the proxy itself errored: exactly the failure that
/// must not be silent, because a crashed thread with no audit line looks like a
/// connection that never happened.
fn guard(logs: &Logs, peer: &str, body: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_err() {
        deny(logs, peer, "-", "internal-error");
    }
}

/// The per-jail budget and connection cap.
#[derive(Debug)]
struct Jail {
    max_bytes: u64,
    max_connections: usize,
    bytes: AtomicU64,
    connections: AtomicUsize,
}

impl Jail {
    fn new(config: &ClassConfig) -> Jail {
        Jail {
            max_bytes: config.max_bytes,
            max_connections: config.max_connections,
            bytes: AtomicU64::new(0),
            connections: AtomicUsize::new(0),
        }
    }

    /// Take one connection slot, or report how many are already in use.
    fn admit(self: &Arc<Self>) -> Result<Permit, usize> {
        let active = self.connections.fetch_add(1, Ordering::SeqCst);
        if active >= self.max_connections {
            self.connections.fetch_sub(1, Ordering::SeqCst);
            return Err(active);
        }
        Ok(Permit(self.clone()))
    }

    /// Charge `bytes` against the budget; `Err` means the budget is spent.
    fn charge(&self, bytes: u64) -> Result<(), ()> {
        if bytes == 0 {
            return Ok(());
        }
        let before = self.bytes.fetch_add(bytes, Ordering::SeqCst);
        if before + bytes > self.max_bytes {
            self.bytes.fetch_sub(bytes, Ordering::SeqCst);
            return Err(());
        }
        Ok(())
    }
}

/// One admitted connection; the slot is released when this is dropped.
#[derive(Debug)]
struct Permit(Arc<Jail>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle(mut stream: TcpStream, config: &ClassConfig, logs: &Logs, jail: &Jail, permit: Permit) {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let _ = stream.set_read_timeout(Some(HEAD_TIMEOUT));

    let (head, pending) = match read_head(&mut stream) {
        Ok(head) => head,
        Err(reason) => {
            deny(logs, &peer, "-", reason);
            let _ = respond(&mut stream, 400, "Bad Request");
            return;
        }
    };

    let request = match Request::parse(&head) {
        Ok(request) => request,
        Err((status, reason, text)) => {
            // A non-CONNECT method is a decision too: log the destination the
            // client named, so a plain-HTTP attempt is as visible as a denial.
            let dest = request_target(&head);
            deny(logs, &peer, &dest, reason);
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

    // Resolve once, check every answer, connect to a checked address. The leg
    // re-checks the class allowlist, so this is not the only place the decision
    // is made.
    let dialed = match egress::dial(config, &request.host, request.port) {
        Ok(dialed) => dialed,
        Err(denied) => {
            let mut fields: Vec<(&str, String)> = Vec::new();
            if let Some(address) = denied.address() {
                fields.push(("address", address.to_string()));
            }
            eprintln!(
                "agentjail-gateway: {} refused: {}{}",
                dest,
                denied.reason(),
                denied
                    .address()
                    .map(|address| format!(" ({address})"))
                    .unwrap_or_default()
            );
            deny_with(logs, &peer, &dest, &denied.reason(), "0/0", &fields);
            let _ = respond(&mut stream, 403, "Forbidden");
            return;
        }
    };

    // Record the decision the moment the connection exists, not when it ends: a
    // tunnel that is established and then reset, or a gateway torn down
    // mid-relay, is exactly what an incident review looks for, and it must not
    // leave the stream silent. Denials already log at decision time.
    //
    // `resolved` and `pinned` are the interesting half of the answer: a rebind
    // that lands on a public address is only visible here.
    allow(logs, &peer, &dest, &dialed.resolved_csv(), dialed.pinned);
    if respond(&mut stream, 200, "Connection established").is_err() {
        return;
    }
    let _ = stream.set_read_timeout(None);
    let relayed = relay(stream, dialed.stream, jail, &pending);
    if relayed.over_budget {
        deny_with(
            logs,
            &peer,
            &dest,
            "byte-budget",
            &format!("{}/{}", relayed.up, relayed.down),
            &[("budget", jail.max_bytes.to_string())],
        );
    } else {
        allow_close(logs, &peer, &dest, relayed.up, relayed.down);
    }
    drop(permit);
}

/// One `decision=allow` line: the connection exists. `bytes` is `0/0` here by
/// definition; the counts are on the matching `allow-close` line.
fn allow(logs: &Logs, peer: &str, dest: &str, resolved: &str, pinned: SocketAddr) {
    logs.audit(&[
        ("peer", peer.to_string()),
        ("dest", dest.to_string()),
        ("decision", "allow".to_string()),
        ("reason", "-".to_string()),
        ("bytes", "0/0".to_string()),
        ("resolved", resolved.to_string()),
        ("pinned", pinned.ip().to_string()),
    ]);
}

/// The whole-connection byte counts for the `allow` line above.
fn allow_close(logs: &Logs, peer: &str, dest: &str, up: u64, down: u64) {
    logs.audit(&[
        ("peer", peer.to_string()),
        ("dest", dest.to_string()),
        ("decision", "allow-close".to_string()),
        ("reason", "-".to_string()),
        ("bytes", format!("{up}/{down}")),
    ]);
}

fn deny(logs: &Logs, peer: &str, dest: &str, reason: &str) {
    deny_with(logs, peer, dest, reason, "0/0", &[]);
}

/// A refusal in the same shape as a policy denial, plus the counters that
/// caused it (`budget=`, `connections=`, `address=`, ...).
fn deny_with(
    logs: &Logs,
    peer: &str,
    dest: &str,
    reason: &str,
    bytes: &str,
    extra: &[(&str, String)],
) {
    let mut fields: Vec<(&str, String)> = vec![
        ("peer", peer.to_string()),
        ("dest", dest.to_string()),
        ("decision", "deny".to_string()),
        ("reason", reason.to_string()),
        ("bytes", bytes.to_string()),
    ];
    fields.extend(extra.iter().cloned());
    logs.audit(&fields);
}

#[derive(Debug)]
struct Request {
    host: String,
    port: u16,
}

impl Request {
    /// `CONNECT host:port HTTP/1.x` and nothing else. The remaining headers are
    /// read (they carry `Proxy-Authorization`) and ignored.
    ///
    /// The request line is parsed strictly: the destination decides where bytes
    /// go, so a lenient parse is a way to smuggle a different host past the
    /// checks that read the parsed value.
    fn parse(head: &str) -> Result<Request, (u16, &'static str, &'static str)> {
        let request_line = head.lines().next().unwrap_or_default();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.is_empty() {
            return Err((400, "malformed", "Bad Request"));
        }
        if !parts[0].eq_ignore_ascii_case("CONNECT") {
            return Err((405, "not-connect", "Method Not Allowed"));
        }
        if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
            return Err((400, "malformed", "Bad Request"));
        }
        let target = parts[1];
        if target.contains(['/', '?', '#', '@', ' ', '\\']) {
            return Err((400, "malformed", "Bad Request"));
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

/// The destination a non-CONNECT request named, for the denial line. Sanitised
/// by the log itself; this only picks the token out of the request line.
fn request_target(head: &str) -> String {
    head.lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .unwrap_or("-")
        .to_string()
}

/// Read up to the blank line that ends the request head, and keep whatever
/// arrived after it.
///
/// The trailing bytes are a client that pipelined data behind its `CONNECT`
/// (rare but legal on a ready socket). Dropping them would silently corrupt the
/// tunnel, and — once the byte budget is an enforced limit — would also make the
/// accounting undercount what was actually sent.
fn read_head(stream: &mut TcpStream) -> Result<(String, Vec<u8>), &'static str> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(0) => return Err("client-closed"),
            Ok(read) => read,
            Err(_) => return Err("read-timeout"),
        };
        head.extend_from_slice(&chunk[..read]);
        if let Some(end) = head
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            let pending = head.split_off(end);
            return Ok((String::from_utf8_lossy(&head).into_owned(), pending));
        }
        if head.len() > HEAD_LIMIT {
            return Err("head-too-large");
        }
    }
}

fn respond(stream: &mut TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let body =
        format!("HTTP/1.1 {status} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[derive(Default)]
struct Relayed {
    up: u64,
    down: u64,
    /// The budget, not the client, ended the tunnel.
    over_budget: bool,
}

/// One tunnel: both ends, the jail's budget, and the "cut" switch.
struct Tunnel<'a> {
    client: &'a TcpStream,
    target: &'a TcpStream,
    jail: &'a Jail,
    cut: AtomicBool,
}

impl Tunnel<'_> {
    /// Cut the tunnel hard: both ends, both directions, so no pump stays
    /// blocked on a read that only a shutdown can end.
    fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.target.shutdown(Shutdown::Both);
    }

    /// Copy one direction, charging the jail for every chunk. Returns the bytes
    /// delivered and whether the budget stopped it.
    fn pump(&self, upstream: bool) -> (u64, bool) {
        let (from, to) = if upstream {
            (self.client, self.target)
        } else {
            (self.target, self.client)
        };
        let mut reader = from;
        let mut writer = to;
        let mut buffer = vec![0u8; RELAY_CHUNK];
        let mut total = 0u64;
        loop {
            if self.cut.load(Ordering::SeqCst) {
                break;
            }
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if self.jail.charge(read as u64).is_err() {
                self.cut();
                return (total, true);
            }
            if writer.write_all(&buffer[..read]).is_err() {
                break;
            }
            total += read as u64;
        }
        let _ = to.shutdown(Shutdown::Write);
        (total, self.cut.load(Ordering::SeqCst))
    }
}

/// Copy in both directions until both sides are done or the budget is spent,
/// counting every byte against the jail.
fn relay(client: TcpStream, target: TcpStream, jail: &Jail, pending: &[u8]) -> Relayed {
    // Bytes that arrived with the request head are upstream bytes: they were
    // sent by the jail and must count, so the budget cannot be walked around by
    // sending before the tunnel is established.
    let mut up = 0u64;
    if !pending.is_empty() {
        if jail.charge(pending.len() as u64).is_err() {
            return Relayed {
                over_budget: true,
                ..Relayed::default()
            };
        }
        let mut writer = &target;
        if writer.write_all(pending).is_err() {
            return Relayed::default();
        }
        up = pending.len() as u64;
    }

    let tunnel = Tunnel {
        client: &client,
        target: &target,
        jail,
        cut: AtomicBool::new(false),
    };
    let (up_rest, down, over_budget) = std::thread::scope(|scope| {
        let downstream = scope.spawn(|| tunnel.pump(false));
        let (up_rest, up_cut) = tunnel.pump(true);
        let (down, down_cut) = downstream.join().unwrap_or((0, false));
        (up_rest, down, up_cut || down_cut)
    });
    Relayed {
        up: up + up_rest,
        down,
        over_budget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> ClassConfig {
        ClassConfig::parse(text).expect("valid class config")
    }

    const BASE: &str = r#"
class = "test"
listen = "127.0.0.1:0"
dns = "127.0.0.1:0"
max_bytes = 4096
max_connections = 2
"#;

    fn logs(dir: &std::path::Path) -> Logs {
        let text = format!(
            "{BASE}audit_log = \"{}\"\nallow = [\"api.example.com:443\"]\n",
            dir.join("audit.log").display()
        );
        Logs::open(&config(&text))
            .expect("logs")
            .with_jail("jail-1")
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("agentjail-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn the_connection_cap_admits_exactly_its_limit() {
        let dir = tmpdir("cap");
        let jail = Arc::new(Jail::new(&config(BASE)));
        assert_eq!(jail.max_connections, 2);
        let first = jail.admit().expect("first");
        let second = jail.admit().expect("second");
        // A third is refused and told how many are in use.
        assert_eq!(jail.admit().expect_err("third"), 2);
        drop(first);
        let third = jail.admit().expect("slot released");
        drop(second);
        drop(third);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_budget_refuses_the_chunk_that_would_exceed_it() {
        let jail = Jail::new(&config(BASE));
        assert!(jail.charge(4096).is_ok(), "the whole budget is available");
        assert!(jail.charge(1).is_err(), "one byte more is refused");
        assert_eq!(
            jail.bytes.load(Ordering::SeqCst),
            4096,
            "a refused chunk is not counted"
        );
    }

    #[test]
    fn a_panic_in_a_connection_is_logged_as_a_denial() {
        let dir = tmpdir("panic");
        let logs = logs(&dir);
        guard(&logs, "10.89.0.2:1234", || panic!("simulated proxy bug"));
        let audit = std::fs::read_to_string(dir.join("audit.log")).expect("audit");
        assert!(
            audit.contains("peer=10.89.0.2:1234 dest=- decision=deny reason=internal-error"),
            "{audit}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_connect_request_is_405_and_logged_with_its_destination() {
        let error = Request::parse("GET http://example.com/ HTTP/1.1\r\n\r\n").expect_err("GET");
        assert_eq!(error.0, 405);
        assert_eq!(error.1, "not-connect");
        assert_eq!(
            request_target("GET http://example.com/ HTTP/1.1\r\n\r\n"),
            "http://example.com/"
        );
    }

    #[test]
    fn a_loose_request_line_is_refused_rather_than_guessed_at() {
        for line in [
            "CONNECT host:443",
            "CONNECT host:443 HTTP/1.1 extra",
            "CONNECT host:443 HTTP/2",
            "CONNECT host/path:443 HTTP/1.1",
            "CONNECT host:0 HTTP/1.1",
            "CONNECT :443 HTTP/1.1",
        ] {
            assert!(
                Request::parse(&format!("{line}\r\n\r\n")).is_err(),
                "{line} must not parse"
            );
        }
        let request =
            Request::parse("CONNECT API.Example.com:443 HTTP/1.1\r\n\r\n").expect("valid");
        assert_eq!(request.host, "api.example.com");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn bytes_after_the_head_are_kept_for_the_tunnel() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            stream
                .write_all(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n\r\nearly bytes")
                .expect("write");
            std::thread::sleep(Duration::from_millis(200));
        });
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (head, pending) = read_head(&mut stream).expect("head");
        assert!(head.ends_with("\r\n\r\n"), "{head:?}");
        assert_eq!(pending, b"early bytes");
        writer.join().expect("writer");
    }
}
