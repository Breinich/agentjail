//! End-to-end gateway tests: a real listener, a real CONNECT, real audit lines.
//!
//! These do not need podman and do not reach the internet. They start the
//! gateway with a class config that points at a loopback target the test owns,
//! which is what proves the three decisions the design rests on:
//!
//! 1. an allowlisted destination answers **through the proxy** and the audit
//!    stream records it;
//! 2. anything not on the class allowlist is refused **and** logged as a denial;
//! 3. a raw `IP:port` is refused even when a name for the same address is
//!    allowlisted, and a name is answered only for this class.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_agentjail-gateway")
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("gateway-e2e-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A loopback server that says who it is and answers one line.
fn target_server(label: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            // Answer immediately: a CONNECT tunnel carries no request until the
            // client sends one, and the relay must not be the thing that waits.
            let _ = stream.write_all(format!("hello from {label}\n").as_bytes());
            let mut buffer = [0u8; 256];
            let _ = stream.read(&mut buffer);
        }
    });
    (port, handle)
}

struct Gateway {
    child: Child,
    /// The gateway's own stderr: startup lines, then DNS lines (audit defaults
    /// to stdout). Ports are chosen by the kernel and read from here.
    stderr: BufReader<std::process::ChildStderr>,
    proxy_port: u16,
    dns_port: u16,
    dir: PathBuf,
}

impl Gateway {
    fn start(name: &str, allow: &str, extra: &str) -> Gateway {
        let dir = tmpdir(name);
        let config = format!(
            r#"class = "test"
listen = "127.0.0.1:0"
dns = "127.0.0.1:0"
audit_log = "{}"
dns_log = "-"
{extra}
allow = [
{allow}
]
"#,
            dir.join("audit.log").display(),
        );
        let config_path = dir.join("class.toml");
        std::fs::write(&config_path, config).expect("write class config");

        let mut child = Command::new(binary())
            .args(["--config", config_path.to_str().expect("path")])
            .args(["--jail-id", "jail-42"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start gateway");

        let mut stderr = BufReader::new(child.stderr.take().expect("stderr"));
        let (mut proxy_port, mut dns_port) = (0, 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = String::new();
        while proxy_port == 0 || dns_port == 0 {
            let mut line = String::new();
            assert!(
                stderr.read_line(&mut line).expect("read stderr") > 0,
                "gateway exited before listening: {seen}"
            );
            if let Some(port) = port_after(&line, "connect listening on ") {
                proxy_port = port;
            }
            if let Some(port) = port_after(&line, "dns listening on ") {
                dns_port = port;
            }
            seen.push_str(&line);
            assert!(Instant::now() < deadline, "gateway did not listen: {seen}");
        }

        Gateway {
            child,
            stderr,
            proxy_port,
            dns_port,
            dir,
        }
    }

    /// Send one CONNECT and return (status line, body read after the head).
    fn connect(&self, target: &str) -> (String, String) {
        let mut stream =
            TcpStream::connect(("127.0.0.1", self.proxy_port)).expect("connect to proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        write!(
            stream,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .expect("write");
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).expect("status line");
        let mut line = String::new();
        while reader.read_line(&mut line).expect("header") > 2 {}
        let mut body = String::new();
        let _ = reader.read_to_string(&mut body);
        (status.trim_end().to_string(), body)
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.dir.join("audit.log")).unwrap_or_default()
    }
}

fn port_after(line: &str, marker: &str) -> Option<u16> {
    line.split(marker)
        .nth(1)?
        .trim()
        .rsplit_once(':')?
        .1
        .parse()
        .ok()
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn check_prints_the_class_allowlist_and_exits_zero() {
    let dir = tmpdir("check");
    let config = dir.join("class.toml");
    std::fs::write(
        &config,
        "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\nallow = [\"api.example.com:443\"]\n",
    )
    .expect("write");
    let output = Command::new(binary())
        .args(["--config", config.to_str().expect("path"), "--check"])
        .output()
        .expect("run gateway");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("api.example.com:443"), "{stdout}");
    assert!(stdout.contains("class: model"), "{stdout}");
    assert!(stdout.contains("audit stream: stdout"), "{stdout}");
    assert!(stdout.contains("dns stream: stderr"), "{stdout}");
}

#[test]
fn an_invalid_class_config_is_refused() {
    let dir = tmpdir("invalid");
    let config = dir.join("class.toml");
    std::fs::write(
        &config,
        "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\nallow = [\"https://api.example.com\"]\n",
    )
    .expect("write");
    let output = Command::new(binary())
        .args(["--config", config.to_str().expect("path")])
        .output()
        .expect("run gateway");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is invalid"), "{stderr}");
    assert!(stderr.contains("no scheme"), "{stderr}");
}

#[test]
fn an_allowlisted_destination_answers_through_the_proxy_and_is_audited() {
    let (port, _server) = target_server("allowed");
    let gateway = Gateway::start("allow", &format!("  \"localhost:{port}\","), "");

    let (status, body) = gateway.connect(&format!("localhost:{port}"));
    assert_eq!(status, "HTTP/1.1 200 Connection established", "{body}");
    assert!(body.contains("hello from allowed"), "{body}");

    // The audit line is written when the connection closes, so give the relay a
    // moment to finish both directions.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("decision=allow") {
        assert!(
            Instant::now() < deadline,
            "no audit line: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains("decision=allow"))
        .expect("allow line");
    assert!(line.starts_with("ts="), "{line}");
    assert!(line.contains("class=test"), "{line}");
    assert!(line.contains("jail=jail-42"), "{line}");
    assert!(line.contains(&format!("dest=localhost:{port}")), "{line}");
    assert!(line.contains("bytes="), "{line}");
}

#[test]
fn a_denied_destination_is_refused_and_logged_as_a_denial() {
    let (allowed_port, _allowed) = target_server("allowed");
    let (other_port, _other) = target_server("other");
    let gateway = Gateway::start("deny", &format!("  \"localhost:{allowed_port}\","), "");

    let (status, _body) = gateway.connect(&format!("localhost:{other_port}"));
    assert!(
        status.starts_with("HTTP/1.1 403"),
        "unlisted port must be refused, got {status}"
    );

    let needle = format!("dest=localhost:{other_port} decision=deny");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains(&needle) {
        assert!(
            Instant::now() < deadline,
            "no denial line: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains(&needle))
        .expect("deny line");
    assert!(
        line.contains(&format!("dest=localhost:{other_port}")),
        "{line}"
    );
    assert!(line.contains("reason=not-in-class"), "{line}");
    assert!(line.contains("bytes=0/0"), "{line}");
}

#[test]
fn a_raw_ip_destination_is_refused_even_when_the_name_is_allowlisted() {
    let (port, _server) = target_server("named");
    let gateway = Gateway::start("raw-ip", &format!("  \"localhost:{port}\","), "");

    let (status, _body) = gateway.connect(&format!("127.0.0.1:{port}"));
    assert!(
        status.starts_with("HTTP/1.1 403"),
        "a raw IP must be refused, got {status}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("reason=ip-literal") {
        assert!(
            Instant::now() < deadline,
            "no ip-literal denial: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The same destination by name works, so the refusal is about the form of
    // the destination and not about the target being unreachable.
    let (status, body) = gateway.connect(&format!("localhost:{port}"));
    assert_eq!(status, "HTTP/1.1 200 Connection established", "{body}");
}

#[test]
fn a_method_other_than_connect_is_refused() {
    let gateway = Gateway::start("method", "  \"localhost:1\",", "");
    let mut stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    write!(
        stream,
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    .expect("write");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 405"), "{response}");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("reason=not-connect") {
        assert!(
            Instant::now() < deadline,
            "no denial: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn dns_answers_only_this_class_names_and_logs_on_its_own_stream() {
    let (port, _server) = target_server("dns");
    let mut gateway = Gateway::start("dns", &format!("  \"localhost:{port}\","), "");

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    for name in ["localhost", "evil.example.com"] {
        let packet = query(0x4242, name, 1);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            socket
                .send_to(&packet, ("127.0.0.1", gateway.dns_port))
                .expect("send query");
            let mut buffer = [0u8; 512];
            match socket.recv_from(&mut buffer) {
                Ok((len, _)) => {
                    let response = &buffer[..len];
                    assert_eq!(&response[0..2], &[0x42, 0x42]);
                    let rcode = response[3] & 0x0f;
                    let answers = u16::from_be_bytes([response[6], response[7]]);
                    if name == "localhost" {
                        assert_eq!((rcode, answers), (0, 1), "{name}: {response:?}");
                        assert_eq!(&response[len - 4..], &[127, 0, 0, 1]);
                    } else {
                        assert_eq!(
                            (rcode, answers),
                            (3, 0),
                            "{name} must be NXDOMAIN: {response:?}"
                        );
                    }
                    break;
                }
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "no DNS reply for {name}: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    // The DNS stream is stderr and the audit stream is a separate file: a query
    // is not a connection, so it must not appear in the audit log.
    let stderr = &mut gateway.stderr;
    let mut dns_lines = String::new();
    for _ in 0..2 {
        let mut line = String::new();
        assert!(stderr.read_line(&mut line).expect("read stderr") > 0);
        dns_lines.push_str(&line);
    }
    assert!(dns_lines.contains("qname=localhost"), "{dns_lines}");
    assert!(dns_lines.contains("decision=answer"), "{dns_lines}");
    assert!(dns_lines.contains("qname=evil.example.com"), "{dns_lines}");
    assert!(dns_lines.contains("decision=nxdomain"), "{dns_lines}");
    assert!(
        !gateway.audit().contains("qname="),
        "a DNS line leaked into the audit stream: {:?}",
        gateway.audit()
    );
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    for _ in 0..3 {
        packet.extend_from_slice(&0u16.to_be_bytes());
    }
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}
