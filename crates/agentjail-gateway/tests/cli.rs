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

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
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

/// A loopback server that answers one line and closes, so the client sees the
/// end of the tunnel instead of waiting for its own read timeout.
fn one_shot_server(label: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.write_all(format!("hello from {label}\n").as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
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

/// The limits a test class runs with. The default is generous enough that a
/// normal small connection is never refused, and `address_policy = "loopback"`
/// is what lets a test own a fixture on the machine it runs on; no committed
/// class uses that policy.
struct Limits {
    max_bytes: u64,
    max_connections: usize,
    address_policy: &'static str,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_bytes: 1 << 20,
            max_connections: 8,
            address_policy: "loopback",
        }
    }
}

impl Gateway {
    fn start(name: &str, allow: &str, extra: &str) -> Gateway {
        Gateway::start_with(name, allow, extra, Limits::default())
    }

    fn start_with(name: &str, allow: &str, extra: &str, limits: Limits) -> Gateway {
        let dir = tmpdir(name);
        let config = format!(
            r#"class = "test"
listen = "127.0.0.1:0"
dns = "127.0.0.1:0"
audit_log = "{}"
dns_log = "-"
max_bytes = {}
max_connections = {}
address_policy = "{}"
{extra}
allow = [
{allow}
]
"#,
            dir.join("audit.log").display(),
            limits.max_bytes,
            limits.max_connections,
            limits.address_policy,
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

    /// One CONNECT, with the two ways a refusal can legitimately arrive.
    ///
    /// The gateway answers a refusal with a status line, but it may also have
    /// already cut the connection by the time the client finishes writing its
    /// request, and then the write or the read fails with a reset. That is the
    /// same decision arriving a different way — a race, not a different
    /// behaviour — so a test must be able to see it without swallowing it. Any
    /// other I/O error is a real failure and panics here, never silently.
    fn connect_attempt(&self, target: &str) -> Attempt {
        let mut stream =
            TcpStream::connect(("127.0.0.1", self.proxy_port)).expect("connect to proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        if let Err(error) = stream.write_all(request.as_bytes()) {
            return closed_or_panic(error, "writing the request");
        }
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        match reader.read_line(&mut status) {
            Ok(0) => {
                return Attempt::Closed {
                    why: "closed before a status line".to_string(),
                }
            }
            Ok(_) => {}
            Err(error) => return closed_or_panic(error, "reading the status line"),
        }
        let mut line = String::new();
        loop {
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) if n > 2 => line.clear(),
                Ok(_) => break,
                Err(error) => {
                    return closed_or_panic(error, "reading the headers");
                }
            }
        }
        let mut body = String::new();
        let _ = reader.read_to_string(&mut body);
        Attempt::Answered {
            status: status.trim_end().to_string(),
            body,
        }
    }

    /// Send one CONNECT and return (status line, body read after the head).
    /// Strict: a caller that wants the refusal-as-close behaviour uses
    /// `connect_attempt` instead.
    fn connect(&self, target: &str) -> (String, String) {
        match self.connect_attempt(target) {
            Attempt::Answered { status, body } => (status, body),
            Attempt::Closed { why } => {
                panic!("the gateway closed the connection instead of answering: {why}")
            }
        }
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.dir.join("audit.log")).unwrap_or_default()
    }
}

/// How a CONNECT attempt ended. Both variants can be a refusal; which one a test
/// accepts is the test's decision, and the audit line is what proves a refusal
/// was a decision rather than a crash.
enum Attempt {
    Answered { status: String, body: String },
    Closed { why: String },
}

fn closed_or_panic(error: std::io::Error, stage: &str) -> Attempt {
    match error.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            Attempt::Closed {
                why: format!("reset {stage}: {error}"),
            }
        }
        _ => panic!("{stage} failed for a reason that is not a refusal: {error}"),
    }
}

/// The mapping that keeps a refusal visible and a real failure loud. The socket
/// path is timing-dependent under load, so this covers it deterministically.
#[test]
fn a_connection_level_error_is_a_refusal_and_anything_else_is_not() {
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::BrokenPipe,
    ] {
        match closed_or_panic(std::io::Error::from(kind), "writing the request") {
            Attempt::Closed { why } => assert!(why.contains("writing the request"), "{why}"),
            Attempt::Answered { status, .. } => {
                panic!("{kind:?} was reported as an answer: {status}")
            }
        }
    }
    let caught = std::panic::catch_unwind(|| {
        closed_or_panic(
            std::io::Error::from(ErrorKind::PermissionDenied),
            "writing the request",
        )
    });
    assert!(
        caught.is_err(),
        "a non-connection error must not be swallowed as a refusal"
    );
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
        "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
         max_bytes = 1048576\nmax_connections = 4\nallow = [\"api.example.com:443\"]\n",
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
    assert!(
        stdout.contains("budget: 1048576 byte(s) per jail"),
        "{stdout}"
    );
    assert!(
        stdout.contains("cap: 4 concurrent connection(s)"),
        "{stdout}"
    );
    assert!(stdout.contains("address policy: public"), "{stdout}");
}

#[test]
fn an_invalid_class_config_is_refused() {
    let dir = tmpdir("invalid");
    let config = dir.join("class.toml");
    std::fs::write(
        &config,
        "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
         max_bytes = 1048576\nmax_connections = 4\nallow = [\"https://api.example.com\"]\n",
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
    let (port, _server) = one_shot_server("allowed");
    let gateway = Gateway::start("allow", &format!("  \"localhost:{port}\","), "");

    let (status, body) = gateway.connect(&format!("localhost:{port}"));
    assert_eq!(status, "HTTP/1.1 200 Connection established", "{body}");
    assert!(body.contains("hello from allowed"), "{body}");

    // The allow line is written when the connection is established; the close
    // line carries the byte counts. Either one is enough for this test.
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
    // The other half of the answer: what the name resolved to and which
    // address the tunnel actually went to. A rebind that lands on a public
    // address is only visible here.
    assert!(line.contains("resolved="), "{line}");
    assert!(line.contains("127.0.0.1"), "{line}");
    assert!(line.contains("pinned=127.0.0.1"), "{line}");
}

/// A server that answers with `bytes` bytes of filler, for the budget.
fn flood_server(bytes: usize) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let filler = vec![b'x'; bytes];
            let _ = stream.write_all(&filler);
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    (port, handle)
}

#[test]
fn a_connection_that_exceeds_the_byte_budget_is_cut_and_logged() {
    let (port, _server) = flood_server(64 * 1024);
    // Small enough that one relay chunk of filler is delivered and the next is
    // refused: the cut is the budget, not the target closing.
    let budget = 20_000;
    let gateway = Gateway::start_with(
        "budget",
        &format!("  \"localhost:{port}\","),
        "",
        Limits {
            max_bytes: budget,
            ..Limits::default()
        },
    );

    let mut stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        stream,
        "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
    )
    .expect("write");
    // The cut can arrive as EOF or as a reset; both end the read, and the
    // budget assertion below is made on what was delivered plus the audit line,
    // never on how the socket ended.
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    let body = String::from_utf8_lossy(&received);
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    let delivered = body.matches('x').count();
    assert!(delivered > 0, "the tunnel delivered nothing: {body:?}");
    assert!(
        delivered < 64 * 1024,
        "the whole 64 KiB passed a {budget}-byte budget"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("reason=byte-budget") {
        assert!(
            Instant::now() < deadline,
            "the cut was not logged: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains("reason=byte-budget"))
        .expect("budget denial");
    assert!(line.contains(&format!("dest=localhost:{port}")), "{line}");
    assert!(line.contains("decision=deny"), "{line}");
    assert!(line.contains(&format!("budget={budget}")), "{line}");
    assert!(line.contains("bytes="), "{line}");
}

#[test]
fn a_second_connection_over_the_cap_is_refused_and_logged() {
    let (port, _server) = target_server("capped");
    let gateway = Gateway::start_with(
        "cap",
        &format!("  \"localhost:{port}\","),
        "",
        Limits {
            max_connections: 1,
            ..Limits::default()
        },
    );

    // The first tunnel stays open: the fixture answers and then waits, so the
    // slot is still held when the second attempt arrives.
    let mut holder = TcpStream::connect(("127.0.0.1", gateway.proxy_port)).expect("connect");
    holder
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        holder,
        "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
    )
    .expect("write");
    let mut reader = BufReader::new(holder.try_clone().expect("clone"));
    let mut status = String::new();
    reader.read_line(&mut status).expect("status line");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let mut line = String::new();
    while reader.read_line(&mut line).expect("header") > 2 {}

    // The refusal may arrive as a 429, or as a reset if the gateway cut this
    // connection before the request finished going out. Both are the cap
    // decision; the audit line below is what distinguishes a refusal from a
    // crash, and this test asserts that line either way.
    match gateway.connect_attempt(&format!("localhost:{port}")) {
        Attempt::Answered { status, .. } => assert!(
            status.starts_with("HTTP/1.1 429"),
            "a second connection over the cap must be refused, got {status}"
        ),
        Attempt::Closed { why } => {
            eprintln!("cap refusal arrived as a closed connection ({why}); the audit line decides")
        }
    }

    // The first tunnel is untouched by the refusal: the fixture's greeting is
    // still readable through it. This also proves the slot was really held.
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .expect("read the greeting through the held tunnel");
    assert!(
        greeting.contains("hello from capped"),
        "the held tunnel stopped working: {greeting:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("reason=connection-cap") {
        assert!(
            Instant::now() < deadline,
            "the cap refusal was not logged: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains("reason=connection-cap"))
        .expect("cap denial");
    assert!(line.contains("decision=deny"), "{line}");
    assert!(line.contains("connections=1/1"), "{line}");
    drop(reader);
}

#[test]
fn a_name_resolving_to_a_blocked_address_is_refused_with_the_range_named() {
    let (port, _server) = target_server("blocked");
    // The `public` policy is the default for the committed `model` and
    // `external` classes: `localhost` is allowlisted by name and resolves to
    // loopback, which is exactly the answer that must be refused.
    let gateway = Gateway::start_with(
        "blocked",
        &format!("  \"localhost:{port}\","),
        "",
        Limits {
            address_policy: "public",
            ..Limits::default()
        },
    );

    let (status, _body) = gateway.connect(&format!("localhost:{port}"));
    assert!(
        status.starts_with("HTTP/1.1 403"),
        "a loopback answer must be refused, got {status}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("reason=blocked-") {
        assert!(
            Instant::now() < deadline,
            "no blocked-range denial: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains("reason=blocked-"))
        .expect("blocked denial");
    assert!(line.contains("reason=blocked-loopback"), "{line}");
    // `localhost` resolves to both loopback families; whichever the resolver
    // lists first is the answer that is reported.
    assert!(
        line.contains("address=127.0.0.1") || line.contains("address=::1"),
        "{line}"
    );
    assert!(line.contains(&format!("dest=localhost:{port}")), "{line}");
}

#[test]
fn an_established_connection_is_audited_at_once_and_a_reset_leaves_its_line() {
    let (port, _server) = target_server("reset");
    let gateway = Gateway::start("reset", &format!("  \"localhost:{port}\","), "");

    let mut stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        stream,
        "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
    )
    .expect("write");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut status = String::new();
    reader.read_line(&mut status).expect("status line");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");

    // The tunnel is still open, so a line now can only come from the decision
    // made at establish time. Before the fix the stream stayed empty until the
    // relay finished, and a connection established and then reset produced no
    // line at all - the case an incident review looks for.
    let needle = format!("dest=localhost:{port} decision=allow reason=- bytes=0/0");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains(&needle) {
        assert!(
            Instant::now() < deadline,
            "no allow line while the tunnel is open: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Reset rather than close: SO_LINGER 0 makes the kernel send RST on drop, so
    // the relay sees a reset client, not an orderly end of stream.
    drop(reader);
    reset(stream);

    // The reset adds the counts on a second line and never removes the first.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.audit().contains("decision=allow-close") {
        assert!(
            Instant::now() < deadline,
            "no close line after the reset: {:?}",
            gateway.audit()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let audit = gateway.audit();
    let close = audit
        .lines()
        .find(|line| line.contains("decision=allow-close"))
        .expect("close line");
    assert!(close.contains(&format!("dest=localhost:{port}")), "{close}");
    assert!(close.contains("bytes="), "{close}");
}

/// Close a socket with `SO_LINGER 0`, which makes the kernel send RST instead of
/// FIN. That is the client that goes away mid-tunnel.
fn reset(stream: TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "SO_LINGER 0");
    drop(stream);
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
    let (port, _server) = one_shot_server("named");
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
    // The plain-HTTP attempt is logged in the denial shape, with the
    // destination it named, so it is as visible as a policy denial.
    let audit = gateway.audit();
    let line = audit
        .lines()
        .find(|line| line.contains("reason=not-connect"))
        .expect("denial line");
    assert!(line.contains("decision=deny"), "{line}");
    assert!(line.contains("dest=http://example.com/"), "{line}");
    assert!(line.contains("class=test"), "{line}");
    assert!(line.contains("jail=jail-42"), "{line}");
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
