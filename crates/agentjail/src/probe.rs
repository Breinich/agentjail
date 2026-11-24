//! The selftest probe: the one piece of code that runs **both** on the bare host
//! and inside a jail. It only observes; it does not decide. The harness
//! (`selftest.rs`) applies the same assertions to the observations from either
//! executor, so a negative that passes is never a second, weaker
//! implementation that only exists for the jail.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

pub struct ProbeArgs {
    pub case: String,
    pub host_secret: String,
    pub env_secret: String,
    pub target_host: String,
    pub target_ip: String,
    pub allowed_port: u16,
    pub denied_port: u16,
    pub memory_limit: u64,
    pub nofile_limit: u64,
    pub pids_limit: u32,
    pub netns: String,
    pub role: String,
    pub token: String,
    pub peer_token: String,
    pub hold_ms: u64,
    pub alloc_bytes: u64,
}

pub fn run(args: &ProbeArgs) -> Value {
    match args.case.as_str() {
        "main" => main_probe(args),
        "isolation" => isolation_probe(args),
        "network" => {
            let (namespace, route, interface, peer, cap_net_admin) = network_probe(&args.netns);
            json!({
                "namespace": namespace,
                "route": route,
                "interface": interface,
                "peer": peer,
                "cap_net_admin": cap_net_admin,
            })
        }
        "hold" => {
            std::thread::sleep(Duration::from_millis(args.hold_ms));
            json!({ "held": true })
        }
        "hold-alloc" => {
            hold_alloc(args.alloc_bytes);
            json!({ "allocated": args.alloc_bytes })
        }
        other => json!({ "error": format!("unknown probe case {other:?}") }),
    }
}

fn main_probe(args: &ProbeArgs) -> Value {
    // Everything before the namespace case runs in the executor's own
    // namespace: for the baseline that is the plain host process.
    let host_file = match std::fs::read(&args.host_secret) {
        Ok(_) => "read".to_string(),
        Err(error) => format!("error:{error}"),
    };
    let host_env = if std::env::var_os(&args.env_secret).is_some() {
        "present"
    } else {
        "absent"
    };

    let denied_target = format!("{}:{}", args.target_host, args.denied_port);
    let outside_direct = tcp_connect(&args.target_host, args.denied_port, 1500);
    let outside_proxy = proxy_connect(&denied_target);
    let outside_reachable = outside_direct.is_ok()
        || outside_proxy
            .as_ref()
            .map(|response| response.0.contains(" 200 "))
            .unwrap_or(false);

    let raw_target = format!("{}:{}", args.target_ip, args.allowed_port);
    let raw_direct = tcp_connect(&args.target_ip, args.allowed_port, 1500);
    let raw_proxy = proxy_connect(&raw_target);
    let raw_reachable = raw_direct.is_ok()
        || raw_proxy
            .as_ref()
            .map(|response| response.0.contains(" 200 "))
            .unwrap_or(false);

    let positive = proxy_connect(&format!("{}:{}", args.target_host, args.allowed_port))
        .map(|(status, body)| {
            json!({
                "status": status,
                "body": String::from_utf8_lossy(&body).trim().to_string(),
            })
        })
        .unwrap_or_else(|| json!({ "error": "no proxy configured or proxy connection failed" }));

    let nofile = nofile_probe(args.nofile_limit);
    let pids = pids_probe(args.pids_limit);
    let memory = memory_probe(args.memory_limit);

    // Network-control cases run in a child of their own. The baseline may move
    // itself into a fresh user+network namespace to obtain the capability a
    // plain host process would need, and that must not affect the observations
    // above.
    let network = network_child(&args.netns).unwrap_or_else(|error| {
        json!({
            "namespace": format!("unavailable:{error}"),
            "route": "not-attempted",
            "interface": "not-attempted",
            "peer": "not-attempted",
            "cap_net_admin": false,
        })
    });

    json!({
        "host_file": host_file,
        "host_env": host_env,
        "outside": {
            "direct": describe_connect(&outside_direct),
            "proxy": outside_proxy.as_ref().map(|response| response.0.clone()).unwrap_or_else(|| "absent".to_string()),
            "reachable": outside_reachable,
        },
        "raw_ip": {
            "direct": describe_connect(&raw_direct),
            "proxy": raw_proxy.as_ref().map(|response| response.0.clone()).unwrap_or_else(|| "absent".to_string()),
            "reachable": raw_reachable,
        },
        "positive": positive,
        "nofile": nofile,
        "pids": pids,
        "memory": memory,
        "network": {
            "namespace": network["namespace"],
            "route": network["route"],
            "interface": network["interface"],
            "peer": network["peer"],
        },
        "cap_net_admin": network["cap_net_admin"],
    })
}

fn network_child(netns: &str) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let output = std::process::Command::new(executable)
        .args(["__probe", "--case", "network", "--netns", netns])
        .output()
        .map_err(|error| format!("cannot start network probe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "network probe exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot parse network probe JSON: {error}"))
}

fn isolation_probe(args: &ProbeArgs) -> Value {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let home = Path::new(&home);
    let _ = std::fs::create_dir_all(home);
    let own_marker = home.join("peer-own.marker");
    let peer_marker = home.join("peer-other.marker");
    let socket = home.join("peer.sock");

    // Both roles write their own marker. If the two jails shared a home, the
    // other marker and the owner's socket would be visible under the same path.
    if let Err(error) = std::fs::write(&own_marker, &args.token) {
        return json!({ "error": format!("cannot write own marker: {error}") });
    }

    let listener = if args.role == "owner" {
        match std::os::unix::net::UnixListener::bind(&socket) {
            Ok(listener) => Some(listener),
            Err(error) => return json!({ "error": format!("cannot bind peer socket: {error}") }),
        }
    } else {
        None
    };

    // The owner holds the socket open while the prober starts and tries it.
    std::thread::sleep(Duration::from_millis(args.hold_ms));

    let peer_file = if peer_marker.exists() {
        "present"
    } else {
        "absent"
    };
    let own_file = std::fs::read_to_string(&own_marker).unwrap_or_default() == args.token;
    let socket_result = match UnixStream::connect(&socket) {
        Ok(_) => "connected",
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => "absent",
            _ => "refused",
        },
    };
    let own_env = std::env::var("PEER_ID").ok() == Some(args.token.clone());
    let peer_env = std::env::var("PEER_PEER_ID").is_err();

    if let Some(listener) = listener {
        drop(listener);
    }

    json!({
        "own_file": if own_file { "present" } else { "missing" },
        "peer_file": peer_file,
        "peer_socket": socket_result,
        "own_env": own_env,
        "peer_env_absent": peer_env,
        "peer_token_configured": !args.peer_token.is_empty(),
    })
}

fn hold_alloc(bytes: u64) {
    let size = bytes as usize;
    let mut buffer = vec![0u8; size];
    // Touch one byte per page so the pages are committed, not just reserved.
    let mut index = 0;
    while index < size {
        buffer[index] = 1;
        index += 4096;
    }
    std::thread::sleep(Duration::from_millis(1000));
    drop(buffer);
}

fn describe_connect(result: &Result<(), String>) -> String {
    match result {
        Ok(()) => "connected".to_string(),
        Err(error) => format!("refused:{error}"),
    }
}

fn tcp_connect(host: &str, port: u16, timeout_ms: u64) -> Result<(), String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve:{error}"))?;
    for address in addresses {
        if TcpStream::connect_timeout(&address, Duration::from_millis(timeout_ms)).is_ok() {
            return Ok(());
        }
    }
    Err("no address accepted a connection".to_string())
}

/// Send one CONNECT through the proxy the jail was given. Returns the status
/// line and, for a 200, whatever the destination sent before closing.
fn proxy_connect(target: &str) -> Option<(String, Vec<u8>)> {
    let proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .ok()?;
    let authority = proxy
        .strip_prefix("http://")
        .or_else(|| proxy.strip_prefix("https://"))
        .unwrap_or(&proxy);
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(
        &(host, port).to_socket_addrs().ok()?.next()?,
        Duration::from_millis(2000),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .ok()?;
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )
    .ok()?;
    let _ = stream.flush();

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return Some((status_line(&raw), Vec::new()));
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_header_end(&raw) {
            break position;
        }
        if raw.len() > 64 * 1024 {
            return Some((status_line(&raw), Vec::new()));
        }
    };
    let status = status_line(&raw);
    let mut body = raw[header_end..].to_vec();
    if status.contains(" 200 ") {
        // The fixture sends a short line and closes; a bounded read keeps a
        // misbehaving destination from stalling the harness.
        let _ = stream.read_to_end(&mut body);
    }
    Some((status, body))
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn status_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.lines().next().unwrap_or("").trim().to_string()
}

fn nofile_probe(configured: u64) -> Value {
    // A bare process can raise its soft limit to the hard limit; the jail's hard
    // limit is what podman set from the profile, so the same probe shows both.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        let mut raised = limit;
        raised.rlim_cur = raised.rlim_max;
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) };
        limit.rlim_cur
    } else {
        0
    };

    let cap = configured.saturating_mul(2).saturating_add(16).min(16384);
    let mut files = Vec::new();
    let mut error = String::new();
    while (files.len() as u64) < cap {
        match std::fs::File::open("/dev/null") {
            Ok(file) => files.push(file),
            Err(err) => {
                error = err.to_string();
                break;
            }
        }
    }
    json!({
        "configured": configured,
        "soft": soft,
        "opened": files.len(),
        "probe_cap": cap,
        "error": error,
    })
}

fn pids_probe(configured: u32) -> Value {
    let cap = configured.saturating_mul(2).saturating_add(8).min(512);
    let exe = std::env::current_exe().unwrap_or_default();
    let mut children = Vec::new();
    let mut error = String::new();
    while (children.len() as u32) < cap {
        match std::process::Command::new(&exe)
            .args(["__probe", "--case", "hold", "--hold-ms", "5000"])
            .spawn()
        {
            Ok(child) => children.push(child),
            Err(err) => {
                error = err.to_string();
                break;
            }
        }
    }
    let spawned = children.len() as u32;
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    json!({
        "configured": configured,
        "spawned": spawned,
        "probe_cap": cap,
        "error": error,
    })
}

fn memory_probe(limit: u64) -> Value {
    let alloc = limit.saturating_mul(2).max(64 * 1024 * 1024);
    let exe = std::env::current_exe().unwrap_or_default();
    let child = std::process::Command::new(&exe)
        .args([
            "__probe",
            "--case",
            "hold-alloc",
            "--alloc-bytes",
            &alloc.to_string(),
        ])
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            return json!({ "alloc_bytes": alloc, "exit": format!("spawn-error:{error}") })
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit = match status.code() {
                    Some(code) => format!("exit:{code}"),
                    None => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::process::ExitStatusExt;
                            format!("signal:{}", status.signal().unwrap_or(0))
                        }
                        #[cfg(not(unix))]
                        {
                            "signal:unknown".to_string()
                        }
                    }
                };
                return json!({ "alloc_bytes": alloc, "exit": exit });
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return json!({ "alloc_bytes": alloc, "exit": "timeout" });
            }
            Err(error) => {
                return json!({ "alloc_bytes": alloc, "exit": format!("wait-error:{error}") })
            }
        }
    }
}

fn network_probe(netns: &str) -> (String, String, String, String, bool) {
    let mut namespace = "current".to_string();
    if netns == "nested" {
        match enter_nested_netns() {
            Ok(()) => namespace = "nested".to_string(),
            Err(error) => {
                return (
                    format!("unavailable:{error}"),
                    "not-attempted".to_string(),
                    "not-attempted".to_string(),
                    "not-attempted".to_string(),
                    false,
                );
            }
        }
    }

    let cap_net_admin = cap_net_admin();
    // `lo` exists in every network namespace; bringing it up is setup for the
    // route probe, not one of the three attempts.
    let _ = bring_link_up("lo");
    let route = describe_netlink(add_route());
    let interface = describe_netlink(create_link("aj-selftest-if", "dummy"));
    let peer = describe_netlink(create_veth("aj-selftest-a", "aj-selftest-b"));
    (namespace, route, interface, peer, cap_net_admin)
}

fn describe_netlink(result: Result<(), String>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => error,
    }
}

fn cap_net_admin() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let line = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .unwrap_or("");
    let hex = line.split_whitespace().nth(1).unwrap_or("0");
    u64::from_str_radix(hex, 16)
        .map(|caps| caps & (1 << 12) != 0)
        .unwrap_or(false)
}

/// Move the probe into a fresh user and network namespace, then become root
/// inside it. This is how the **baseline** shows the hazard: an ordinary
/// unprivileged process can obtain network control for a namespace it owns, so
/// if the jail denied this only because the host user was unprivileged the test
/// would prove nothing.
fn enter_nested_netns() -> Result<(), String> {
    // Capture the ids **before** unshare: inside the new namespace they read as
    // the overflow uid until a map is written, and mapping the overflow id is
    // exactly the EPERM that makes this look impossible.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            return Err(format!("userns:{}", last_error()));
        }
    }
    // `std::fs::write` opens with O_TRUNC, which procfs refuses; open the
    // control files for writing only, exactly like the kernel expects.
    write_control("/proc/self/setgroups", "deny")?;
    write_control("/proc/self/uid_map", &format!("0 {uid} 1"))?;
    write_control("/proc/self/gid_map", &format!("0 {gid} 1"))?;
    unsafe {
        if libc::setresgid(0, 0, 0) != 0 {
            return Err(format!("setresgid:{}", last_error()));
        }
        if libc::setresuid(0, 0, 0) != 0 {
            return Err(format!("setresuid:{}", last_error()));
        }
        if libc::unshare(libc::CLONE_NEWNET) != 0 {
            return Err(format!("netns:{}", last_error()));
        }
    }
    Ok(())
}

fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

fn write_control(path: &str, value: &str) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("open {path}: {error}"))?;
    file.write_all(value.as_bytes())
        .map_err(|error| format!("write {path}: {error}"))
}

fn ifindex(name: &str) -> Result<i32, String> {
    let name = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(last_error())
    } else {
        Ok(index as i32)
    }
}

fn bring_link_up(name: &str) -> Result<(), String> {
    let index = ifindex(name)?;
    let mut payload = vec![0u8; 16];
    payload[0] = libc::AF_UNSPEC as u8;
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    payload[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    payload[12..16].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    netlink_request(RTM_NEWLINK, 0, &payload)
}

fn add_route() -> Result<(), String> {
    let lo = ifindex("lo")?;
    let mut payload = vec![0u8; 12];
    payload[0] = libc::AF_INET as u8;
    payload[1] = 32; // destination prefix length
    payload[4] = 254; // RT_TABLE_MAIN
    payload[5] = 3; // RTPROT_BOOT
    payload[6] = 253; // RT_SCOPE_LINK
    payload[7] = 1; // RTN_UNICAST
    let mut attrs = Vec::new();
    attrs.extend(attribute(RTA_DST, &[203, 0, 113, 7]));
    attrs.extend(attribute(RTA_OIF, &(lo as u32).to_ne_bytes()));
    payload.extend(attrs);
    netlink_request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &payload)
}

fn create_link(name: &str, kind: &str) -> Result<(), String> {
    let mut attrs = Vec::new();
    attrs.extend(attribute(IFLA_IFNAME, &cstring(name)?));
    attrs.extend(nested_attribute(
        IFLA_LINKINFO,
        &[attribute(IFLA_INFO_KIND, &cstring(kind)?)],
    ));
    netlink_request(
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL,
        &link_payload(&attrs),
    )
}

fn create_veth(left: &str, right: &str) -> Result<(), String> {
    let mut peer = vec![0u8; 16]; // ifinfomsg for the peer end
    peer[0] = libc::AF_UNSPEC as u8;
    peer.extend(attribute(IFLA_IFNAME, &cstring(right)?));
    let link_info = [
        attribute(IFLA_INFO_KIND, &cstring("veth")?),
        nested_attribute(IFLA_INFO_DATA, &[nested_attribute(VETH_INFO_PEER, &[peer])]),
    ];
    let mut attrs = Vec::new();
    attrs.extend(attribute(IFLA_IFNAME, &cstring(left)?));
    attrs.extend(nested_attribute(IFLA_LINKINFO, &link_info));
    netlink_request(
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL,
        &link_payload(&attrs),
    )
}

fn link_payload(attrs: &[u8]) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[0] = libc::AF_UNSPEC as u8;
    payload.extend(attrs);
    payload
}

fn cstring(value: &str) -> Result<Vec<u8>, String> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    Ok(bytes)
}

const RTM_NEWLINK: u16 = 16;
const RTM_NEWROUTE: u16 = 24;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 0x02;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;

fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
    let length = 4 + payload.len();
    let mut bytes = Vec::with_capacity((length + 3) & !3);
    bytes.extend((length as u16).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(payload);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn nested_attribute(kind: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for child in children {
        payload.extend(child);
    }
    attribute(kind, &payload)
}

struct Netlink {
    fd: i32,
    sequence: u32,
}

impl Netlink {
    fn open() -> Result<Self, String> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(last_error());
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let result = unsafe {
            libc::bind(
                fd,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if result != 0 {
            let error = last_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        Ok(Netlink { fd, sequence: 0 })
    }

    fn request(&mut self, kind: u16, extra_flags: u16, payload: &[u8]) -> Result<(), String> {
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
        let length = 16 + payload.len();
        let mut message = Vec::with_capacity(length);
        message.extend((length as u32).to_ne_bytes());
        message.extend(kind.to_ne_bytes());
        message.extend(flags.to_ne_bytes());
        message.extend(sequence.to_ne_bytes());
        message.extend(0u32.to_ne_bytes());
        message.extend(payload);

        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if sent < 0 {
            return Err(errno_name());
        }

        let mut buffer = [0u8; 8192];
        loop {
            let received = unsafe {
                libc::recv(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                return Err(errno_name());
            }
            let received = received as usize;
            if received < 16 {
                continue;
            }
            let message_type = u16::from_ne_bytes([buffer[4], buffer[5]]);
            let message_sequence =
                u32::from_ne_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
            if message_sequence != sequence {
                continue;
            }
            if message_type == NLMSG_ERROR && received >= 20 {
                let code = i32::from_ne_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
                if code == 0 {
                    return Ok(());
                }
                return Err(errno_name_code(-code));
            }
        }
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn netlink_request(kind: u16, extra_flags: u16, payload: &[u8]) -> Result<(), String> {
    let mut netlink = Netlink::open()?;
    netlink.request(kind, extra_flags, payload)
}

fn errno_name() -> String {
    errno_name_code(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

fn errno_name_code(code: i32) -> String {
    match code {
        libc::EPERM => "EPERM".to_string(),
        libc::EACCES => "EACCES".to_string(),
        libc::ENOENT => "ENOENT".to_string(),
        libc::EINVAL => "EINVAL".to_string(),
        libc::ENODEV => "ENODEV".to_string(),
        libc::EOPNOTSUPP => "EOPNOTSUPP".to_string(),
        libc::ETIMEDOUT => "ETIMEDOUT".to_string(),
        other => format!("errno:{other}"),
    }
}
