//! The laboratory gateway (spec §13.10's Chameleon Gateway, first
//! runtime): a proxy the laboratory fully controls, so every trial can
//! *name* what the workload tried to reach while the policy decides
//! whether anything real is ever contacted.
//!
//! Proxy-honoring clients hand the gateway their logical destination in
//! cleartext — `CONNECT host:port` for TLS, an absolute URI for plain
//! HTTP — which is exactly the identity a loopback-proxied environment
//! hides from the syscall boundary. The gateway records every request as
//! an **intent** (host, port, scheme, method, path) and then enforces
//! its policy:
//!
//! - [`GatewayPolicy::Deny`] — refuse everything (`403`). Combined with
//!   a network namespace this yields zero real service interaction with
//!   full intent capture.
//! - [`GatewayPolicy::Forward`] — tunnel to the destination (chaining
//!   through an upstream proxy when the host has one), recording
//!   identities. TLS is tunneled opaquely — the gateway never
//!   man-in-the-middles a connection.
//! - [`GatewayPolicy::ForwardExcept`] — forward everything except one
//!   set of logical destinations: the enforcement mechanism for the
//!   `BlockDependency` treatment (exactly one controlled change).
//!
//! Intents are appended as JSONL to a log file the laboratory parses
//! after the trial — the same file-based contract the strace observer
//! uses. Everything here is std-only (threads, blocking sockets).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{BufWriter, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Maximum request head the gateway reads before giving up on a client.
const MAX_HEAD_BYTES: usize = 32 * 1024;
/// Per-connection I/O timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// What the gateway does with a request (see module docs).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GatewayPolicy {
    /// Refuse every request after recording it.
    Deny,
    /// Forward every request, recording it.
    Forward,
    /// Forward everything except destinations matching an entry
    /// (`host:port` exact, or bare `host` for every port).
    ForwardExcept(BTreeSet<String>),
}

impl GatewayPolicy {
    fn refuses(&self, host: &str, port: u16) -> bool {
        match self {
            GatewayPolicy::Deny => true,
            GatewayPolicy::Forward => false,
            GatewayPolicy::ForwardExcept(blocked) => {
                blocked.contains(&format!("{host}:{port}")) || blocked.contains(host)
            }
        }
    }
}

/// An upstream proxy to chain through (the host's own egress proxy).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
}

impl Upstream {
    /// Parse `http://host:port` (userinfo and paths are rejected — an
    /// upstream proxy URL carrying credentials must not be accepted
    /// silently into evidence-adjacent config).
    pub fn parse(url: &str) -> Option<Upstream> {
        let rest = url.strip_prefix("http://")?;
        let rest = rest.trim_end_matches('/');
        if rest.contains('@') || rest.contains('/') {
            return None;
        }
        let (host, port) = rest.rsplit_once(':')?;
        Some(Upstream {
            host: host.to_string(),
            port: port.parse().ok()?,
        })
    }
}

/// One recorded request: what the workload tried to reach, and how.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GatewayIntent {
    pub seq: u64,
    /// Logical destination host as the client named it.
    pub host: String,
    pub port: u16,
    /// `https` for CONNECT tunnels, `http` for absolute-form requests.
    pub scheme: String,
    /// `CONNECT`, or the HTTP method of a plain request.
    pub method: String,
    /// URL path for plain HTTP; empty for CONNECT (TLS payloads are
    /// opaque by design — the gateway never inspects them).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// `refused`, `forwarded`, or `forward-failed`.
    pub decision: String,
}

/// Read back the intents a gateway wrote. Missing file = no intents
/// (the workload never spoke to the gateway).
pub fn read_intents(log: &Path) -> Vec<GatewayIntent> {
    let Ok(text) = std::fs::read_to_string(log) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

struct GatewayState {
    policy: GatewayPolicy,
    upstream: Option<Upstream>,
    log: Mutex<BufWriter<std::fs::File>>,
    seq: AtomicU64,
    stop: AtomicBool,
}

impl GatewayState {
    fn record(&self, mut intent: GatewayIntent) {
        intent.seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut log) = self.log.lock() {
            if let Ok(line) = serde_json::to_string(&intent) {
                let _ = writeln!(log, "{line}");
                let _ = log.flush();
            }
        }
    }
}

/// A gateway listening on a background thread (host-side use: the
/// laboratory starts it in-process for forward-mode trials).
pub struct GatewayServer {
    pub port: u16,
    state: Arc<GatewayState>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
    log_path: PathBuf,
}

impl GatewayServer {
    /// Bind `addr` (use port 0 for an ephemeral port) and serve until
    /// [`GatewayServer::shutdown`].
    pub fn start(
        addr: &str,
        policy: GatewayPolicy,
        upstream: Option<Upstream>,
        log_path: &Path,
    ) -> std::io::Result<GatewayServer> {
        let listener = TcpListener::bind(addr)?;
        let port = listener.local_addr()?.port();
        let state = Arc::new(GatewayState {
            policy,
            upstream,
            log: Mutex::new(BufWriter::new(std::fs::File::create(log_path)?)),
            seq: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let accept_state = Arc::clone(&state);
        let accept_thread = std::thread::spawn(move || accept_loop(listener, accept_state));
        Ok(GatewayServer {
            port,
            state,
            accept_thread: Some(accept_thread),
            log_path: log_path.to_path_buf(),
        })
    }

    /// Stop accepting, join the accept thread, and return the intents.
    pub fn shutdown(mut self) -> Vec<GatewayIntent> {
        self.state.stop.store(true, Ordering::SeqCst);
        // Unblock the accept call.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        if let Ok(mut log) = self.state.log.lock() {
            let _ = log.flush();
        }
        read_intents(&self.log_path)
    }
}

/// Serve until killed — the in-namespace subprocess mode. Writes
/// `ready` once the socket is bound so a wrapper script can wait for it.
pub fn serve_blocking(
    addr: &str,
    policy: GatewayPolicy,
    upstream: Option<Upstream>,
    log_path: &Path,
    ready: Option<&Path>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let state = Arc::new(GatewayState {
        policy,
        upstream,
        log: Mutex::new(BufWriter::new(std::fs::File::create(log_path)?)),
        seq: AtomicU64::new(0),
        stop: AtomicBool::new(false),
    });
    if let Some(ready) = ready {
        std::fs::write(ready, b"ready")?;
    }
    accept_loop(listener, state);
    Ok(())
}

fn accept_loop(listener: TcpListener, state: Arc<GatewayState>) {
    for stream in listener.incoming() {
        if state.stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let conn_state = Arc::clone(&state);
        std::thread::spawn(move || handle_connection(stream, conn_state));
    }
}

/// The parsed first line of a proxy request.
struct ProxyRequest {
    host: String,
    port: u16,
    scheme: &'static str,
    method: String,
    path: String,
    /// The raw request head, for transparent forwarding.
    head: Vec<u8>,
}

fn parse_request(stream: &mut TcpStream) -> Option<ProxyRequest> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > MAX_HEAD_BYTES {
            return None;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buffer[..n]),
        }
    }
    let first_line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let first_line = String::from_utf8_lossy(&head[..first_line_end]).into_owned();
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        // `CONNECT host:port HTTP/1.1`
        let (host, port) = target.rsplit_once(':')?;
        return Some(ProxyRequest {
            host: host.trim_start_matches('[').trim_end_matches(']').into(),
            port: port.parse().ok()?,
            scheme: "https",
            method,
            path: String::new(),
            head,
        });
    }
    // Absolute-form plain HTTP: `GET http://host[:port]/path HTTP/1.1`
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().ok()?),
        None => (authority.to_string(), 80),
    };
    Some(ProxyRequest {
        host,
        port,
        scheme: "http",
        method,
        path: path.to_string(),
        head,
    })
}

fn handle_connection(mut stream: TcpStream, state: Arc<GatewayState>) {
    let Some(request) = parse_request(&mut stream) else {
        return;
    };
    let refused = state.policy.refuses(&request.host, request.port);
    let intent = GatewayIntent {
        seq: 0,
        host: request.host.clone(),
        port: request.port,
        scheme: request.scheme.into(),
        method: request.method.clone(),
        path: request.path.clone(),
        decision: if refused { "refused" } else { "forwarded" }.into(),
    };
    if refused {
        state.record(intent);
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    match forward(&mut stream, &request, &state) {
        Ok(()) => state.record(intent),
        Err(_) => {
            state.record(GatewayIntent {
                decision: "forward-failed".into(),
                ..intent
            });
            let _ = stream.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn forward(
    client: &mut TcpStream,
    request: &ProxyRequest,
    state: &GatewayState,
) -> std::io::Result<()> {
    let mut server = match &state.upstream {
        // Chain through the host's own proxy: forward the original head
        // verbatim (a proxy expects CONNECT / absolute-form) and let its
        // response flow back through the splice.
        Some(upstream) => {
            let mut server = connect(&upstream.host, upstream.port)?;
            server.write_all(&request.head)?;
            server
        }
        // Direct: dial the destination ourselves.
        None => {
            let mut server = connect(&request.host, request.port)?;
            if request.scheme == "https" {
                // Tunnel established; tell the client to start TLS.
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            } else {
                // Rewrite the absolute-form first line to origin-form
                // and forward the rest of the head untouched.
                let first_end = request
                    .head
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .unwrap_or(request.head.len());
                let rewritten = format!("{} {} HTTP/1.1\r\n", request.method, request.path);
                server.write_all(rewritten.as_bytes())?;
                server.write_all(&request.head[first_end + 2..])?;
            }
            server
        }
    };
    splice(client, &mut server);
    Ok(())
}

fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("no address"))?;
    let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Copy bytes both ways until either side closes.
fn splice(client: &mut TcpStream, server: &mut TcpStream) {
    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut server_writer) = server.try_clone() else {
        return;
    };
    let uplink = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut server_writer);
        let _ = server_writer.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(server, client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = uplink.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn temp_log(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ovid-gw-{name}-{}.jsonl", std::process::id()))
    }

    fn request_via(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut response)
            .unwrap();
        response
    }

    #[test]
    fn deny_refuses_connect_and_records_the_identity() {
        let log = temp_log("deny-connect");
        let gateway = GatewayServer::start("127.0.0.1:0", GatewayPolicy::Deny, None, &log).unwrap();
        let response = request_via(
            gateway.port,
            "CONNECT llm.example.internal:443 HTTP/1.1\r\nHost: llm.example.internal:443\r\n\r\n",
        );
        assert!(response.contains("403"), "{response}");
        let intents = gateway.shutdown();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].host, "llm.example.internal");
        assert_eq!(intents[0].port, 443);
        assert_eq!(intents[0].scheme, "https");
        assert_eq!(intents[0].decision, "refused");
    }

    #[test]
    fn deny_records_plain_http_method_and_path() {
        let log = temp_log("deny-http");
        let gateway = GatewayServer::start("127.0.0.1:0", GatewayPolicy::Deny, None, &log).unwrap();
        let response = request_via(
            gateway.port,
            "POST http://api.example.internal/v1/telemetry HTTP/1.1\r\nHost: api.example.internal\r\n\r\n",
        );
        assert!(response.contains("403"), "{response}");
        let intents = gateway.shutdown();
        assert_eq!(intents[0].host, "api.example.internal");
        assert_eq!(intents[0].port, 80);
        assert_eq!(intents[0].scheme, "http");
        assert_eq!(intents[0].method, "POST");
        assert_eq!(intents[0].path, "/v1/telemetry");
    }

    /// A tiny one-shot TCP echo peer standing in for a real service.
    fn echo_server() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 256];
                if let Ok(n) = stream.read(&mut buffer) {
                    let _ = stream.write_all(&buffer[..n]);
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn forward_tunnels_connect_end_to_end() {
        let (echo_port, echo) = echo_server();
        let log = temp_log("forward");
        let gateway =
            GatewayServer::start("127.0.0.1:0", GatewayPolicy::Forward, None, &log).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", gateway.port)).unwrap();
        stream
            .write_all(format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(status.contains("200"), "{status}");
        let mut blank = String::new();
        reader.read_line(&mut blank).unwrap(); // end of gateway response
        stream.write_all(b"ping-through-tunnel").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut echoed = String::new();
        reader.get_mut().set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        reader.get_mut().read_to_string(&mut echoed).unwrap();
        assert_eq!(echoed, "ping-through-tunnel");
        echo.join().unwrap();
        let intents = gateway.shutdown();
        assert_eq!(intents[0].decision, "forwarded");
    }

    #[test]
    fn forward_except_blocks_exactly_the_named_dependency() {
        let (echo_port, echo) = echo_server();
        let log = temp_log("except");
        let blocked = BTreeSet::from(["blocked.example.internal".to_string()]);
        let gateway = GatewayServer::start(
            "127.0.0.1:0",
            GatewayPolicy::ForwardExcept(blocked),
            None,
            &log,
        )
        .unwrap();
        // The blocked host is refused...
        let response = request_via(
            gateway.port,
            "CONNECT blocked.example.internal:443 HTTP/1.1\r\n\r\n",
        );
        assert!(response.contains("403"), "{response}");
        // ...while another destination still forwards.
        let response = request_via(
            gateway.port,
            &format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n"),
        );
        assert!(response.contains("200"), "{response}");
        echo.join().unwrap();
        let intents = gateway.shutdown();
        assert_eq!(intents[0].decision, "refused");
        assert_eq!(intents[0].host, "blocked.example.internal");
        assert_eq!(intents[1].decision, "forwarded");
    }

    #[test]
    fn unreachable_destination_is_a_forward_failure_not_a_hang() {
        let log = temp_log("unreach");
        let gateway =
            GatewayServer::start("127.0.0.1:0", GatewayPolicy::Forward, None, &log).unwrap();
        // A port nothing listens on: refused fast by the kernel.
        let response = request_via(gateway.port, "CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n");
        assert!(response.contains("502"), "{response}");
        let intents = gateway.shutdown();
        assert_eq!(intents[0].decision, "forward-failed");
    }

    #[test]
    fn upstream_urls_with_credentials_are_rejected() {
        assert_eq!(
            Upstream::parse("http://proxy.corp:3128"),
            Some(Upstream {
                host: "proxy.corp".into(),
                port: 3128
            })
        );
        assert!(Upstream::parse("http://user:secret@proxy.corp:3128").is_none());
        assert!(Upstream::parse("https://proxy.corp:3128").is_none());
    }
}
