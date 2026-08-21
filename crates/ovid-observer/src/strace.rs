//! strace-based observer: wraps a command under `strace -f` and parses the
//! output into normalized boundary events.
//!
//! The parser handles the syscalls that map onto the spec's initial event
//! set (§13.7): exec (including PATH-search `ENOENT` misses — the spec's
//! canonical missing-tool signal), file opens and misses, shared-object
//! loads, socket connect/bind/listen with IPv4/IPv6/Unix decoding, and
//! process exits. `<unfinished ...>`/`<... resumed>` pairs are stitched.

use crate::{BoundaryObserver, ObservationReport};
use ovid_core::{BoundaryEvent, EventEnvelope, IdGenerator, OvidId, ProcessIdentity, TrustTier};
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

/// Whether strace is available on this host.
pub fn strace_available() -> bool {
    std::process::Command::new("strace")
        .arg("-V")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub struct StraceObserver;

/// Syscalls traced. Kept minimal for overhead (§12.2): process, file, and
/// socket boundaries only. stat/access are included because every modern
/// shell and make performs PATH lookups with stat-family probes rather
/// than execve loops — a missing tool is visible *only* as a stat miss.
const TRACE_SET: &str = "execve,execveat,openat,open,creat,newfstatat,statx,access,faccessat,\
                         faccessat2,connect,bind,listen,socket,exit_group";

impl BoundaryObserver for StraceObserver {
    fn name(&self) -> &'static str {
        "ovid-strace-observer"
    }

    fn version(&self) -> &'static str {
        ovid_core::OVID_VERSION
    }

    fn wrap(&self, argv: &[String], output_path: &Path) -> Vec<String> {
        let mut wrapped = vec![
            "strace".to_string(),
            "-f".to_string(),  // follow children: the process tree is the unit
            "-qq".to_string(), // suppress attach/exit noise
            "-s".to_string(),
            "256".to_string(),
            "-o".to_string(),
            output_path.display().to_string(),
            "-e".to_string(),
            format!("trace={TRACE_SET}"),
        ];
        wrapped.extend(argv.iter().cloned());
        wrapped
    }

    fn collect(
        &self,
        output_path: &Path,
        run_id: &OvidId,
        ids: &IdGenerator,
    ) -> std::io::Result<ObservationReport> {
        let file = std::fs::File::open(output_path)?;
        let mut report = ObservationReport::default();
        let mut parser = Parser::default();
        for line in BufReader::new(file).lines() {
            let line = line?;
            report.raw_line_count += 1;
            match parser.parse_line(&line) {
                LineOutcome::Event(pid, event) => {
                    report.events.push(EventEnvelope {
                        event_id: ids.next("evidence"),
                        run_id: run_id.clone(),
                        sequence: report.events.len() as u64,
                        wall_time: Some(chrono::Utc::now()),
                        provider: self.name().to_string(),
                        provider_version: self.version().to_string(),
                        trust_tier: TrustTier::T2,
                        process: Some(ProcessIdentity {
                            pid,
                            parent_pid: None,
                            executable: parser.executables.get(&pid).cloned(),
                        }),
                        event,
                    });
                }
                LineOutcome::Ignored => {}
                LineOutcome::Unparsed => report.unparsed_lines += 1,
            }
        }
        Ok(report)
    }
}

enum LineOutcome {
    Event(u32, BoundaryEvent),
    Ignored,
    Unparsed,
}

#[derive(Default)]
struct Parser {
    /// Stitching buffer for `<unfinished ...>` lines, keyed by (pid, syscall).
    unfinished: HashMap<(u32, String), String>,
    /// (pid, fd) -> (address, port) from bind, consumed by listen.
    bound: HashMap<(u32, i32), (String, u16)>,
    /// pid -> last successfully exec'd executable.
    executables: HashMap<u32, String>,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static regex compiles")
}

fn regexes() -> &'static Regexes {
    static RE: OnceLock<Regexes> = OnceLock::new();
    RE.get_or_init(|| Regexes {
        execve: re(r#"^execve(?:at)?\((?:[^,]*,\s*)?"([^"]+)",\s*\[(.*?)\][^=]*=\s*(-?\d+)(?:\s+(\w+))?"#),
        open: re(r#"^(?:openat|open|creat)\((?:AT_FDCWD,\s*|[-\d]+(?:<[^>]*>)?,\s*)?"([^"]+)"(?:,\s*([A-Z_|]+))?[^=]*=\s*(-?\d+)(?:\s+(\w+))?"#),
        stat_miss: re(r#"^(?:newfstatat|statx|access|faccessat2?|faccessat)\((?:AT_FDCWD,\s*|[-\d]+(?:<[^>]*>)?,\s*)?"([^"]+)"[^=]*=\s*-\d+\s+(\w+)"#),
        inet: re(r#"sin6?_port=htons\((\d+)\)"#),
        inet_addr: re(r#"inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)""#),
        unix_path: re(r#"sun_path="([^"]+)""#),
        result: re(r#"\)\s*=\s*(-?\d+)(?:\s+(\w+))?"#),
        fd_prefix: re(r#"^(?:connect|bind|listen)\((\d+)"#),
        exited: re(r#"^\+\+\+ exited with (\d+) \+\+\+$"#),
        killed: re(r#"^\+\+\+ killed by (\w+)"#),
    })
}

struct Regexes {
    execve: Regex,
    open: Regex,
    stat_miss: Regex,
    inet: Regex,
    inet_addr: Regex,
    unix_path: Regex,
    result: Regex,
    fd_prefix: Regex,
    exited: Regex,
    killed: Regex,
}

impl Parser {
    fn parse_line(&mut self, raw: &str) -> LineOutcome {
        // With `-f -o file`, every line begins with the pid.
        let raw = raw.trim_end();
        let Some((pid_text, rest)) = raw.split_once(char::is_whitespace) else {
            return LineOutcome::Unparsed;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            return LineOutcome::Unparsed;
        };
        let rest = rest.trim_start();

        // Stitch unfinished/resumed pairs.
        if rest.ends_with("<unfinished ...>") {
            let syscall = rest.split('(').next().unwrap_or("").to_string();
            let body = rest.trim_end_matches("<unfinished ...>").to_string();
            self.unfinished.insert((pid, syscall), body);
            return LineOutcome::Ignored;
        }
        let rest_owned: String;
        let rest = if let Some(resumed) = rest.strip_prefix("<... ") {
            let syscall = resumed.split(' ').next().unwrap_or("").to_string();
            let Some(head) = self.unfinished.remove(&(pid, syscall)) else {
                return LineOutcome::Ignored;
            };
            let tail = resumed.split_once("resumed>").map(|(_, t)| t).unwrap_or("");
            rest_owned = format!("{head}{}", tail.trim_start_matches(' '));
            &rest_owned
        } else {
            rest
        };

        let r = regexes();

        if let Some(caps) = r.exited.captures(rest) {
            let code: i32 = caps[1].parse().unwrap_or(-1);
            return LineOutcome::Event(
                pid,
                BoundaryEvent::ProcessExited {
                    exit_code: code,
                    signal: None,
                },
            );
        }
        if r.killed.captures(rest).is_some() {
            return LineOutcome::Event(
                pid,
                BoundaryEvent::ProcessExited {
                    exit_code: -1,
                    signal: Some(9),
                },
            );
        }
        if rest.starts_with("---") {
            return LineOutcome::Ignored; // signal delivery notes
        }

        if let Some(caps) = r.execve.captures(rest) {
            let path = caps[1].to_string();
            let argv = parse_argv_list(&caps[2]);
            let code: i64 = caps[3].parse().unwrap_or(0);
            let errno = if code < 0 {
                caps.get(4).map(|m| m.as_str().to_string())
            } else {
                None
            };
            if errno.is_none() {
                self.executables.insert(pid, path.clone());
            }
            return LineOutcome::Event(pid, BoundaryEvent::ProcessExec { path, argv, errno });
        }

        if let Some(caps) = r.open.captures(rest) {
            let path = caps[1].to_string();
            let flags = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let code: i64 = caps[3].parse().unwrap_or(0);
            let errno = if code < 0 {
                caps.get(4).map(|m| m.as_str().to_string())
            } else {
                None
            };
            let write =
                flags.contains("O_WRONLY") || flags.contains("O_RDWR") || flags.contains("O_CREAT");
            if errno.is_none() && !write && is_shared_object(&path) {
                return LineOutcome::Event(pid, BoundaryEvent::SharedObjectMapped { path });
            }
            return LineOutcome::Event(pid, BoundaryEvent::FileOpened { path, errno, write });
        }

        // stat/access failures: PATH-scan misses and probed-but-absent
        // files. Successful stats are deliberately not events (volume);
        // failures are first-class (§6.2).
        if let Some(caps) = r.stat_miss.captures(rest) {
            return LineOutcome::Event(
                pid,
                BoundaryEvent::FileOpened {
                    path: caps[1].to_string(),
                    errno: Some(caps[2].to_string()),
                    write: false,
                },
            );
        }
        if rest.starts_with("newfstatat(")
            || rest.starts_with("statx(")
            || rest.starts_with("access(")
            || rest.starts_with("faccessat")
        {
            return LineOutcome::Ignored; // successful stat/access
        }

        if rest.starts_with("connect(") {
            let (result, errno) = self.call_result(rest);
            if let Some(caps) = r.unix_path.captures(rest) {
                return LineOutcome::Event(
                    pid,
                    BoundaryEvent::UnixSocketConnected {
                        path: caps[1].to_string(),
                        result: Some(errno.unwrap_or_else(|| result_label(result))),
                    },
                );
            }
            if let Some(port_caps) = r.inet.captures(rest) {
                let port: u16 = port_caps[1].parse().unwrap_or(0);
                let address = r
                    .inet_addr
                    .captures(rest)
                    .and_then(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_string()))
                    .unwrap_or_else(|| "unknown".to_string());
                return LineOutcome::Event(
                    pid,
                    BoundaryEvent::SocketConnect {
                        address,
                        port,
                        original_dns_name: None,
                        result: Some(errno.unwrap_or_else(|| result_label(result))),
                        protocol_hint: None,
                    },
                );
            }
            return LineOutcome::Ignored; // netlink and other families
        }

        if rest.starts_with("bind(") {
            if let (Some(fd_caps), Some(port_caps)) =
                (r.fd_prefix.captures(rest), r.inet.captures(rest))
            {
                let fd: i32 = fd_caps[1].parse().unwrap_or(-1);
                let port: u16 = port_caps[1].parse().unwrap_or(0);
                let address = r
                    .inet_addr
                    .captures(rest)
                    .and_then(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_string()))
                    .unwrap_or_else(|| "0.0.0.0".to_string());
                let (result, _) = self.call_result(rest);
                if result == 0 {
                    self.bound.insert((pid, fd), (address.clone(), port));
                    return LineOutcome::Event(pid, BoundaryEvent::SocketBound { address, port });
                }
            }
            return LineOutcome::Ignored;
        }

        if rest.starts_with("listen(") {
            if let Some(fd_caps) = r.fd_prefix.captures(rest) {
                let fd: i32 = fd_caps[1].parse().unwrap_or(-1);
                let (result, _) = self.call_result(rest);
                if result == 0 {
                    if let Some((address, port)) = self.bound.get(&(pid, fd)).cloned() {
                        return LineOutcome::Event(
                            pid,
                            BoundaryEvent::SocketListening { address, port },
                        );
                    }
                }
            }
            return LineOutcome::Ignored;
        }

        if rest.starts_with("socket(") || rest.starts_with("exit_group(") {
            return LineOutcome::Ignored;
        }

        LineOutcome::Unparsed
    }

    fn call_result(&self, rest: &str) -> (i64, Option<String>) {
        let r = regexes();
        match r.result.captures(rest) {
            Some(caps) => {
                let code: i64 = caps[1].parse().unwrap_or(0);
                let errno = if code < 0 {
                    caps.get(2).map(|m| m.as_str().to_string())
                } else {
                    None
                };
                (code, errno)
            }
            None => (0, None),
        }
    }
}

fn result_label(code: i64) -> String {
    if code >= 0 {
        "success".to_string()
    } else {
        "error".to_string()
    }
}

fn is_shared_object(path: &str) -> bool {
    path.ends_with(".so") || path.contains(".so.")
}

/// Parse strace's argv rendering: `"a", "b", "c"...` (possibly truncated).
fn parse_argv_list(list: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut rest = list;
    while let Some(start) = rest.find('"') {
        let Some(end) = rest[start + 1..].find('"') else {
            break;
        };
        args.push(rest[start + 1..start + 1 + end].to_string());
        rest = &rest[start + 2 + end..];
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::IdGenerator;

    fn collect_from(text: &str) -> ObservationReport {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.txt");
        std::fs::write(&path, text).unwrap();
        let ids = IdGenerator::deterministic();
        let run = ids.next("run");
        StraceObserver.collect(&path, &run, &ids).unwrap()
    }

    #[test]
    fn parses_exec_success_and_enoent() {
        let report = collect_from(concat!(
            "100   execve(\"/usr/bin/protoc\", [\"protoc\", \"--version\"], 0x7ffd /* 10 vars */) = -1 ENOENT (No such file or directory)\n",
            "100   execve(\"/usr/bin/cc\", [\"cc\"], 0x7ffd /* 10 vars */) = 0\n",
        ));
        assert_eq!(report.events.len(), 2);
        assert!(report.events[0].event.is_failure());
        match &report.events[0].event {
            BoundaryEvent::ProcessExec { path, argv, errno } => {
                assert_eq!(path, "/usr/bin/protoc");
                assert_eq!(argv, &["protoc", "--version"]);
                assert_eq!(errno.as_deref(), Some("ENOENT"));
            }
            other => panic!("wrong event: {other:?}"),
        }
        assert!(!report.events[1].event.is_failure());
    }

    #[test]
    fn parses_open_miss_write_and_shared_object() {
        let report = collect_from(concat!(
            "100   openat(AT_FDCWD, \"/usr/include/openssl/ssl.h\", O_RDONLY) = -1 ENOENT (No such file or directory)\n",
            "100   openat(AT_FDCWD, \"/lib/x86_64-linux-gnu/libssl.so.3\", O_RDONLY|O_CLOEXEC) = 3\n",
            "100   openat(AT_FDCWD, \"out.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4\n",
        ));
        match &report.events[0].event {
            BoundaryEvent::FileOpened { path, errno, write } => {
                assert_eq!(path, "/usr/include/openssl/ssl.h");
                assert_eq!(errno.as_deref(), Some("ENOENT"));
                assert!(!write);
            }
            other => panic!("wrong: {other:?}"),
        }
        assert!(matches!(
            &report.events[1].event,
            BoundaryEvent::SharedObjectMapped { path } if path.contains("libssl")
        ));
        assert!(matches!(
            &report.events[2].event,
            BoundaryEvent::FileOpened { write: true, .. }
        ));
    }

    #[test]
    fn parses_connect_refused_and_unix() {
        let report = collect_from(concat!(
            "200   connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 ECONNREFUSED (Connection refused)\n",
            "200   connect(4, {sa_family=AF_UNIX, sun_path=\"/run/db.sock\"}, 110) = 0\n",
            "200   connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"::1\", &sin6_addr), sin6_scope_id=0}, 28) = 0\n",
        ));
        match &report.events[0].event {
            BoundaryEvent::SocketConnect {
                address,
                port,
                result,
                ..
            } => {
                assert_eq!(address, "127.0.0.1");
                assert_eq!(*port, 5432);
                assert_eq!(result.as_deref(), Some("ECONNREFUSED"));
            }
            other => panic!("wrong: {other:?}"),
        }
        assert!(matches!(
            &report.events[1].event,
            BoundaryEvent::UnixSocketConnected { path, result }
                if path == "/run/db.sock" && result.as_deref() == Some("success")
        ));
        match &report.events[2].event {
            BoundaryEvent::SocketConnect { address, port, .. } => {
                assert_eq!(address, "::1");
                assert_eq!(*port, 443);
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn bind_listen_produces_listener_with_port() {
        let report = collect_from(concat!(
            "300   bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr(\"0.0.0.0\")}, 16) = 0\n",
            "300   listen(3, 128) = 0\n",
        ));
        assert!(matches!(
            &report.events[1].event,
            BoundaryEvent::SocketListening { port: 8080, .. }
        ));
    }

    #[test]
    fn stitches_unfinished_resumed() {
        let report = collect_from(concat!(
            "400   connect(7, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"10.0.0.9\")}, 16 <unfinished ...>\n",
            "401   openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3\n",
            "400   <... connect resumed>) = -1 ETIMEDOUT (Connection timed out)\n",
        ));
        let connect = report
            .events
            .iter()
            .find_map(|e| match &e.event {
                BoundaryEvent::SocketConnect { port, result, .. } => Some((*port, result.clone())),
                _ => None,
            })
            .expect("stitched connect event");
        assert_eq!(connect.0, 80);
        assert_eq!(connect.1.as_deref(), Some("ETIMEDOUT"));
    }

    #[test]
    fn stat_scan_misses_become_file_events() {
        let report = collect_from(concat!(
            "700   newfstatat(AT_FDCWD, \"/usr/local/bin/protoc\", 0x7ffec9c35ec0, 0) = -1 ENOENT (No such file or directory)\n",
            "700   access(\"/usr/bin/protoc\", X_OK) = -1 ENOENT (No such file or directory)\n",
            "700   statx(AT_FDCWD, \"/opt/bin/protoc\", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7ffd) = -1 ENOENT (No such file or directory)\n",
            "700   newfstatat(AT_FDCWD, \"/usr/bin/make\", {st_mode=S_IFREG|0755, st_size=1}, 0) = 0\n",
        ));
        // Three misses captured; the successful stat is ignored.
        assert_eq!(report.events.len(), 3);
        for envelope in &report.events {
            assert!(matches!(
                &envelope.event,
                BoundaryEvent::FileOpened { errno: Some(err), .. } if err == "ENOENT"
            ));
        }
        assert_eq!(report.unparsed_lines, 0);
    }

    #[test]
    fn exit_and_kill_lines() {
        let report = collect_from("500   +++ exited with 3 +++\n501   +++ killed by SIGKILL +++\n");
        assert!(matches!(
            &report.events[0].event,
            BoundaryEvent::ProcessExited {
                exit_code: 3,
                signal: None
            }
        ));
        assert!(matches!(
            &report.events[1].event,
            BoundaryEvent::ProcessExited {
                signal: Some(9),
                ..
            }
        ));
    }

    #[test]
    fn unparsed_lines_are_counted_not_lost() {
        let report = collect_from("600   prctl(PR_SET_NAME, \"x\") = 0\ngarbage line\n");
        assert_eq!(report.events.len(), 0);
        assert_eq!(report.unparsed_lines, 2);
        assert_eq!(report.raw_line_count, 2);
    }

    #[test]
    fn wrap_produces_strace_invocation() {
        let argv = vec!["cargo".to_string(), "test".to_string()];
        let wrapped = StraceObserver.wrap(&argv, Path::new("/tmp/out.trace"));
        assert_eq!(wrapped[0], "strace");
        assert!(wrapped.contains(&"-f".to_string()));
        assert!(wrapped
            .windows(2)
            .any(|w| w[0] == "-o" && w[1] == "/tmp/out.trace"));
        assert_eq!(&wrapped[wrapped.len() - 2..], &["cargo", "test"]);
    }
}
