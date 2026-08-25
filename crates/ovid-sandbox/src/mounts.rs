//! Mounted-network-filesystem discovery (spec §13.7, §18.2).
//!
//! Linux exposes the calling process's mount namespace through
//! `/proc/self/mountinfo`. The process laboratory shares that mount
//! namespace, so this is authoritative for paths its workload can reach.
//! Only NFS/NFSv4 entries are retained. Raw mount options are deliberately
//! not persisted because they can contain environment-specific or
//! credential-adjacent material.

use std::path::{Path, PathBuf};

/// One mounted NFS export visible to a workload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NfsMount {
    /// Local mount point in the workload's mount namespace.
    pub mount_point: PathBuf,
    /// NFS server identity, without user-info.
    pub server: String,
    /// Export path on the server.
    pub export: String,
    /// `nfs` or `nfs4`.
    pub fs_type: String,
    /// Whether the mount's VFS options are read-only.
    pub read_only: bool,
}

impl NfsMount {
    /// Stable dependency identity used by the causal domain.
    pub fn identity(&self) -> String {
        format!("{}:{}", self.server, self.export)
    }
}

/// Read NFS mounts visible to the current process.
///
/// Hosts without Linux mountinfo return an empty list honestly; callers
/// must not interpret that as proof that no remote storage exists.
pub fn discover_nfs_mounts() -> Vec<NfsMount> {
    if let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") {
        return parse_mountinfo(&text);
    }
    discover_nfs_mounts_from_command()
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn discover_nfs_mounts_from_command() -> Vec<NfsMount> {
    std::process::Command::new("/sbin/mount")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_mount_output(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn discover_nfs_mounts_from_command() -> Vec<NfsMount> {
    Vec::new()
}

/// Parse Linux `/proc/*/mountinfo`, defensively ignoring malformed and
/// non-NFS entries. Public for adapter contract tests and alternate mount
/// namespace providers.
pub fn parse_mountinfo(text: &str) -> Vec<NfsMount> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<&str> = left.split_whitespace().collect();
        let right_fields: Vec<&str> = right.split_whitespace().collect();
        if left_fields.len() < 6 || right_fields.len() < 2 {
            continue;
        }
        let fs_type = right_fields[0];
        if fs_type != "nfs" && fs_type != "nfs4" {
            continue;
        }
        let mount_point = PathBuf::from(unescape_mount_field(left_fields[4]));
        if !mount_point.is_absolute() {
            continue;
        }
        let source = unescape_mount_field(right_fields[1]);
        let Some((server, export)) = split_nfs_source(&source) else {
            continue;
        };
        let options = left_fields[5].split(',');
        mounts.push(NfsMount {
            mount_point,
            server,
            export,
            fs_type: fs_type.to_string(),
            read_only: options.into_iter().any(|option| option == "ro"),
        });
    }
    sort_and_dedup(&mut mounts);
    mounts
}

/// Parse the `mount` command's macOS/BSD format, with support for the
/// common Linux form as a testable fallback:
///
/// - `server:/export on /mnt/path (nfs, read-only, ...)`
/// - `server:/export on /mnt/path type nfs4 (ro,...)`
pub fn parse_mount_output(text: &str) -> Vec<NfsMount> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let Some((source, mounted)) = line.split_once(" on ") else {
            continue;
        };
        let parsed = if let Some((mount_point, typed)) = mounted.split_once(" type ") {
            // Defensive: tolerate a Linux-style fixture even though Linux
            // normally uses `/proc/self/mountinfo` above.
            let (fs_type, options) = typed.split_once(" (").unwrap_or((typed, ""));
            let options = options.strip_suffix(')').unwrap_or(options);
            Some((
                mount_point,
                fs_type.trim(),
                options.split(',').map(str::trim).collect(),
            ))
        } else if let Some((mount_point, options)) = mounted.rsplit_once(" (") {
            // BSD: filesystem type is the first parenthesized item.
            let options = options.strip_suffix(')').unwrap_or(options);
            let mut fields = options.split(',').map(str::trim);
            let fs_type = fields.next().unwrap_or_default();
            let flags: Vec<&str> = fields.collect();
            Some((mount_point, fs_type, flags))
        } else {
            None
        };
        let Some((mount_point, fs_type, flags)) = parsed else {
            continue;
        };
        if fs_type != "nfs" && fs_type != "nfs4" {
            continue;
        }
        let mount_point = PathBuf::from(unescape_mount_field(mount_point));
        let Some((server, export)) = split_nfs_source(&unescape_mount_field(source)) else {
            continue;
        };
        if !mount_point.is_absolute() {
            continue;
        }
        mounts.push(NfsMount {
            mount_point,
            server,
            export,
            fs_type: fs_type.to_string(),
            read_only: flags
                .iter()
                .any(|flag| *flag == "ro" || *flag == "read-only"),
        });
    }
    sort_and_dedup(&mut mounts);
    mounts
}

fn sort_and_dedup(mounts: &mut Vec<NfsMount>) {
    mounts.sort_by(|a, b| {
        b.mount_point
            .components()
            .count()
            .cmp(&a.mount_point.components().count())
            .then_with(|| a.mount_point.cmp(&b.mount_point))
    });
    mounts.dedup_by(|a, b| a.mount_point == b.mount_point && a.identity() == b.identity());
}

fn split_nfs_source(source: &str) -> Option<(String, String)> {
    let (server, export) = if let Some(rest) = source.strip_prefix('[') {
        let (server, export) = rest.split_once("]:")?;
        (server, export)
    } else {
        source.rsplit_once(':')?
    };
    let server = server
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(server);
    if server.is_empty() || export.is_empty() || !export.starts_with('/') {
        return None;
    }
    Some((server.to_string(), export.to_string()))
}

fn unescape_mount_field(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let octal = &bytes[index + 1..index + 4];
            if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                let decoded = (octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0');
                out.push(decoded);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Return the most-specific NFS mount containing `path`.
pub fn mount_for_path<'a>(path: &Path, mounts: &'a [NfsMount]) -> Option<&'a NfsMount> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.components().count())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "24 22 0:21 / / rw,relatime - ext4 /dev/root rw\n",
        "31 24 0:44 /models /mnt/shared\\040models ro,nosuid - nfs4 files.internal:/exports/models rw,vers=4.2\n",
        "32 24 0:45 / /mnt/shared\\040models/cache rw - nfs [2001:db8::8]:/cache rw,vers=3\n",
        "broken mountinfo line\n",
    );

    #[test]
    fn parses_nfs_mounts_and_unescapes_fields() {
        let mounts = parse_mountinfo(SAMPLE);
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            mounts[0].mount_point,
            PathBuf::from("/mnt/shared models/cache")
        );
        assert_eq!(mounts[0].server, "2001:db8::8");
        assert_eq!(mounts[0].export, "/cache");
        assert!(!mounts[0].read_only);
        assert_eq!(mounts[1].identity(), "files.internal:/exports/models");
        assert!(mounts[1].read_only);
    }

    #[test]
    fn most_specific_nested_mount_wins() {
        let mut mounts = parse_mountinfo(SAMPLE);
        mounts.reverse(); // callers need not pre-sort their mount list
        let mount = mount_for_path(Path::new("/mnt/shared models/cache/index.db"), &mounts)
            .expect("nested mount");
        assert_eq!(mount.export, "/cache");
        assert!(mount_for_path(Path::new("/tmp/local"), &mounts).is_none());
    }

    #[test]
    fn malformed_sources_and_non_nfs_are_ignored() {
        let text = concat!(
            "1 0 0:1 / /mnt rw - nfs not-an-export rw\n",
            "2 0 0:2 / relative rw - nfs server:/export rw\n",
            "3 0 0:3 / /data rw - ext4 server:/export rw\n",
        );
        assert!(parse_mountinfo(text).is_empty());
    }

    #[test]
    fn parses_macos_and_linux_mount_command_formats() {
        let text = concat!(
            "files.internal:/exports/models on /Volumes/shared models (nfs, nodev, read-only)\n",
            "[2001:db8::8]:/cache on /mnt/cache type nfs4 (rw,nosuid)\n",
            "/dev/disk3s1 on / (apfs, sealed, local)\n",
        );
        let mounts = parse_mount_output(text);
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            mounts[0].mount_point,
            PathBuf::from("/Volumes/shared models")
        );
        assert!(mounts[0].read_only);
        assert_eq!(mounts[1].server, "2001:db8::8");
        assert_eq!(mounts[1].fs_type, "nfs4");
    }
}
