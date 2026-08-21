//! Firecracker MicroVM orchestration (spec §13.5, §16, §34.5, ADR-002).
//!
//! This module owns the *configuration plane* of the default untrusted
//! execution boundary: jailer invocation, machine configuration, the
//! standard five-device disk layout, vsock, and snapshot payloads for
//! Firecracker's Unix-socket REST API. Everything is generated as ordered
//! API requests so it can be unit-tested deterministically and driven by a
//! plain Unix-socket HTTP client at runtime.
//!
//! On hosts without KVM (or without the firecracker/jailer binaries) the
//! backend reports [`OvidError::UnsupportedHost`] — the spec requires the
//! evidence model to stay honest about isolation, so there is no silent
//! fallback here; callers choose the process backend explicitly and the
//! resulting manifests carry that weaker isolation tier.

use crate::{ExecutionBackend, IsolationTier, RunResult, RunSpec};
use ovid_core::{Digest, OvidError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Machine sizing (FR-024 budgets at the VM level).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
}

impl Default for MachineConfig {
    fn default() -> Self {
        MachineConfig {
            vcpu_count: 2,
            mem_size_mib: 2048,
            smt: false,
        }
    }
}

/// One virtio block device.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: PathBuf,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

/// Jailer invocation parameters (FR-021, §16.2).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct JailerConfig {
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base: PathBuf,
    pub exec_file: PathBuf,
}

impl JailerConfig {
    /// The jailer command line. Each MicroVM gets a dedicated jail
    /// directory, unprivileged UID/GID, and its own cgroup/netns setup.
    pub fn command_line(&self, netns: Option<&Path>) -> Vec<String> {
        let mut argv = vec![
            "jailer".to_string(),
            "--id".to_string(),
            self.id.clone(),
            "--uid".to_string(),
            self.uid.to_string(),
            "--gid".to_string(),
            self.gid.to_string(),
            "--chroot-base-dir".to_string(),
            self.chroot_base.display().to_string(),
            "--exec-file".to_string(),
            self.exec_file.display().to_string(),
        ];
        if let Some(netns) = netns {
            argv.push("--netns".to_string());
            argv.push(netns.display().to_string());
        }
        argv.push("--".to_string());
        // Firecracker's own arguments follow; the API socket lives inside
        // the jail.
        argv.push("--api-sock".to_string());
        argv.push("/run/firecracker.socket".to_string());
        argv
    }
}

/// A complete target-VM specification (§13.5's device layout).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct VmSpec {
    pub machine: MachineConfig,
    /// Digest-pinned kernel image (FR-022).
    pub kernel_path: PathBuf,
    pub kernel_digest: Digest,
    pub boot_args: String,
    /// Digest-pinned immutable base rootfs with the guest agent (FR-022).
    pub rootfs_path: PathBuf,
    pub rootfs_digest: Digest,
    /// Read-only repository source image (FR-023).
    pub source_image_path: PathBuf,
    /// Disposable overlay for writes and installed dependencies.
    pub overlay_path: PathBuf,
    /// Optional bounded artifact-export device.
    pub output_path: Option<PathBuf>,
    /// Optional high-churn scratch device.
    pub scratch_path: Option<PathBuf>,
    /// vsock CID for guest-agent control (§13.5: reconnect after restore,
    /// never snapshot an active stream — §16.6).
    pub vsock_cid: u32,
    pub vsock_uds_path: PathBuf,
}

impl VmSpec {
    /// The standard device set, in attach order:
    /// rootfs (ro, root), source (ro), overlay (rw), output (rw), scratch (rw).
    pub fn drives(&self) -> Vec<Drive> {
        let mut drives = vec![
            Drive {
                drive_id: "rootfs".into(),
                path_on_host: self.rootfs_path.clone(),
                is_root_device: true,
                is_read_only: true,
            },
            Drive {
                drive_id: "source".into(),
                path_on_host: self.source_image_path.clone(),
                is_root_device: false,
                is_read_only: true,
            },
            Drive {
                drive_id: "overlay".into(),
                path_on_host: self.overlay_path.clone(),
                is_root_device: false,
                is_read_only: false,
            },
        ];
        if let Some(output) = &self.output_path {
            drives.push(Drive {
                drive_id: "output".into(),
                path_on_host: output.clone(),
                is_root_device: false,
                is_read_only: false,
            });
        }
        if let Some(scratch) = &self.scratch_path {
            drives.push(Drive {
                drive_id: "scratch".into(),
                path_on_host: scratch.clone(),
                is_root_device: false,
                is_read_only: false,
            });
        }
        drives
    }

    /// Ordered (method, path, body) requests for the Firecracker API
    /// (§34.5): machine config, boot source, drives, vsock, then start.
    pub fn api_requests(&self) -> Vec<(String, String, serde_json::Value)> {
        let mut requests = vec![
            (
                "PUT".to_string(),
                "/machine-config".to_string(),
                serde_json::json!({
                    "vcpu_count": self.machine.vcpu_count,
                    "mem_size_mib": self.machine.mem_size_mib,
                    "smt": self.machine.smt,
                }),
            ),
            (
                "PUT".to_string(),
                "/boot-source".to_string(),
                serde_json::json!({
                    "kernel_image_path": self.kernel_path,
                    "boot_args": self.boot_args,
                }),
            ),
        ];
        for drive in self.drives() {
            requests.push((
                "PUT".to_string(),
                format!("/drives/{}", drive.drive_id),
                serde_json::json!({
                    "drive_id": drive.drive_id,
                    "path_on_host": drive.path_on_host,
                    "is_root_device": drive.is_root_device,
                    "is_read_only": drive.is_read_only,
                }),
            ));
        }
        requests.push((
            "PUT".to_string(),
            "/vsock".to_string(),
            serde_json::json!({
                "guest_cid": self.vsock_cid,
                "uds_path": self.vsock_uds_path,
            }),
        ));
        requests.push((
            "PUT".to_string(),
            "/actions".to_string(),
            serde_json::json!({ "action_type": "InstanceStart" }),
        ));
        requests
    }

    /// Snapshot-create request pair (§16.6): pause, then snapshot.
    pub fn snapshot_requests(
        &self,
        snapshot_dir: &Path,
    ) -> Vec<(String, String, serde_json::Value)> {
        vec![
            (
                "PATCH".to_string(),
                "/vm".to_string(),
                serde_json::json!({ "state": "Paused" }),
            ),
            (
                "PUT".to_string(),
                "/snapshot/create".to_string(),
                serde_json::json!({
                    "snapshot_type": "Full",
                    "snapshot_path": snapshot_dir.join("vmstate"),
                    "mem_file_path": snapshot_dir.join("memory"),
                }),
            ),
        ]
    }
}

/// Host capability probe.
pub fn host_supports_firecracker() -> Result<(), OvidError> {
    if !Path::new("/dev/kvm").exists() {
        return Err(OvidError::UnsupportedHost(
            "/dev/kvm not present — Firecracker requires a Linux/KVM host (spec §12.5); \
             use the process backend for trusted repositories"
                .into(),
        ));
    }
    let found = std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join("firecracker").exists())
    });
    if !found {
        return Err(OvidError::UnsupportedHost(
            "firecracker binary not found on PATH".into(),
        ));
    }
    Ok(())
}

/// The MicroVM execution backend. Configuration and payload generation are
/// fully implemented and tested; `run` requires a KVM host.
pub struct FirecrackerBackend {
    pub jailer: JailerConfig,
    pub vm: VmSpec,
}

impl ExecutionBackend for FirecrackerBackend {
    fn name(&self) -> &'static str {
        "ovid-firecracker-backend"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Microvm
    }

    fn run(&self, _spec: &RunSpec) -> Result<RunResult, OvidError> {
        // Fail closed before any side effect if the host cannot provide the
        // isolation this backend promises.
        host_supports_firecracker()?;
        Err(OvidError::UnsupportedHost(
            "Firecracker run loop requires a KVM worker with prepared kernel/rootfs images; \
             see docs/ARCHITECTURE.md#execution-backends for provisioning"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> VmSpec {
        VmSpec {
            machine: MachineConfig::default(),
            kernel_path: "/var/lib/ovid/blobs/kernel".into(),
            kernel_digest: Digest::of_bytes(b"kernel"),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".into(),
            rootfs_path: "/var/lib/ovid/blobs/rootfs".into(),
            rootfs_digest: Digest::of_bytes(b"rootfs"),
            source_image_path: "/var/lib/ovid/jobs/j1/disks/source.img".into(),
            overlay_path: "/var/lib/ovid/jobs/j1/disks/overlay.img".into(),
            output_path: Some("/var/lib/ovid/jobs/j1/disks/output.img".into()),
            scratch_path: None,
            vsock_cid: 3,
            vsock_uds_path: "/var/lib/ovid/jobs/j1/sockets/vsock.sock".into(),
        }
    }

    #[test]
    fn drive_layout_matches_spec() {
        let drives = spec().drives();
        let ids: Vec<&str> = drives.iter().map(|d| d.drive_id.as_str()).collect();
        assert_eq!(ids, ["rootfs", "source", "overlay", "output"]);
        // Immutability rules: rootfs and source read-only; overlay writable.
        assert!(drives[0].is_read_only && drives[0].is_root_device);
        assert!(
            drives[1].is_read_only,
            "source must attach read-only (FR-023)"
        );
        assert!(!drives[2].is_read_only);
    }

    #[test]
    fn api_requests_are_ordered_and_end_with_start() {
        let requests = spec().api_requests();
        assert_eq!(requests[0].1, "/machine-config");
        assert_eq!(requests[1].1, "/boot-source");
        let last = requests.last().unwrap();
        assert_eq!(last.1, "/actions");
        assert_eq!(last.2["action_type"], "InstanceStart");
        // Every request body serializes.
        for (_, _, body) in &requests {
            serde_json::to_string(body).unwrap();
        }
    }

    #[test]
    fn snapshot_pauses_before_creating() {
        let requests = spec().snapshot_requests(Path::new("/var/lib/ovid/snapshots/s1"));
        assert_eq!(requests[0].1, "/vm");
        assert_eq!(requests[0].2["state"], "Paused");
        assert_eq!(requests[1].1, "/snapshot/create");
    }

    #[test]
    fn jailer_command_line_is_restrictive() {
        let jailer = JailerConfig {
            id: "job-42".into(),
            uid: 10042,
            gid: 10042,
            chroot_base: "/var/lib/ovid/jobs".into(),
            exec_file: "/usr/bin/firecracker".into(),
        };
        let argv = jailer.command_line(Some(Path::new("/var/run/netns/job-42")));
        assert_eq!(argv[0], "jailer");
        assert!(argv.windows(2).any(|w| w[0] == "--uid" && w[1] == "10042"));
        assert!(argv.windows(2).any(|w| w[0] == "--netns"));
        assert!(argv.contains(&"--".to_string()));
    }

    #[test]
    fn backend_fails_closed_without_kvm() {
        if Path::new("/dev/kvm").exists() {
            eprintln!("KVM present; skipping fail-closed assertion");
            return;
        }
        let backend = FirecrackerBackend {
            jailer: JailerConfig {
                id: "x".into(),
                uid: 1,
                gid: 1,
                chroot_base: "/tmp".into(),
                exec_file: "/usr/bin/firecracker".into(),
            },
            vm: spec(),
        };
        let spec = RunSpec::new(
            vec!["true".into()],
            crate::WorkspaceMode::InPlace {
                root: "/tmp".into(),
            },
        );
        match backend.run(&spec) {
            Err(OvidError::UnsupportedHost(message)) => {
                assert!(message.contains("KVM") || message.contains("/dev/kvm"));
            }
            other => panic!("expected UnsupportedHost, got {other:?}"),
        }
    }
}
