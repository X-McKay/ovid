//! End-to-end tests for the 0.2 surface: `prove`, `replay`, `inspect`,
//! `doctor`, and the remote-source safety gate — the real CLI over the
//! committed `prove-truth` fixture through the process laboratory.

use std::path::{Path, PathBuf};
use std::process::Command;

fn ovid_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ovid")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn run_ovid(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(ovid_bin())
        .args(args)
        .output()
        .expect("ovid binary runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn temp_out(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ovid-prove-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[cfg(unix)]
#[test]
fn prove_truth_fixture_reaches_a_verified_world() {
    let out = temp_out("truth");
    let fixture = fixtures().join("prove-truth");
    let (code, stdout, stderr) = run_ovid(&[
        "prove",
        fixture.to_str().unwrap(),
        "--workload",
        "test",
        "--out",
        out.to_str().unwrap(),
        "--timeout",
        "300",
    ]);
    assert_eq!(code, Some(0), "prove failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("stable (2/2 passed)"), "{stdout}");
    assert!(stdout.contains("verified"), "{stdout}");

    // proof.json is the primary machine projection.
    let proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("proof.json")).unwrap()).unwrap();
    assert_eq!(proof["api_version"], "ovid.dev/proof/v1alpha1");
    assert_eq!(proof["baseline"]["verdict"], "stable-passing");
    assert_eq!(proof["world"]["status"], "verified");
    assert_eq!(proof["scope"]["workload"], "test");
    assert_eq!(
        proof["provision"]["outcome"]["passed"], true,
        "provisioning (`make deps`) must have run and passed: {proof}"
    );
    // The scope names the observer and policies — conclusions are scoped,
    // never universal (proposal §2.2).
    assert!(proof["scope"]["observer"]
        .as_str()
        .unwrap()
        .contains("ovid-process-backend"));

    // The journal is the canonical record: typed events in the ledger.
    let ledger = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    for kind in [
        "journal:workload-selected",
        "journal:environment-prepared",
        "journal:snapshot-created",
        "journal:trial-completed",
        "journal:baseline-classified",
        "journal:world-synthesized",
        "journal:replay-completed",
    ] {
        assert!(ledger.contains(kind), "missing {kind} in evidence.jsonl");
    }

    // The lock's status reflects the domain outcome.
    let lock = std::fs::read_to_string(out.join("world.lock.yaml")).unwrap();
    assert!(lock.contains("status: verified"), "{lock}");

    // Trial workspaces are destroyed after their results are persisted;
    // only the frozen snapshot remains under .lab.
    let lab = out.join(".lab");
    if lab.exists() {
        for entry in std::fs::read_dir(&lab).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with("trial-"),
                "trial overlay {name} must be destroyed after persistence"
            );
        }
    }

    // Replay re-verifies the same bundle from clean state.
    let (code, stdout, stderr) = run_ovid(&["replay", out.to_str().unwrap(), "--timeout", "300"]);
    assert_eq!(code, Some(0), "replay failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("verified"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn remote_sources_never_execute_on_the_host_without_opt_in() {
    // The gate fires before any acquisition, so no network is touched.
    let (code, _stdout, stderr) = run_ovid(&[
        "prove",
        "https://github.com/example/never-fetched",
        "--workload",
        "test",
    ]);
    assert_ne!(code, Some(0));
    assert!(
        stderr.contains("--trusted-process") && stderr.contains("microsandbox"),
        "the refusal must name both remedies: {stderr}"
    );
}

#[test]
fn inspect_is_static_and_ranks_workloads() {
    let out = temp_out("inspect");
    let fixture = fixtures().join("prove-truth");
    let (code, stdout, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(0), "inspect failed:\n{stderr}");
    assert!(
        stdout.contains("workload candidates"),
        "inspect must rank workloads: {stdout}"
    );
    assert!(stdout.contains("make test"), "{stdout}");
    // Static only: provisioning must NOT have created data/seed.txt in
    // the fixture (inspect never executes repository code).
    assert!(!fixture.join("data").exists());
}

#[test]
fn doctor_reports_capabilities_with_remediation() {
    let (code, stdout, _stderr) = run_ovid(&["doctor"]);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("strace"));
    assert!(stdout.contains("user namespaces"));
    assert!(stdout.contains("msb"));
}
