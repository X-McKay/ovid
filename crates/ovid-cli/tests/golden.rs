//! Golden regression tests (spec §37.7).
//!
//! Inventory results for the committed fixtures are compared against
//! committed golden JSON files. Volatile fields (ids, timestamps, absolute
//! paths, digests of the workdir) are stripped before comparison so the
//! goldens are stable across machines.
//!
//! To regenerate after an intentional behavior change:
//! `UPDATE_GOLDENS=1 cargo test -p ovid-cli --test golden`

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// The stable projection of an inventory manifest.
fn normalized_inventory(fixture: &str) -> serde_json::Value {
    let out = std::env::temp_dir().join(format!("ovid-golden-{fixture}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let fixture_path = fixtures().join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_ovid"))
        .args(["inventory", fixture_path.to_str().unwrap(), "--out", out.to_str().unwrap()])
        .output()
        .expect("ovid runs");
    assert!(
        output.status.success(),
        "inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("ovid.json")).unwrap()).unwrap();
    serde_json::json!({
        "languages": manifest["inventory"]["languages"],
        "components": manifest["inventory"]["components"],
        "scanned_files": manifest["inventory"]["scanned_files"],
        "file_count": manifest["repository"]["file_count"],
    })
}

fn check_golden(fixture: &str) {
    let golden_path = fixtures().join("golden").join(format!("{fixture}.inventory.json"));
    let actual = normalized_inventory(fixture);
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        std::fs::write(&golden_path, serde_json::to_string_pretty(&actual).unwrap() + "\n")
            .unwrap();
        eprintln!("updated {}", golden_path.display());
        return;
    }
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
            panic!(
                "golden file {} missing — run UPDATE_GOLDENS=1 cargo test -p ovid-cli --test golden",
                golden_path.display()
            )
        }),
    )
    .unwrap();
    assert_eq!(
        actual, expected,
        "inventory output for fixture {fixture} drifted from its golden; \
         if the change is intentional, regenerate with UPDATE_GOLDENS=1"
    );
}

#[test]
fn golden_node_app() {
    check_golden("node-app");
}

#[test]
fn golden_python_app() {
    check_golden("python-app");
}

#[test]
fn golden_rust_service() {
    check_golden("rust-service");
}

#[test]
fn golden_network_caller() {
    check_golden("network-caller");
}
