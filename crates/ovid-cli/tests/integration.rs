//! End-to-end integration tests over the `ovid` binary and fixture
//! repositories (spec §37.1's fixture corpus).
//!
//! Each test runs the real CLI against a committed fixture and asserts on
//! the produced bundle: manifest contents, evidence-chain integrity, and
//! security properties (env scrubbing, source protection, deadlines).
//! The prove loop's causal behavior is additionally covered by the truth
//! scenarios in `ovid-application` and the end-to-end run in `prove.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn ovid_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ovid")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn run_ovid(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(ovid_bin())
        .args(args)
        .output()
        .expect("ovid binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn load_manifest(out: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(out.join("ovid.json")).expect("ovid.json exists");
    serde_json::from_str(&text).expect("manifest parses")
}

fn temp_out(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ovid-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn inspect_node_fixture_merges_declared_and_resolved() {
    let out = temp_out("node");
    let fixture = fixtures().join("node-app");
    let (ok, stdout, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inspect failed: {stderr}");
    assert!(stdout.contains("components:"));
    assert!(
        stdout.contains("workload candidates"),
        "inspect ranks workloads: {stdout}"
    );

    let manifest = load_manifest(&out);
    assert_eq!(manifest["analysis"]["mode"], "inspect");
    let components = manifest["inventory"]["components"].as_array().unwrap();
    let express = components
        .iter()
        .find(|c| c["name"] == "express" && c["version"] == "4.19.2")
        .expect("express merged entry");
    assert_eq!(express["states"]["declared"], true);
    assert_eq!(express["states"]["resolved"], true);
    assert!(
        components.iter().any(|c| c["name"] == "accepts"),
        "transitive dep present"
    );
    // Static inspection must never claim dynamic states (§6.3).
    for component in components {
        assert!(component["states"]["loaded"].is_null());
        assert!(component["states"]["exercised"].is_null());
    }
    // Lean bundle: manifest + ledger + claims. Standards exports render
    // on demand via `ovid export` (proposal §14.10).
    for file in ["ovid.yaml", "ovid.json", "evidence.jsonl", "claims.json"] {
        assert!(out.join(file).exists(), "{file} missing from bundle");
    }
    for file in ["cyclonedx.json", "spdx.json", "integration-plan.md"] {
        assert!(
            !out.join(file).exists(),
            "{file} must be lazy, not written on every run"
        );
    }
}

#[test]
fn export_renders_standards_projections_on_demand() {
    let out = temp_out("export");
    let fixture = fixtures().join("node-app");
    let (ok, _, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inspect failed: {stderr}");

    let (ok, stdout, _) = run_ovid(&[
        "export",
        "--from",
        out.to_str().unwrap(),
        "--format",
        "cyclonedx",
    ]);
    assert!(ok);
    assert!(stdout.contains("\"bomFormat\"") || stdout.contains("CycloneDX"));
    assert!(stdout.contains("express"));

    let (ok, stdout, _) = run_ovid(&[
        "export",
        "--from",
        out.to_str().unwrap(),
        "--format",
        "spdx",
    ]);
    assert!(ok);
    assert!(stdout.contains("express"));

    let (ok, _, stderr) = run_ovid(&[
        "export",
        "--from",
        out.to_str().unwrap(),
        "--format",
        "nonsense",
    ]);
    assert!(!ok);
    assert!(stderr.contains("unknown export format"));
}

#[test]
fn evidence_chain_verifies_after_inspection() {
    let out = temp_out("chain");
    let fixture = fixtures().join("python-app");
    let (ok, _, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inspect failed: {stderr}");
    let ledger = ovid_evidence::EvidenceLedger::open(out.join("evidence.jsonl")).unwrap();
    assert!(!ledger.is_empty());
    let head = ledger
        .verify_chain()
        .expect("chain verifies")
        .expect("chain head");
    let manifest = load_manifest(&out);
    assert_eq!(
        manifest["provenance"]["evidence_chain_head"]
            .as_str()
            .unwrap(),
        head.as_str(),
        "manifest provenance must publish the verified chain head"
    );
}

#[cfg(unix)]
#[test]
fn prove_missing_tool_reports_candidate_with_resolver_hint() {
    let out = temp_out("missingtool");
    let fixture = fixtures().join("missing-tool");
    let output = Command::new(ovid_bin())
        .args([
            "prove",
            fixture.to_str().unwrap(),
            "--workload",
            "test",
            "--packs-dir",
            fixture.join("packs").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--timeout",
            "120",
        ])
        .output()
        .unwrap();
    // The workload cannot pass (its tool is missing): exit code 20.
    assert_eq!(output.status.code(), Some(20));

    let proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("proof.json")).unwrap()).unwrap();
    assert_eq!(proof["baseline"]["verdict"], "stable-failing");
    let candidate = proof["executable_candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ovid-fixture-protoc")
        .expect("missing tool discovered as a candidate");
    assert_eq!(candidate["found"], false);
    assert!(
        candidate["resolver_hint"]
            .as_str()
            .unwrap()
            .contains("fixture-protoc-package"),
        "resolver pack hint surfaced as remediation: {candidate}"
    );
    // No causal label from a failing baseline — unresolved, honestly.
    let conclusion = proof["conclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["conclusion"])
        .find(|c| c["dependency"]["logical_identity"] == "ovid-fixture-protoc")
        .expect("candidate classified");
    assert_eq!(conclusion["necessity"], "unresolved");
    assert!(conclusion["reason"].as_str().unwrap().contains("baseline"));

    // The manifest projection carries the tool with its hint.
    let manifest = load_manifest(&out);
    let tools = manifest["build"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|t| t["name"] == "ovid-fixture-protoc")
        .expect("tool in manifest");
    assert_eq!(tool["discovered_by"], "failed-search");
    assert!(tool["candidate_package"]
        .as_str()
        .unwrap()
        .contains("fixture-protoc-package"));
    // The misses are first-class evidence in the ledger (§6.2).
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(ledger_text.contains("ovid-fixture-protoc"));
}

#[cfg(unix)]
#[test]
fn hostile_workload_cannot_read_secrets_or_tamper_source() {
    let out = temp_out("hostile");
    let fixture = fixtures().join("hostile");
    // Plant a canary secret in the parent environment; cap trials so no
    // hide-executable sweep runs (2 baseline + 1 replay).
    let output = Command::new(ovid_bin())
        .env("OVID_IT_SECRET_TOKEN", "super-secret-value")
        .args([
            "prove",
            fixture.to_str().unwrap(),
            "--workload",
            "steal",
            "--max-trials",
            "3",
            "--out",
            out.to_str().unwrap(),
            "--timeout",
            "120",
            "--",
            "sh",
            "steal.sh",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The fixture's grep found nothing: no bundle file ever contains the
    // canary value (spec: no secrets in outputs).
    for file in [
        "ovid.json",
        "ovid.yaml",
        "proof.json",
        "evidence.jsonl",
        "claims.json",
    ] {
        let text = std::fs::read_to_string(out.join(file)).unwrap();
        assert!(
            !text.contains("super-secret-value"),
            "secret leaked into {file}"
        );
    }
    // Trials run in snapshot forks: the fixture source tree is untouched.
    assert!(
        !fixture.join("tampered.txt").exists(),
        "hostile workload modified the source checkout"
    );
}

#[cfg(unix)]
#[test]
fn timeout_kills_workload_and_reports_failure() {
    let out = temp_out("timeout");
    let fixture = fixtures().join("hostile");
    let start = std::time::Instant::now();
    let output = Command::new(ovid_bin())
        .args([
            "prove",
            fixture.to_str().unwrap(),
            "--workload",
            "sleepy",
            "--baseline-runs",
            "1",
            "--max-trials",
            "1",
            "--no-replay",
            "--timeout",
            "2",
            "--out",
            out.to_str().unwrap(),
            "--",
            "sleep",
            "120",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(20), "workload failed => 20");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "deadline must be enforced"
    );
    let proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("proof.json")).unwrap()).unwrap();
    assert_eq!(
        proof["trials"][0]["outcome"]["failure_signature"],
        "timeout"
    );
}

#[test]
fn diff_detects_component_changes() {
    let before_dir = temp_out("diff-before");
    let after_dir = temp_out("diff-after");
    // Build two variants of a node repo in temp copies.
    let make_variant = |dir: &Path, version: &str| {
        std::fs::create_dir_all(dir.join("repo")).unwrap();
        std::fs::write(
            dir.join("repo/package.json"),
            r#"{"name":"x","dependencies":{"express":"^4"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("repo/package-lock.json"),
            format!(
                r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"x"}},"node_modules/express":{{"version":"{version}"}}}}}}"#
            ),
        )
        .unwrap();
        let (ok, _, stderr) = run_ovid(&[
            "inspect",
            dir.join("repo").to_str().unwrap(),
            "--out",
            dir.join("out").to_str().unwrap(),
        ]);
        assert!(ok, "{stderr}");
    };
    make_variant(&before_dir, "4.18.0");
    make_variant(&after_dir, "4.19.2");
    let (ok, stdout, _) = run_ovid(&[
        "diff",
        "--before",
        before_dir.join("out").to_str().unwrap(),
        "--after",
        after_dir.join("out").to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("4.18.0 -> 4.19.2"), "diff output: {stdout}");
}

#[test]
fn explain_returns_evidence_backed_claims() {
    let out = temp_out("explain");
    let fixture = fixtures().join("node-app");
    let (ok, _, _) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok);
    let (ok, stdout, stderr) = run_ovid(&["explain", "express", "--from", out.to_str().unwrap()]);
    assert!(ok, "explain failed: {stderr}");
    // Each printed explanation is a JSON document with resolved evidence.
    assert!(stdout.contains("supporting_evidence"), "{stdout}");
    assert!(stdout.contains("manifest-file-scanned"));
}

#[test]
fn packs_list_and_validate() {
    let (ok, stdout, _) = run_ovid(&["packs", "list"]);
    assert!(ok);
    assert!(stdout.contains("postgres"));
    assert!(stdout.contains("runner"));
    let dir = fixtures().join("missing-tool/packs");
    let (ok, _, stderr) = run_ovid(&["packs", "validate", dir.to_str().unwrap()]);
    assert!(ok, "fixture packs must validate: {stderr}");
}

#[test]
fn compose_services_appear_as_declared_external_systems() {
    let out = temp_out("compose");
    let fixture = fixtures().join("network-caller");
    let (ok, _, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inspect failed: {stderr}");
    let manifest = load_manifest(&out);
    let external = manifest["external_systems"].as_array().unwrap();

    // mailhog is declared in compose but never contacted: declared-only
    // record with classified protocol, zero attempts, no dynamic states.
    let mailhog = external
        .iter()
        .find(|s| s["id"] == "mailhog")
        .expect("declared-only service present");
    assert_eq!(mailhog["identity"], "declared");
    assert_eq!(mailhog["declared"], true);
    assert_eq!(mailhog["port"], 2525);
    assert_eq!(
        mailhog["protocol"], "smtp",
        "declared port classified via protocol pack"
    );
    assert_eq!(mailhog["attempts"], 0);
    assert!(
        mailhog["causality"].is_null(),
        "declaration alone earns no causality"
    );
    assert!(mailhog["treatment"]
        .as_str()
        .unwrap()
        .contains("declared-image:mailhog/mailhog"));
    let postgres_declared = external.iter().find(|s| s["id"] == "postgres").unwrap();
    assert_eq!(postgres_declared["identity"], "declared");

    // Declares claims recorded with evidence.
    let claims_text = std::fs::read_to_string(out.join("claims.json")).unwrap();
    assert!(claims_text.contains("service:mailhog"));
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(ledger_text.contains("compose-service-declared"));
}

#[test]
fn declared_endpoints_and_env_indirection_are_reported() {
    let out = temp_out("endpoints");
    let fixture = fixtures().join("declared-endpoints");
    let (ok, _, stderr) = run_ovid(&[
        "inspect",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inspect failed: {stderr}");
    let manifest = load_manifest(&out);
    let external = manifest["external_systems"].as_array().unwrap();

    // Literal config URL: declared-only record with scheme-derived
    // protocol, pack-derived default port, path, and the credential env
    // *name* from the sibling `api_key_env` key.
    let model = external
        .iter()
        .find(|s| s["id"] == "models.fixture-lab.dev:443")
        .expect("declared endpoint present: {external:?}");
    assert_eq!(model["identity"], "declared");
    assert_eq!(model["declared"], true);
    assert_eq!(model["protocol"], "https");
    assert_eq!(model["port"], 443, "default port from the https pack");
    assert_eq!(model["url_path"], "/v1");
    assert_eq!(model["attempts"], 0);
    assert!(
        model["causality"].is_null(),
        "declaration earns no causality"
    );
    assert_eq!(model["credential_env"][0], "FIXTURE_MODEL_KEY");
    assert!(model["declared_sources"][0]
        .as_str()
        .unwrap()
        .contains("config/inference.yaml (model_endpoint.base_url)"));

    // Env-parameterized endpoints: connectivity is declared even though
    // the host is bound at runtime; scheme/path context is preserved.
    let telemetry = external
        .iter()
        .find(|s| s["id"] == "env:TELEMETRY_HOST")
        .expect("env-parameterized endpoint present");
    assert_eq!(telemetry["identity"], "env-parameterized");
    assert_eq!(telemetry["env_var"], "TELEMETRY_HOST");
    assert_eq!(telemetry["protocol"], "https");
    assert_eq!(telemetry["url_path"], "/ingest");
    assert!(external.iter().any(|s| s["id"] == "env:FIXTURE_DB_HOST"));

    // Source-mined env reads (T5): captured with template context and
    // shipped defaults; non-endpoint vars (LOG_LEVEL) are not.
    let inference = external
        .iter()
        .find(|s| s["id"] == "env:INFERENCE_HOST")
        .expect("source-mined endpoint present");
    assert_eq!(inference["url_path"], "/v2/complete");
    assert!(inference["declared_sources"][0]
        .as_str()
        .unwrap()
        .contains("client.py"));
    let model_url = external
        .iter()
        .find(|s| s["id"] == "env:MODEL_URL")
        .expect("getenv default captured");
    assert_eq!(model_url["port"], 8080);
    assert!(!external.iter().any(|s| s["id"] == "env:LOG_LEVEL"));

    // A template-placeholder host (all-caps convention) is flagged, not
    // asserted as a real name.
    let mirror = external
        .iter()
        .find(|s| s["id"] == "REPLACE-WITH-MIRROR-HOST:8000")
        .expect("placeholder endpoint present");
    assert_eq!(mirror["identity"], "template-placeholder");
    assert!(
        mirror["dns_name"].is_null(),
        "placeholder is not a DNS name"
    );
    assert_eq!(mirror["port"], 8000);

    // Env-parameterized and placeholder endpoints are unresolved (host
    // unknown by construction), never guessed (§6.6).
    let unresolved = manifest["unresolved"].as_array().unwrap();
    assert!(unresolved.iter().any(|u| u["id"] == "env:TELEMETRY_HOST"
        && u["reason"]
            .as_str()
            .unwrap()
            .contains("bound at runtime from env var TELEMETRY_HOST")));
    assert!(unresolved
        .iter()
        .any(|u| u["id"] == "REPLACE-WITH-MIRROR-HOST:8000"
            && u["reason"]
                .as_str()
                .unwrap()
                .contains("template placeholder")));

    // Ledger + claims carry the declarations with the right tiers.
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(ledger_text.contains("endpoint-declared"));
    let claims_text = std::fs::read_to_string(out.join("claims.json")).unwrap();
    assert!(claims_text.contains("service:models.fixture-lab.dev"));
    assert!(claims_text.contains("service:env:INFERENCE_HOST"));
}
