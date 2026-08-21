//! End-to-end integration tests over the `ovid` binary and fixture
//! repositories (spec §37.1's fixture corpus, local-mode scope).
//!
//! Each test runs the real CLI against a committed fixture and asserts on
//! the produced bundle: manifest contents, evidence-chain integrity, and
//! security properties (env scrubbing, source protection, deadlines).

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
fn inventory_node_fixture_merges_declared_and_resolved() {
    let out = temp_out("node");
    let fixture = fixtures().join("node-app");
    let (ok, stdout, stderr) = run_ovid(&[
        "inventory",
        fixture.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "inventory failed: {stderr}");
    assert!(stdout.contains("components:"));

    let manifest = load_manifest(&out);
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
    // Static inventory must never claim dynamic states (§6.3).
    for component in components {
        assert!(component["states"]["loaded"].is_null());
        assert!(component["states"]["exercised"].is_null());
    }
    // Full bundle written.
    for file in [
        "ovid.yaml",
        "cyclonedx.json",
        "spdx.json",
        "integration-plan.md",
        "evidence.jsonl",
        "claims.json",
    ] {
        assert!(out.join(file).exists(), "{file} missing from bundle");
    }
    assert!(
        !out.join("provenance.json").exists(),
        "provenance lives in the manifest, not a duplicate file"
    );
}

#[test]
fn observe_python_fixture_finds_optional_database() {
    let out = temp_out("python");
    let fixture = fixtures().join("python-app");
    let (ok, _, stderr) = run_ovid(&[
        "observe",
        fixture.to_str().unwrap(),
        "--run",
        "python3 app.py",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "observe failed: {stderr}");

    let manifest = load_manifest(&out);
    assert_eq!(manifest["workloads"][0]["status"], "passed");
    let external = manifest["external_systems"].as_array().unwrap();
    let db = external
        .iter()
        .find(|s| s["port"] == 5432)
        .expect("postgres attempt observed");
    assert_eq!(db["protocol"], "postgresql");
    // Workload succeeded while the database was unavailable: natural
    // counterfactual => optional.
    assert_eq!(db["causality"], "optional");
    assert!(db["failures"].as_u64().unwrap() >= 1);
    assert!(
        !db["evidence"].as_array().unwrap().is_empty(),
        "external claims link evidence"
    );

    // Declared python deps present from pyproject/requirements.
    let components = manifest["inventory"]["components"].as_array().unwrap();
    assert!(components.iter().any(|c| c["name"] == "requests"));
    assert!(components.iter().any(|c| c["name"] == "psycopg2-binary"));
}

#[test]
fn evidence_chain_verifies_after_analysis() {
    let out = temp_out("chain");
    let fixture = fixtures().join("python-app");
    let (ok, _, stderr) = run_ovid(&[
        "observe",
        fixture.to_str().unwrap(),
        "--run",
        "python3 app.py",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "observe failed: {stderr}");
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

#[test]
fn analyze_missing_tool_fixture_proposes_resolver_candidate() {
    let out = temp_out("missingtool");
    let fixture = fixtures().join("missing-tool");
    let (ok, stdout, stderr) = run_ovid(&[
        "analyze",
        fixture.to_str().unwrap(),
        "--workloads",
        "test",
        "--packs-dir",
        fixture.join("packs").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "analyze failed: {stderr}");
    let manifest = load_manifest(&out);
    assert_eq!(manifest["workloads"][0]["status"], "failed");
    // The missing tool is discovered from PATH-scan misses and matched to
    // the fixture resolver pack's trusted candidate (MVP criterion 4's
    // discovery half; installation requires a provisioned world).
    let tools = manifest["build"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|t| t["name"] == "ovid-fixture-protoc")
        .unwrap_or_else(|| {
            panic!(
                "missing tool not reported: {stdout}\n{:?}",
                manifest["build"]
            )
        });
    assert_eq!(tool["discovered_by"], "failed-exec");
    assert_eq!(
        tool["candidate_package"],
        "fixture-provider:fixture-protoc-package"
    );
    // The misses are first-class evidence in the ledger (§6.2).
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(ledger_text.contains("ovid-fixture-protoc"));
    assert!(ledger_text.contains("ENOENT"));
    // A requires claim links workload to the tool.
    let claims_text = std::fs::read_to_string(out.join("claims.json")).unwrap();
    assert!(claims_text.contains("tool:ovid-fixture-protoc"));
}

#[test]
fn analyze_network_fixture_synthesizes_world_with_service_packs() {
    let out = temp_out("network");
    let fixture = fixtures().join("network-caller");
    let (ok, stdout, stderr) = run_ovid(&[
        "analyze",
        fixture.to_str().unwrap(),
        "--workloads",
        "test",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "analyze failed: {stderr}\n{stdout}");
    let manifest = load_manifest(&out);
    assert_eq!(manifest["workloads"][0]["status"], "passed", "{stdout}");

    let external = manifest["external_systems"].as_array().unwrap();
    let ports: Vec<u64> = external
        .iter()
        .map(|s| s["port"].as_u64().unwrap())
        .collect();
    assert!(
        ports.contains(&5432) && ports.contains(&6379),
        "both services observed: {ports:?}"
    );

    // World synthesis proposes real service cells for classified protocols.
    assert_eq!(manifest["world"]["status"], "proposed");
    let dependencies = manifest["world"]["dependencies"].as_array().unwrap();
    assert!(dependencies.iter().any(|d| d["treatment"]
        .as_str()
        .unwrap()
        .contains("service-pack:postgres")));
    assert!(dependencies.iter().any(|d| d["treatment"]
        .as_str()
        .unwrap()
        .contains("service-pack:redis")));

    // Lock + compose written; compose contains the postgres image.
    assert!(out.join("world.lock.yaml").exists());
    let compose = std::fs::read_to_string(out.join("compose.yaml")).unwrap();
    assert!(
        compose.contains("postgres@sha256"),
        "compose must pin service images: {compose}"
    );

    // World export via CLI.
    let (ok, compose_out, _) = run_ovid(&[
        "world",
        "export",
        "--from",
        out.to_str().unwrap(),
        "--format",
        "compose",
    ]);
    assert!(ok);
    assert!(compose_out.contains("postgres"));
}

#[test]
fn hostile_fixture_cannot_read_secrets_or_tamper_source() {
    let out = temp_out("hostile");
    let fixture = fixtures().join("hostile");
    // Plant a canary secret in the parent environment.
    let output = Command::new(ovid_bin())
        .env("OVID_IT_SECRET_TOKEN", "super-secret-value")
        .args([
            "observe",
            fixture.to_str().unwrap(),
            "--run",
            "sh steal.sh",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let manifest = load_manifest(&out);
    assert_eq!(manifest["workloads"][0]["status"], "passed");
    // The fixture's grep found nothing: manifest and ledger never contain
    // the canary value.
    for file in ["ovid.json", "evidence.jsonl", "claims.json"] {
        let text = std::fs::read_to_string(out.join(file)).unwrap();
        assert!(
            !text.contains("super-secret-value"),
            "secret leaked into {file}"
        );
    }
    // Ephemeral workspace: the fixture source tree is untouched.
    assert!(
        !fixture.join("tampered.txt").exists(),
        "hostile workload modified the source checkout"
    );
}

#[test]
fn timeout_kills_workload_and_reports_failure() {
    let out = temp_out("timeout");
    let fixture = fixtures().join("hostile");
    let start = std::time::Instant::now();
    let (ok, stdout, _) = run_ovid(&[
        "observe",
        fixture.to_str().unwrap(),
        "--run",
        "sleep 120",
        "--timeout",
        "2",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "CLI itself should succeed; the workload fails");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "deadline must be enforced"
    );
    let manifest = load_manifest(&out);
    assert_eq!(manifest["workloads"][0]["status"], "failed", "{stdout}");
}

#[test]
fn diff_detects_component_changes() {
    let before_dir = temp_out("diff-before");
    let after_dir = temp_out("diff-after");
    // Build two variants of the node fixture in temp copies.
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
            "inventory",
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
        "inventory",
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
    assert!(stdout.contains("rust@1.0.0"));
    assert!(stdout.contains("postgres@1.0.0"));

    let dir = temp_out("packs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("bad.yaml"),
        "api_version: wrong\nkind: runner-recipe\nmetadata: {name: bad}\ndetect: {}\n",
    )
    .unwrap();
    let (ok, _, stderr) = run_ovid(&["packs", "validate", dir.to_str().unwrap()]);
    assert!(!ok, "invalid pack must fail validation");
    assert!(stderr.contains("api_version"), "{stderr}");
}

#[test]
fn counterfactual_env_classifies_required_variable() {
    let out = temp_out("cfenv");
    let dir = temp_out("cfenv-repo");
    std::fs::create_dir_all(&dir).unwrap();
    // Workload requires OVID_IT_MODE; Makefile provides the test command.
    std::fs::write(
        dir.join("Makefile"),
        "test:\n\t@test -n \"$$OVID_IT_MODE\"\n",
    )
    .unwrap();
    let output = Command::new(ovid_bin())
        .env("OVID_IT_MODE", "enabled")
        .args([
            "analyze",
            dir.to_str().unwrap(),
            "--workloads",
            "test",
            "--inherit-env",
            "OVID_IT_MODE",
            "--counterfactual-env",
            "OVID_IT_MODE",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(
        ledger_text.contains("remove-env:OVID_IT_MODE") && ledger_text.contains("\"required\""),
        "counterfactual experiment must record Required classification"
    );
    let claims_text = std::fs::read_to_string(out.join("claims.json")).unwrap();
    assert!(claims_text.contains("environment:OVID_IT_MODE"));
}

#[test]
fn tomography_runs_offline_online_pair_and_classifies() {
    let out = temp_out("tomography");
    let fixture = fixtures().join("network-caller");
    let (ok, stdout, stderr) = run_ovid(&[
        "tomography",
        fixture.to_str().unwrap(),
        "--workloads",
        "test",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "tomography failed: {stderr}\n{stdout}");
    let manifest = load_manifest(&out);
    assert_eq!(manifest["analysis"]["mode"], "tomography");

    // Both runs are recorded as workloads and both pass (the fixture
    // tolerates its unavailable loopback dependencies).
    let workloads = manifest["workloads"].as_array().unwrap();
    let names: Vec<&str> = workloads
        .iter()
        .map(|w| w["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"test-offline") && names.contains(&"test-online"),
        "{names:?}"
    );
    assert!(
        workloads.iter().all(|w| w["status"] == "passed"),
        "{workloads:?}"
    );

    // Loopback services refused in both runs + workload passed offline:
    // the natural counterfactual classifies them optional.
    let external = manifest["external_systems"].as_array().unwrap();
    let db = external
        .iter()
        .find(|s| s["port"] == 5432)
        .expect("postgres observed");
    assert_eq!(db["causality"], "optional");
    assert_eq!(db["identity"], "ip-only", "loopback IPs carry no DNS name");

    // The counterfactual experiment is in the ledger with its condition.
    let ledger_text = std::fs::read_to_string(out.join("evidence.jsonl")).unwrap();
    assert!(
        ledger_text.contains("network-isolated"),
        "experiment evidence recorded"
    );

    // One complete bundle: world lock + compose from the online run.
    assert!(out.join("world.lock.yaml").exists());
    assert!(out.join("compose.yaml").exists());
}

#[test]
fn compose_services_appear_as_declared_external_systems() {
    let out = temp_out("compose");
    let fixture = fixtures().join("network-caller");
    let (ok, _, stderr) = run_ovid(&[
        "analyze",
        fixture.to_str().unwrap(),
        "--workloads",
        "test",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "analyze failed: {stderr}");
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

    // The observed loopback destinations remain separate records — a
    // port-only coincidence with a compose service must not merge (§6.6).
    assert!(external.iter().any(|s| s["id"] == "127.0.0.1:5432"));
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
        "analyze",
        fixture.to_str().unwrap(),
        "--workloads",
        "test",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "analyze failed: {stderr}");
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

#[test]
fn successful_package_opens_promote_loaded_state() {
    let out = temp_out("loaded");
    let repo = temp_out("loaded-repo");
    // A repo declaring `requests`, whose workload opens the installed
    // package's files under a site-packages layout.
    std::fs::create_dir_all(repo.join(".venv/lib/python3.11/site-packages/requests")).unwrap();
    std::fs::create_dir_all(repo.join(".venv/lib/python3.11/site-packages/unrelated")).unwrap();
    std::fs::write(
        repo.join("requirements.txt"),
        "requests==2.31.0\nflask==3.0.0\n",
    )
    .unwrap();
    std::fs::write(
        repo.join(".venv/lib/python3.11/site-packages/requests/__init__.py"),
        "# fixture module\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("run.sh"),
        "cat .venv/lib/python3.11/site-packages/requests/__init__.py > /dev/null\n",
    )
    .unwrap();
    let (ok, _, stderr) = run_ovid(&[
        "observe",
        repo.to_str().unwrap(),
        "--run",
        "sh run.sh",
        "--in-place",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "observe failed: {stderr}");
    let manifest = load_manifest(&out);
    let components = manifest["inventory"]["components"].as_array().unwrap();
    let requests = components.iter().find(|c| c["name"] == "requests").unwrap();
    assert_eq!(
        requests["states"]["loaded"], true,
        "opened package must be promoted to loaded: {requests}"
    );
    // §6.3: loading never implies execution; and the unopened declared
    // package stays unloaded.
    assert!(requests["states"]["exercised"].is_null());
    let flask = components.iter().find(|c| c["name"] == "flask").unwrap();
    assert!(
        flask["states"]["loaded"].is_null(),
        "unopened package must stay unloaded"
    );
    // The loads claim links to the open evidence.
    let claims_text = std::fs::read_to_string(out.join("claims.json")).unwrap();
    assert!(claims_text.contains("\"loads\""), "loads claim recorded");
}
