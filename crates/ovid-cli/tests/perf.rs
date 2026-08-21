//! Performance regression tests (spec §12.2, §37.6).
//!
//! These are guardrails, not benchmarks: thresholds are set well above the
//! measured baseline (see docs/VALIDATION.md for real numbers) so they only
//! fire on order-of-magnitude regressions, keeping CI stable across noisy
//! runners. Each test prints its measurement so CI logs double as a coarse
//! benchmark history.
//!
//! Run explicitly with: `cargo test -p ovid-cli --test perf -- --ignored`

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Build a synthetic repository with `files` source files.
fn synthetic_repo(files: usize) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ovid-perf-{files}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for module in 0..(files / 100).max(1) {
        let module_dir = dir.join(format!("src/module{module}"));
        std::fs::create_dir_all(&module_dir).unwrap();
        for index in 0..100.min(files) {
            std::fs::write(
                module_dir.join(format!("file{index}.rs")),
                format!("pub fn f{index}() -> u64 {{ {index} }}\n").repeat(20),
            )
            .unwrap();
        }
    }
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"perf\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    dir
}

#[test]
#[ignore = "perf guardrail; run with --ignored"]
fn inventory_5000_files_under_threshold() {
    let repo = synthetic_repo(5000);
    let out = std::env::temp_dir().join(format!("ovid-perf-out-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_ovid"))
        .args(["inventory", repo.to_str().unwrap(), "--out", out.to_str().unwrap()])
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    assert!(output.status.success());
    println!("PERF inventory 5000 files: {} ms", elapsed.as_millis());
    // Spec target: p50 < 30 s for <100k files (§12.2). Guardrail here:
    // 5k files in < 20 s even on slow CI.
    assert!(elapsed < Duration::from_secs(20), "inventory too slow: {elapsed:?}");
}

#[test]
#[ignore = "perf guardrail; run with --ignored"]
fn observed_run_overhead_is_bounded() {
    let repo = synthetic_repo(10);
    let out_base = std::env::temp_dir().join(format!("ovid-perf-ovh-{}", std::process::id()));
    // A workload with real file I/O so the ptrace overhead is amortized.
    let workload = "i=0; while [ $i -lt 400 ]; do cat Cargo.toml > /dev/null; i=$((i+1)); done";
    let run = |observe: bool| -> Duration {
        let start = Instant::now();
        let mut args = vec![
            "observe".to_string(),
            repo.to_str().unwrap().to_string(),
            "--run".to_string(),
            workload.to_string(),
            "--in-place".to_string(),
            "--out".to_string(),
            format!("{}-{observe}", out_base.display()),
        ];
        if !observe {
            // No un-observe flag exists; approximate the native baseline by
            // timing the same loop under plain sh.
            args = vec![];
            let status = Command::new("sh").arg("-c").arg(workload).current_dir(&repo).status().unwrap();
            assert!(status.success());
            return start.elapsed();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_ovid")).args(&args).output().unwrap();
        assert!(output.status.success());
        start.elapsed()
    };
    let native = run(false);
    let observed = run(true);
    let ratio = observed.as_secs_f64() / native.as_secs_f64().max(0.001);
    println!(
        "PERF observed-vs-native: native {} ms, observed(total pipeline) {} ms, ratio {ratio:.1}x",
        native.as_millis(),
        observed.as_millis()
    );
    // The observed figure includes acquisition + fingerprinting + strace +
    // parsing + bundle output, so the bound is a coarse regression guard.
    // The ptrace backend's per-syscall cost is documented in
    // docs/VALIDATION.md; the eBPF backend is the low-overhead path.
    assert!(
        observed < Duration::from_secs(60),
        "observed pipeline run unexpectedly slow: {observed:?}"
    );
}

#[test]
#[ignore = "perf guardrail; run with --ignored"]
fn ledger_append_throughput() {
    let dir = std::env::temp_dir().join(format!("ovid-perf-ledger-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ledger = ovid_evidence::EvidenceLedger::open(dir.join("evidence.jsonl")).unwrap();
    let ids = ovid_core::IdGenerator::new();
    let start = Instant::now();
    let count = 5000u64;
    for index in 0..count {
        ledger
            .append(ovid_evidence::EvidenceRecord {
                id: ids.next("evidence"),
                record_type: "perf".into(),
                run_id: None,
                wall_time: None,
                provider: "perf".into(),
                provider_version: "0".into(),
                trust_tier: ovid_core::TrustTier::T2,
                data: serde_json::json!({ "index": index }),
                previous: None,
            })
            .unwrap();
    }
    let elapsed = start.elapsed();
    let per_second = count as f64 / elapsed.as_secs_f64();
    println!("PERF ledger append: {count} records in {} ms ({per_second:.0}/s)", elapsed.as_millis());
    assert!(per_second > 1000.0, "ledger append too slow: {per_second:.0}/s");
    ledger.verify_chain().unwrap();
}

#[test]
#[ignore = "perf guardrail; run with --ignored"]
fn aggregation_handles_event_floods() {
    let ids = ovid_core::IdGenerator::new();
    let run = ids.next("run");
    let events: Vec<ovid_core::EventEnvelope> = (0..100_000)
        .map(|index| ovid_core::EventEnvelope {
            event_id: ids.next("evidence"),
            run_id: run.clone(),
            sequence: index,
            wall_time: None,
            provider: "perf".into(),
            provider_version: "0".into(),
            trust_tier: ovid_core::TrustTier::T2,
            process: None,
            event: ovid_core::BoundaryEvent::FileOpened {
                // 1000 distinct paths repeated 100x each.
                path: format!("/app/file{}.txt", index % 1000),
                errno: None,
                write: false,
            },
        })
        .collect();
    let start = Instant::now();
    let aggregated = ovid_observer::aggregate(events);
    let elapsed = start.elapsed();
    println!(
        "PERF aggregate: 100k events -> {} retained in {} ms",
        aggregated.events.len(),
        elapsed.as_millis()
    );
    assert_eq!(aggregated.events.len(), 1000);
    assert!(elapsed < Duration::from_secs(5), "aggregation too slow: {elapsed:?}");
}
