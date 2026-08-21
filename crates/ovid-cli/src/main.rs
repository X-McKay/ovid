//! Ovid CLI — the composition root (proposal §4, §6.1).
//!
//! The surface is task-oriented: `doctor` (host capabilities), `inspect`
//! (static, fast, never executes repository code), `prove` (the primary
//! causal loop), `replay` (re-verify a world), `explain` (evidence
//! trees), `diff` (compare causal models), `export` (lazy standards
//! projections), and `packs` (extension management).

mod inspect_cmd;
mod lab;
mod prove_cmd;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ovid",
    version,
    about = "Evidence-backed causal dependency verifier",
    long_about = "Ovid experimentally determines what a repository workload needs, explains \
                  why, and verifies that the inferred environment can reproduce the workload. \
                  Start with `ovid doctor`, then `ovid inspect <repo>`, then \
                  `ovid prove <repo> --workload test`."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Static inspection: composition, declared endpoints, and ranked
    /// workload candidates. Never executes repository code.
    Inspect {
        /// Repository locator: local path or git URL.
        locator: String,
        /// Git reference (branch/tag) for URL locators.
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Output bundle directory.
        #[arg(long, default_value = "ovid-output")]
        out: PathBuf,
        /// Additional pack directory to load (validated, schema-checked).
        #[arg(long = "packs-dir")]
        packs_dir: Option<PathBuf>,
        /// Print the manifest as JSON instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Prove what a workload needs: stable baseline, enforced
    /// interventions, causal classification, and a replay-verified world.
    Prove {
        /// Repository locator: local path or git URL.
        locator: String,
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Workload to prove: build|test|start (discovered), or a name
        /// for an explicit command passed after `--`.
        #[arg(long, default_value = "test")]
        workload: String,
        /// Explicit workload command (overrides discovery).
        #[arg(last = true)]
        argv: Vec<String>,
        /// Bundle directory (default: `.ovid/runs/<analysis-id>`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Execution backend: `process` (host; trusted repos) or
        /// `microsandbox` (libkrun guest VM).
        #[arg(long, default_value = "process")]
        backend: String,
        /// Guest image for the microsandbox backend.
        #[arg(long = "guest-image", default_value = "ubuntu")]
        guest_image: String,
        /// Explicitly accept host-process execution for a remote
        /// repository you trust (otherwise remote sources require the
        /// guest-VM backend).
        #[arg(long = "trusted-process")]
        trusted_process: bool,
        /// Baseline repetitions from the frozen snapshot.
        #[arg(long = "baseline-runs", default_value_t = 2)]
        baseline_runs: usize,
        /// Confirmation runs per intervention.
        #[arg(long = "confirmation-runs", default_value_t = 1)]
        confirmation_runs: usize,
        /// Hard ceiling on trials.
        #[arg(long = "max-trials", default_value_t = 12)]
        max_trials: usize,
        /// Per-trial wall-clock timeout in seconds.
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// Extra host environment variable names to pass through
        /// (repeatable; names only, values come from the host).
        #[arg(long = "inherit-env")]
        inherit_env: Vec<String>,
        /// Runtime egress posture: `deny` (default; no real external
        /// traffic — a lab gateway names what the workload tried to
        /// reach) or `allow` (gateway-mediated real egress, required to
        /// classify network dependencies causally).
        #[arg(long, default_value = "deny")]
        egress: String,
        /// Skip the clean-replay verification step.
        #[arg(long = "no-replay")]
        no_replay: bool,
        #[arg(long = "packs-dir")]
        packs_dir: Option<PathBuf>,
        /// Print the proof report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Re-verify a proved bundle: rebuild the environment, rerun the
    /// locked workload from clean state, update the lock status.
    Replay {
        /// Analysis bundle directory (from `ovid prove`).
        bundle: PathBuf,
        #[arg(long, default_value = "process")]
        backend: String,
        #[arg(long = "guest-image", default_value = "ubuntu")]
        guest_image: String,
        #[arg(long = "inherit-env")]
        inherit_env: Vec<String>,
        /// Egress posture; use `allow` to re-verify a world proved with
        /// real network access.
        #[arg(long, default_value = "deny")]
        egress: String,
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
    },
    /// Report host capabilities (observation, isolation, backends) with
    /// exact remediation steps.
    Doctor,
    /// Explain a claim by traversing to its evidence (FR-110).
    Explain {
        /// Claim id, e.g. `claim:...`, or a search term.
        claim: String,
        /// Analysis bundle directory to read.
        #[arg(long, default_value = "ovid-output")]
        from: PathBuf,
    },
    /// Compare two analysis bundles: components, tools, external
    /// systems, causal labels, world status.
    Diff {
        /// `ovid.json` (or bundle dir) for the "before" side.
        #[arg(long)]
        before: PathBuf,
        /// `ovid.json` (or bundle dir) for the "after" side.
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Render a standards projection from a completed bundle on demand.
    Export {
        /// Analysis bundle directory.
        #[arg(long, default_value = "ovid-output")]
        from: PathBuf,
        /// `cyclonedx`, `spdx`, `plan`, `lock`, or `compose`.
        #[arg(long)]
        format: String,
    },
    /// Pack operations.
    Packs {
        #[command(subcommand)]
        command: PacksCommand,
    },
    /// Internal: the laboratory gateway subprocess started inside an
    /// isolated trial namespace. Not part of the public surface.
    #[command(hide = true, name = "internal-gateway")]
    InternalGateway {
        /// Bind address, e.g. `127.0.0.1:3128`.
        #[arg(long)]
        listen: String,
        /// `deny` (record + refuse) or `forward` (record + tunnel).
        #[arg(long)]
        policy: String,
        /// Destinations to refuse under a forward policy (repeatable;
        /// `host:port` or bare `host`).
        #[arg(long)]
        block: Vec<String>,
        /// Upstream proxy URL to chain through when forwarding.
        #[arg(long)]
        upstream: Option<String>,
        /// Intent log (JSONL) path.
        #[arg(long)]
        log: PathBuf,
        /// File created once the socket is bound.
        #[arg(long)]
        ready: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PacksCommand {
    /// List built-in (and optionally external) packs.
    List {
        /// Additional pack directory to load.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Validate all packs in a directory.
    Validate { dir: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect {
            locator,
            reference,
            out,
            packs_dir,
            json,
        } => inspect_cmd::run_inspect(&locator, reference, &out, packs_dir.as_deref(), json),
        Command::Prove {
            locator,
            reference,
            workload,
            argv,
            out,
            backend,
            guest_image,
            trusted_process,
            baseline_runs,
            confirmation_runs,
            max_trials,
            timeout,
            inherit_env,
            egress,
            no_replay,
            packs_dir,
            json,
        } => {
            let options = prove_cmd::ProveOptions {
                workload,
                argv: if argv.is_empty() { None } else { Some(argv) },
                backend: lab::BackendKind::parse(&backend)?,
                guest_image,
                trusted_process,
                baseline_runs,
                confirmation_runs,
                max_trials,
                timeout_seconds: timeout,
                extra_env: inherit_env,
                egress: lab::EgressPolicy::parse(&egress)?,
                no_replay,
                packs_dir,
                json,
            };
            let code = prove_cmd::run_prove(&locator, reference, out, &options)?;
            std::process::exit(code);
        }
        Command::Replay {
            bundle,
            backend,
            guest_image,
            inherit_env,
            egress,
            timeout,
        } => {
            let code = prove_cmd::run_replay(
                &bundle,
                lab::BackendKind::parse(&backend)?,
                &guest_image,
                &inherit_env,
                lab::EgressPolicy::parse(&egress)?,
                timeout,
            )?;
            std::process::exit(code);
        }
        Command::Doctor => prove_cmd::run_doctor(),
        Command::Explain { claim, from } => inspect_cmd::explain(&claim, &from),
        Command::Diff {
            before,
            after,
            json,
        } => {
            let load = |path: &PathBuf| -> Result<ovid_output::Manifest> {
                let file = if path.is_dir() {
                    path.join("ovid.json")
                } else {
                    path.clone()
                };
                let text = std::fs::read_to_string(&file)
                    .with_context(|| format!("cannot read manifest {}", file.display()))?;
                Ok(ovid_output::Manifest::from_json(&text)?)
            };
            let diff = ovid_output::diff_manifests(&load(&before)?, &load(&after)?);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print!("{}", diff.to_markdown());
            }
            Ok(())
        }
        Command::Export { from, format } => inspect_cmd::export(&from, &format),
        Command::Packs { command } => match command {
            PacksCommand::List { dir } => {
                let mut registry = ovid_packs::PackRegistry::builtin()
                    .map_err(|e| anyhow::anyhow!("builtin packs: {e}"))?;
                if let Some(dir) = dir {
                    let loaded = registry
                        .load_dir(&dir)
                        .map_err(|e| anyhow::anyhow!("loading {}: {e}", dir.display()))?;
                    eprintln!("loaded {loaded} external pack(s) from {}", dir.display());
                }
                for pack in registry.all() {
                    println!(
                        "{:<24} {:<20} {}",
                        pack.label(),
                        pack.kind_label(),
                        pack.metadata.signer.as_deref().unwrap_or("unsigned")
                    );
                }
                Ok(())
            }
            PacksCommand::Validate { dir } => {
                let mut registry = ovid_packs::PackRegistry::builtin()
                    .map_err(|e| anyhow::anyhow!("builtin packs: {e}"))?;
                match registry.load_dir(&dir) {
                    Ok(count) => {
                        println!("OK: {count} pack(s) in {} are valid", dir.display());
                        Ok(())
                    }
                    Err(e) => anyhow::bail!("pack validation failed: {e}"),
                }
            }
        },
        Command::InternalGateway {
            listen,
            policy,
            block,
            upstream,
            log,
            ready,
        } => {
            let policy = match policy.as_str() {
                "deny" => ovid_gateway::GatewayPolicy::Deny,
                "forward" if block.is_empty() => ovid_gateway::GatewayPolicy::Forward,
                "forward" => {
                    ovid_gateway::GatewayPolicy::ForwardExcept(block.into_iter().collect())
                }
                other => anyhow::bail!("unknown gateway policy {other:?}"),
            };
            let upstream = match upstream {
                Some(url) => Some(ovid_gateway::Upstream::parse(&url).ok_or_else(|| {
                    anyhow::anyhow!("invalid upstream proxy URL (expected http://host:port)")
                })?),
                None => None,
            };
            ovid_gateway::serve_blocking(&listen, policy, upstream, &log, ready.as_deref())?;
            Ok(())
        }
    }
}
