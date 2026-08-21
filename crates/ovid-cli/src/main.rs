//! Ovid CLI (spec §13.1).
//!
//! Subcommand surface mirrors the spec's representative commands:
//! `inventory`, `observe`, `analyze`, `explain`, `world export`, `diff`,
//! and `packs`. Output is concise by default; every analysis writes a full
//! output bundle (§3.2) to `--out`.

mod pipeline;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ovid",
    version,
    about = "Evidence-driven repository execution tomography",
    long_about = "Ovid analyzes how a repository is built, executed, and integrated by \
                  observing real execution boundaries and recording evidence-backed claims."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Non-executing static inventory of a repository (mode `inventory`).
    Inventory {
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
    /// Run one explicit command under boundary observation (mode `observe`).
    Observe {
        locator: String,
        #[arg(long = "ref")]
        reference: Option<String>,
        /// The command to run, as one shell string.
        #[arg(long)]
        run: String,
        #[arg(long, default_value = "ovid-output")]
        out: PathBuf,
        /// Run in the checkout instead of an ephemeral copy (faster for
        /// large trees; the tree may be modified).
        #[arg(long)]
        in_place: bool,
        /// Host environment variables to pass through (repeatable).
        #[arg(long = "inherit-env")]
        inherit_env: Vec<String>,
        /// Wall-clock timeout in seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Execution backend: `process` (supervised host process) or
        /// `microsandbox` (libkrun guest VM via the `msb` CLI; observation
        /// and network counterfactuals run inside an always-Linux guest).
        #[arg(long, default_value = "process")]
        backend: String,
        /// Guest image for the microsandbox backend.
        #[arg(long = "guest-image", default_value = "ubuntu")]
        guest_image: String,
        #[arg(long = "packs-dir")]
        packs_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Discover workloads, execute them under observation, and synthesize a
    /// proposed world (mode `explore`, local scope).
    Analyze {
        locator: String,
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Workload kinds to attempt, in order.
        #[arg(long, default_value = "build,test")]
        workloads: String,
        #[arg(long, default_value = "ovid-output")]
        out: PathBuf,
        #[arg(long)]
        in_place: bool,
        #[arg(long = "inherit-env")]
        inherit_env: Vec<String>,
        #[arg(long, default_value_t = 900)]
        timeout: u64,
        /// Counterfactually test whether these environment variables are
        /// required by re-running without them (repeatable).
        #[arg(long = "counterfactual-env")]
        counterfactual_env: Vec<String>,
        /// Execution backend: `process` (supervised host process) or
        /// `microsandbox` (libkrun guest VM via the `msb` CLI; observation
        /// and network counterfactuals run inside an always-Linux guest).
        #[arg(long, default_value = "process")]
        backend: String,
        /// Guest image for the microsandbox backend.
        #[arg(long = "guest-image", default_value = "ubuntu")]
        guest_image: String,
        #[arg(long = "packs-dir")]
        packs_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Full tomography: discover workloads, run each twice (isolated
    /// network, then with network), classify external dependencies from
    /// the counterfactual pair, and emit one complete bundle.
    Tomography {
        locator: String,
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Workload kinds to attempt, in order. Provisioning (the best
        /// discovered install candidate) always runs first, online.
        #[arg(long, default_value = "build,test")]
        workloads: String,
        #[arg(long, default_value = "ovid-output")]
        out: PathBuf,
        /// Run in the checkout instead of a persistent workspace copy.
        #[arg(long)]
        in_place: bool,
        /// Extra host environment variables to pass through, on top of the
        /// defaults (PATH/HOME for all runs; proxy and CA variables for
        /// online runs). Repeatable.
        #[arg(long = "inherit-env")]
        inherit_env: Vec<String>,
        /// Fully scrub the environment: no default PATH/HOME/proxy
        /// inheritance.
        #[arg(long)]
        no_default_env: bool,
        /// Run up to this many discovered candidates per workload kind.
        #[arg(long, default_value_t = 1)]
        max_candidates: usize,
        /// Per-run wall-clock timeout in seconds.
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// Execution backend: `process` (supervised host process) or
        /// `microsandbox` (libkrun guest VM via the `msb` CLI; observation
        /// and network counterfactuals run inside an always-Linux guest).
        #[arg(long, default_value = "process")]
        backend: String,
        /// Guest image for the microsandbox backend.
        #[arg(long = "guest-image", default_value = "ubuntu")]
        guest_image: String,
        #[arg(long = "packs-dir")]
        packs_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Explain a claim by traversing to its evidence (FR-110).
    Explain {
        /// Claim id, e.g. `claim:...`, or a search term.
        claim: String,
        /// Analysis bundle directory to read.
        #[arg(long, default_value = "ovid-output")]
        from: PathBuf,
    },
    /// World operations.
    World {
        #[command(subcommand)]
        command: WorldCommand,
    },
    /// Compare two analysis bundles (FR-100/FR-101 composition scope).
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
    /// Pack operations.
    Packs {
        #[command(subcommand)]
        command: PacksCommand,
    },
}

#[derive(Subcommand)]
enum WorldCommand {
    /// Export a generated world from an analysis bundle.
    Export {
        /// Analysis bundle directory.
        #[arg(long, default_value = "ovid-output")]
        from: PathBuf,
        /// `compose` or `lock`.
        #[arg(long, default_value = "compose")]
        format: String,
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
        Command::Inventory {
            locator,
            reference,
            out,
            packs_dir,
            json,
        } => {
            let bundle = pipeline::run_inventory(&locator, reference, &out, packs_dir.as_deref())?;
            if json {
                println!("{}", bundle.manifest.to_json_pretty());
            } else {
                pipeline::print_summary(&bundle);
            }
            Ok(())
        }
        Command::Observe {
            locator,
            reference,
            run,
            out,
            in_place,
            inherit_env,
            timeout,
            backend,
            guest_image,
            packs_dir,
            json,
        } => {
            let options = pipeline::ExecutionOptions {
                in_place,
                inherit_env,
                timeout_seconds: timeout,
                counterfactual_env: vec![],
                backend: pipeline::BackendKind::parse(&backend)?,
                guest_image,
            };
            let bundle = pipeline::run_observe(
                &locator,
                reference,
                &run,
                &out,
                &options,
                packs_dir.as_deref(),
            )?;
            if json {
                println!("{}", bundle.manifest.to_json_pretty());
            } else {
                pipeline::print_summary(&bundle);
            }
            Ok(())
        }
        Command::Analyze {
            locator,
            reference,
            workloads,
            out,
            in_place,
            inherit_env,
            timeout,
            counterfactual_env,
            backend,
            guest_image,
            packs_dir,
            json,
        } => {
            let kinds: Vec<String> = workloads.split(',').map(|s| s.trim().to_string()).collect();
            let options = pipeline::ExecutionOptions {
                in_place,
                inherit_env,
                timeout_seconds: timeout,
                counterfactual_env,
                backend: pipeline::BackendKind::parse(&backend)?,
                guest_image,
            };
            let bundle = pipeline::run_analyze(
                &locator,
                reference,
                &kinds,
                &out,
                &options,
                packs_dir.as_deref(),
            )?;
            if json {
                println!("{}", bundle.manifest.to_json_pretty());
            } else {
                pipeline::print_summary(&bundle);
            }
            Ok(())
        }
        Command::Tomography {
            locator,
            reference,
            workloads,
            out,
            in_place,
            inherit_env,
            no_default_env,
            max_candidates,
            timeout,
            backend,
            guest_image,
            packs_dir,
            json,
        } => {
            let kinds: Vec<String> = workloads.split(',').map(|s| s.trim().to_string()).collect();
            let options = pipeline::TomographyOptions {
                in_place,
                extra_inherit_env: inherit_env,
                timeout_seconds: timeout,
                max_candidates,
                no_default_env,
                backend: pipeline::BackendKind::parse(&backend)?,
                guest_image,
            };
            let bundle = pipeline::run_tomography(
                &locator,
                reference,
                &kinds,
                &out,
                &options,
                packs_dir.as_deref(),
            )?;
            if json {
                println!("{}", bundle.manifest.to_json_pretty());
            } else {
                pipeline::print_summary(&bundle);
            }
            Ok(())
        }
        Command::Explain { claim, from } => pipeline::explain(&claim, &from),
        Command::World { command } => match command {
            WorldCommand::Export { from, format } => {
                let lock_path = from.join("world.lock.yaml");
                let text = std::fs::read_to_string(&lock_path)
                    .with_context(|| format!("no world lock at {}", lock_path.display()))?;
                match format.as_str() {
                    "lock" => print!("{text}"),
                    "compose" => {
                        let lock: ovid_world::WorldLock = serde_yaml::from_str(&text)?;
                        print!("{}", lock.to_compose_yaml());
                    }
                    other => bail!("unknown world export format {other:?} (use compose|lock)"),
                }
                Ok(())
            }
        },
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
                    Err(e) => bail!("pack validation failed: {e}"),
                }
            }
        },
    }
}
