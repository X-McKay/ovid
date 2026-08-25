---
name: setup-ovid
description: Install and provision Ovid and its host prerequisites, then verify the host with `ovid doctor`. Use when setting up Ovid on a new machine, a CI runner, or a Claude Code / Codex web session, or when a run fails because a prerequisite (strace, user namespaces, msb) is missing.
---

# Setting up Ovid

Goal: a host where `ovid doctor` reports the capabilities the intended
command needs, before a real run discovers the gaps. Ovid degrades
honestly — a missing prerequisite does not crash, it narrows what can be
proven — so setup is about *matching the host to the task*.

## 1. Install the CLI

```sh
# Prebuilt release (sha256-verified; falls back to source build):
curl -fsSL https://raw.githubusercontent.com/X-McKay/ovid/main/scripts/install.sh | sh
# or from source (needs Rust >= the workspace MSRV in Cargo.toml, 1.85):
cargo install --locked --git https://github.com/X-McKay/ovid ovid-cli
# or in a checkout:
cargo build --workspace          # dev
cargo install --locked --path crates/ovid-cli
```

Installer env: `OVID_INSTALL_DIR` (default `~/.local/bin`), `OVID_VERSION`
(release tag), `OVID_REPO_URL` (private fork).

## 2. Install host prerequisites (Linux, for execution)

| Capability | Needed for | Install / enable |
|---|---|---|
| `git` | URL sources (local paths don't need it) | distro package |
| `strace` | boundary observation (process backend) | `apt-get install strace` |
| unprivileged user namespaces | enforced deny-all egress on the process backend | enable `kernel.unprivileged_userns_clone=1`; some distros/containers disable it via hardening |
| `msb` (microsandbox) | `--backend microsandbox` guest VM (untrusted/remote code, non-Linux hosts) | <https://microsandbox.dev>; needs Linux/KVM, macOS/Apple-Silicon, or Windows/WHP |

Static analysis (`ovid inspect`) works on macOS/Windows with none of the
execution prerequisites. For a guest-VM run, the **guest image** must
itself contain the workload's tools and `strace`, or observation is
recorded as an explicit completeness limitation.

## 3. Verify the host

```sh
ovid doctor
```

It prints one line per capability with exact remediation:

```
[ok  ] git                 …
[ok  ] strace              boundary observation (process backend)
[ok  ] user namespaces     deny-all egress enforcement (process backend)
[ok  ] egress gateway      names what workloads reach (deny = nothing contacted)
[--  ] msb                 microsandbox guest-VM laboratory (--backend microsandbox)
```

A `[--]` line is not fatal — it tells you which command paths are
limited. Map the task to what must be `[ok]`:
- `ovid inspect` → none (static).
- `ovid prove` (trusted local repo) → `strace` (observation) + user
  namespaces (deny enforcement) for full-fidelity causal labels.
- `ovid prove` on a remote/untrusted repo → `msb`.

## 4. Agent / web-session setup

For Claude Code on the web this repo ships a `SessionStart` hook
(`.claude/hooks/session-start.sh`, registered in `.claude/settings.json`)
that installs `strace` and warms the cargo cache on `startup|resume`.
Mirror that in any other CI/agent environment: install `strace`, ensure
user namespaces, and pre-build once so the first run is warm.

## 5. Confirm end to end

Run the tool against a fixture before trusting it on a real repo:

```sh
ovid inspect fixtures/prove-truth
ovid prove fixtures/prove-truth --workload test --trusted-process
```

If either misbehaves, hand off to the `troubleshoot-ovid` skill.
