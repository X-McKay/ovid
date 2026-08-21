#!/usr/bin/env python3
"""Inventory accuracy against independent ground truth.

Usage: accuracy.py <ovid.json> <clone_dir> <ecosystem>

Ground-truth sources are deliberately independent of Ovid's parsers where
possible (cargo metadata for Rust); for manifest-only ecosystems the
ground truth is a minimal independent parse of the primary manifest.
Prints `P=<precision> R=<recall> (n=<gold size>)`.
"""

import json
import re
import subprocess
import sys
from pathlib import Path


def ovid_components(manifest_path: str):
    manifest = json.load(open(manifest_path))
    return manifest["inventory"]["components"]


def rust_ground_truth(clone: Path):
    """Resolved (name, version) set from cargo metadata (independent tool),
    excluding workspace members."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=clone,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if out.returncode != 0:
        # Retry without --locked (repos without committed lockfiles).
        out = subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=clone,
            capture_output=True,
            text=True,
            timeout=600,
        )
        out.check_returncode()
    meta = json.loads(out.stdout)
    members = {pid for pid in meta["workspace_members"]}
    gold = set()
    for pkg in meta["packages"]:
        if pkg["id"] in members:
            continue
        gold.add((pkg["name"], pkg["version"]))
    return gold


def compare_rust(components, clone: Path):
    gold = rust_ground_truth(clone)
    ours = {
        (c["name"], c["version"])
        for c in components
        if c["ecosystem"] == "cargo" and c.get("version") and c["states"].get("resolved")
    }
    if not gold:
        return "n/a (no external deps)"
    tp = len(ours & gold)
    precision = tp / len(ours) if ours else 0.0
    recall = tp / len(gold)
    return f"P={precision:.3f} R={recall:.3f} (n={len(gold)})"


def compare_rust_declared(components, clone: Path):
    """Workspace repos without lockfiles: compare unique declared direct
    dependency names against cargo metadata --no-deps declarations."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=clone,
        capture_output=True,
        text=True,
        timeout=600,
    )
    out.check_returncode()
    meta = json.loads(out.stdout)
    gold = set()
    for pkg in meta["packages"]:
        for dep in pkg["dependencies"]:
            gold.add(dep["name"])
    ours = {c["name"] for c in components if c["ecosystem"] == "cargo" and c["states"].get("declared")}
    # Workspace-internal path deps are declared in both; keep symmetric.
    tp = len(ours & gold)
    precision = tp / len(ours) if ours else 0.0
    recall = tp / len(gold) if gold else 0.0
    return f"P={precision:.3f} R={recall:.3f} (n={len(gold)}, declared names)"


def compare_python(components, clone: Path):
    import tomllib

    data = tomllib.loads((clone / "pyproject.toml").read_text())
    gold = set()
    for req in data.get("project", {}).get("dependencies", []):
        name = re.split(r"[<>=!~\[;\s]", req.strip(), 1)[0]
        gold.add(name.lower().replace("_", "-"))
    ours = {
        c["name"]
        for c in components
        if c["ecosystem"] == "pypi" and c["states"].get("declared") and c["scope"] == "runtime"
    }
    tp = len(ours & gold)
    precision = tp / len(ours) if ours else 0.0
    recall = tp / len(gold) if gold else 0.0
    return f"P={precision:.3f} R={recall:.3f} (n={len(gold)}, declared runtime)"


def compare_node(components, clone: Path):
    pkg = json.loads((clone / "package.json").read_text())
    gold = set(pkg.get("dependencies", {})) | set(pkg.get("devDependencies", {}))
    ours = {c["name"] for c in components if c["ecosystem"] == "npm" and c["states"].get("declared")}
    tp = len(ours & gold)
    precision = tp / len(ours) if ours else 0.0
    recall = tp / len(gold) if gold else 0.0
    return f"P={precision:.3f} R={recall:.3f} (n={len(gold)}, declared)"


def compare_go(components, clone: Path):
    gold = set()
    in_block = False
    for raw in (clone / "go.mod").read_text().splitlines():
        line = raw.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        entry = line[len("require "):] if line.startswith("require ") else (line if in_block else None)
        if entry:
            parts = entry.split()
            if len(parts) >= 2:
                gold.add((parts[0], parts[1]))
    ours = {
        (c["name"], c["version"])
        for c in components
        if c["ecosystem"] == "golang" and c["states"].get("declared")
    }
    tp = len(ours & gold)
    precision = tp / len(ours) if ours else 0.0
    recall = tp / len(gold) if gold else 0.0
    return f"P={precision:.3f} R={recall:.3f} (n={len(gold)}, go.mod)"


def main():
    manifest_path, clone_dir, ecosystem = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    components = ovid_components(manifest_path)
    if ecosystem == "rust":
        print(compare_rust(components, clone_dir))
    elif ecosystem == "rust-workspace":
        print(compare_rust_declared(components, clone_dir))
    elif ecosystem == "python":
        print(compare_python(components, clone_dir))
    elif ecosystem == "node":
        print(compare_node(components, clone_dir))
    elif ecosystem == "go":
        print(compare_go(components, clone_dir))
    else:
        print("n/a")


if __name__ == "__main__":
    main()
