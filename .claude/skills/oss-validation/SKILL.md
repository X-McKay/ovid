---
name: oss-validation
description: Run the open-source repository validation suite (performance + accuracy against real repos) and update docs/VALIDATION.md. Use before releases or after changes to scanners, the planner, the observer, or the pipeline.
---

# OSS validation runs

`docs/VALIDATION.md` records measured performance and accuracy against
real open-source repositories of varying complexity. Keep it honest and
reproducible: every number in that file comes from `scripts/validate-oss.sh`.

## Procedure

1. Build release: `cargo build --release -p ovid-cli`.
2. Run the suite (clones pinned refs, runs inventory + observe, measures
   wall time, and computes accuracy against ground truth):

   ```sh
   scripts/validate-oss.sh            # writes validation-workdir/results.md
   ```

3. Ground-truth rules used for accuracy (keep these when editing the
   script):
   - **Rust:** resolved-component count vs `Cargo.lock` `[[package]]`
     count; declared direct deps vs `cargo metadata`.
   - **Node:** resolved count vs `package-lock.json` packages entries
     (excluding the root).
   - **Python/Go/JVM:** declared entries vs a manual count of the
     manifest's dependency section.
   - Component accuracy = exact (name, version) matches / ground truth.
4. Update `docs/VALIDATION.md` with the new table, the exact commit of
   each repo analyzed, host specs (`nproc`, memory), and the ovid commit.
   Never edit numbers by hand without a run backing them.
5. If accuracy regressed, bisect scanners with the fixture unit tests
   before touching the validation doc.

## Repo selection

Keep at least 5 repos of varying complexity and ecosystems (small CLI,
mid library, large workspace, non-Rust ecosystems). Pin exact refs so
runs are comparable across time.
