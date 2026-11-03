Frozen Phase 1 container baseline (git commit fdd831f, scanned from the benchmark target before P11 existed).
Used by tests to reproduce the Phase 1 reference numbers (9/11 positives, 4/7 negatives) from normalized findings.
Do not edit: raw files are byte-identical scanner output and are secret-bearing by design (fake secrets only).
ADR-002 exception (docs/DECISIONS.md): re-scrubbed once by an exact-length value mapping (provider-shaped fakes ->
generic-shaped fakes) with benchmarks/rescrub_frozen.py, which recomputed the hashes in manifest.json. Nothing else changed.
